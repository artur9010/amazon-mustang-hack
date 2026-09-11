#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/stat.h>
int main(void){
	char d[] = "/data/local/tmp/.qmeas";
	mkdir(d, 0755);
	char p[256], q[256];
	snprintf(p, sizeof(p), "%s/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", d);
	snprintf(q, sizeof(q), "%s/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", d);
	int t = open(p, O_CREAT|O_RDWR, 0644); close(t);
	int ifd = inotify_init1(IN_NONBLOCK);
	inotify_add_watch(ifd, d, IN_MOVED_TO);
	int N = 5000, done = 0;
	for (int i = 0; i < N; i++) {
		char *from = (i & 1) ? q : p, *to = (i & 1) ? p : q;
		if (rename(from, to) == 0) done++;
	}
	int total = 0, overflow = 0;
	char buf[65536];
	int n;
	while ((n = read(ifd, buf, sizeof(buf))) > 0) {
		for (int off = 0; off < n; ) {
			struct inotify_event *e = (void*)(buf + off);
			if (e->mask & 0x4000) overflow++;
			total++;
			off += sizeof(struct inotify_event) + e->len;
		}
	}
	printf("renames=%d events_read=%d overflow=%d\n", done, total, overflow);
	return 0;
}
