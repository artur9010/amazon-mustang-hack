#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/stat.h>
int main(void){
	char d[] = "/data/local/tmp/.evtchk";
	mkdir(d, 0755);
	char p[256], q[256];
	snprintf(p, sizeof(p), "%s/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", d);
	snprintf(q, sizeof(q), "%s/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", d);
	int t = open(p, O_CREAT|O_RDWR, 0644); close(t);
	int ifd = inotify_init1(0);
	int wd = inotify_add_watch(ifd, d, IN_MOVED_TO|IN_CREATE|IN_DELETE);
	printf("wd=%d\n", wd);
	if (rename(p, q) != 0) printf("rename: %s\n", strerror(errno));
	char buf[4096];
	int n = read(ifd, buf, sizeof(buf));
	printf("read=%d (%s)\n", n, n < 0 ? strerror(errno) : "ok");
	for (int off = 0; off < n; ) {
		struct inotify_event *e = (void*)(buf + off);
		printf("  ev wd=%d mask=%#x len=%d name=%.*s\n", e->wd, e->mask, e->len, e->len, e->name);
		off += sizeof(struct inotify_event) + e->len;
	}
	if (rename(q, p) == 0) { n = read(ifd, buf, sizeof(buf)); printf("read2=%d\n", n); }
	return 0;
}
