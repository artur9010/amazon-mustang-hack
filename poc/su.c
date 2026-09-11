/* Minimal setuid-root su for the mustang root (CVE-2022-38181).
 *
 * run.sh installs this (via the exploit) as /data/metrics/su, chmod 6755,
 * chown root:root.  /data/metrics is a loop-mounted ext4 with neither
 * nosuid nor noexec, so the setuid bit is honoured there.
 *
 * NOTE: only gives full root while the exploit has SELinux in Permissive
 * mode; after a reboot SELinux is Enforcing again and this setuid binary
 * stays confined to u:r:shell:s0 (re-run the exploit to re-arm).
 *
 * build:
 *   zig cc -target arm-linux-musleabihf -static -O2 -o su poc/su.c
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	/* we are already euid 0 via the setuid bit; make it real */
	setgid(0);
	setuid(0);

	if (argc > 1) {
		execvp(argv[1], &argv[1]);
		perror("execvp");
		return 127;
	}

	/* -p is required: mksh drops privileges otherwise */
	execl("/system/bin/sh", "sh", "-p", NULL);
	perror("execl");
	return 127;
}
