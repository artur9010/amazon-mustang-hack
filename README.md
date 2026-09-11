> **AI-assisted project.** This research, exploit development, and documentation
> were produced with AI assistance using the models **GLM-5.3** and
> **DeepSeek V4.1 Flash**.

# amazon-mustang-hack

Root exploit research for the **Amazon Fire 7 9th gen (mustang, MT8163, Mali-T720)** on the
final firmware — **Fire OS 7.3.3.1, PS7331.4463N, kernel 4.9.117 (built 2025-05-03, SPL 2024-08-01)**.

Goal: LineageOS. Bootloader path is dead on this unit (patched bootrom — preloader-only via
CMD short), so the only remaining route is a software kernel exploit.

## Quick start

```
# one-shot: build, run the exploit (retries across the probabilistic reclaim),
# install a setuid-root su and verify it as an unprivileged user
nix-shell -p android-tools --run './run.sh'          # add -p zig too if no zig
```

On success:
```
/data/metrics/su id     # run a command as root
/data/metrics/su        # interactive root shell
```

The reclaim wins roughly **1 boot in 3** and a loss panics/reboots the tablet;
`run.sh` just waits for the reboot and retries. SELinux is forced Permissive as
part of the exploit, so root is **runtime-only** — a reboot restores stock and
you re-run `run.sh`.

Prebuilt `st3` and `su` (armv7 static) are committed, so no toolchain is needed
to run. `./run.sh --build` rebuilds them from `poc/*.c` if you have zig.

# Anything below is just a log of work done by model, no hooman input below.

## PRIMARY TARGET (since session 5): kbase CVE-2022-38181 — stage 2 PROVEN

GhostLock (below) is parked: MTK's BUG_ON rtmutex variant + zero kernel-address
disclosure from shell = architectural dead end on this build (sessions 2-4).
The kbase JIT UAF was re-diagnosed (the destroy-worker "unconditional panic"
was the JIT_FREE deref, log lost to adbd death mid-panic) and stage 2 is now
oracle-proven — see SESSION 5 section.

### PARKED: GhostLock, CVE-2026-43499

rtmutex `remove_waiter()` futex-PI stack-UAF (NebuSec disclosure 2026-07, fix `3bfdc63936dd`
landed 2026-04). Vulnerable range 2.6.39–7.1 → **our 4.9.117 (May 2025) is affected**.

Verified on our exact build:
- `CONFIG_FUTEX=y`, rtmutex compiled in, bug present verbatim:
  `rtmutex.c:1108-1111` uses `current->pi_lock`/`current->pi_blocked_on` (should be
  `waiter->task`); buggy call site `rtmutex.c:1723` (`rt_mutex_start_proxy_lock` error path)
- Trigger surface = pure futex syscalls (`WAIT_REQUEUE_PI`/`CMP_REQUEUE_PI`), no device node,
  nothing SELinux-gated — the kbase path's fatal obstacles don't exist here
- Consumer: `sched_setattr` → `__sched_setscheduler` → `rt_mutex_adjust_pi(p)` at
  `sched/core.c:4706` — derefs stale `pi_blocked_on` ✓
- Proxy waiter lives on the **waiter thread's own stack** (`futex.c:1975` passes `this->rt_waiter`,
  declared in `futex_wait_requeue_pi` at `futex.c:2880`) → waiter stamps its own freed frame
  via arm32 `select` (nr 142) fd_sets
- Exploitation climate: **no KASLR** (fixed base 0xc0008000), no PAN, `DEBUG_RT_MUTEXES` off
  → compact 48-byte `rt_mutex_waiter` (tree_entry@0, pi_tree_entry@0xc, task@0x18,
  lock@0x1c, prio@0x20, deadline@0x28)
- **Minimal chain**: 2 write-slots → `modprobe_path` @ **0xc111488c** (string self-located in
  vmlinux; `KALLSYMS_ALL` off so data symbols need this trick) → unknown-binfmt exec → root
  script (setenforce 0, disable OTA, su)
- References in `refs/`: NebuSec/CyberMeowfia (original), GhostLock-5.10 (Fire OS 8 port,
  full 32-bit ARM trigger in `src/exp32/`), ghostlock-...-4.19-k40 (Qualcomm 4.19 Android port)

### TODO (port plan)
1. Write trigger (3-thread requeue-PI deadlock, cores 0-3) — port of `exp32/main.c`
2. Stamp geometry: `rt_waiter` frame offset vs `do_sys_select` fd_set area — disassemble
   our vmlinux (`do_sys_select` stack_fds vs `futex_wait_requeue_pi` frame), expose
   STAMP_NFDS/STAMP_WAITER_OFF as tunables
3. Fake-writer encoding for arm32 48-byte waiter → "write V to ADDR" slots
4. 2 slots → modprobe_path, fire, root script
5. Fallbacks if select-stamp can't reach: setsockopt(MCAST_JOIN_SOURCE_GROUP) stamp

## Status

- [x] Bootrom (amonet hardware method) — patched on this unit, dead end
- [x] mtk-su (CVE-2020-0069) — patched, `Failed critical init step 3`
- [x] Attack surface survey — `/dev/mali0` world-RW + SELinux `gpu_device`, kbase r26p0-01rel0
- [x] CVE-2022-38181 confirmed in exact-build source; stage-1 trigger works
- [x] CVE-2026-43499 (GhostLock) verified but blocked: MTK BUG_ON rtmutex
      variant + no kernel-address disclosure from shell (sessions 2-4)
- [x] **CVE-2022-38181 stage 2 PROVEN (session 5): destroy-worker panic was
      a misdiagnosis; UAF redirect onto sprayed region, oracle-verified**
- [ ] Stage 1: trigger + stamp + consumer (crash = chain live)
- [x] Stage 2 (kbase path): UAF redirect onto sprayed region — PROVEN session 5
- [ ] Stage 2b: raw-byte slot control (xattr stamp churn) → unlink write
- [x] **Stage 3: arbitrary kernel function call → ROOT (session 10)** — nf LOCAL_OUT
      hook hijack, `selroot` 2-packet chain: zero `selinux_state.enforcing`, rewrite
      fake entry to `commit_creds(&init_cred)`. `uid=0`, SELinux Permissive.
- [_] Stage 4: root script (su, permissive, OTA off) + persistence — root obtained;
      **persistence blocked** (see SESSION 11): LK gates verity-off/SELinux-permissive on
      eng/unlocked, boot-time re-exploit has no viable executor. Next: reverse LK/amzn_verify_unlock.
- [ ] Stage 5: custom OS boot chain


## Key findings

### Device / firmware
- Model KFMUWI, device `mustang`, Fire OS 7.3.3.1 `PS7331.4463N/0031575863040`
- Kernel `4.9.117-g08fe75b-dirty`, built Sat May 3 01:25:15 UTC 2025 (Linaro GCC 6.3-2017.05)
- Amazon silently re-issued 7.3.3.1 in May 2025 (new incremental, same version string)
- Bootrom post-2020 revision: short-to-GND on eMMC CMD gives **preloader only** (patched)
- `/dev/kb`, `/dev/dkb` (Amazon kernel-backup partitions) root:drmrpc 0660 — locked

### Why CVE-2022-38181 applies
- Driver: `mali_kbase` **r26p0-01rel0** (Midgard, Mali-T720), **inside NVD affected range r4p0–r31p0**
- Amazon's May 2025 rebuild shipped the 2018 bug verbatim — no backport
- Exact vulnerable code, source-verified:
  - `mali_kbase_mem.c:2721` `kbase_jit_destroy_worker` frees region, **never clears `kctx->jit_alloc[id]`**
  - `mali_kbase_softjobs.c:1270` `kbase_jit_free_finish` derefs the stale `jit_alloc[ids[j]]`
  - `mali_kbase_mem.c:3138` `kbase_jit_backing_lost` → destroy path (fires during reclaim)

### Exploitation climate (all verified from live config dump + OTA vmlinux)
- armv7 32-bit, non-LPAE → **no KASLR** (kernel at fixed `0xc0008000` VA / `0x40080000` PA)
- **No `ARM_SW_DOMAIN_PAN`** → ret2usr viable; `CONFIG_PANIC_ON_OOPS=y` (failed attempts = reboot)
- No `SLAB_FREELIST_RANDOM`/`HARDENED`, no `CONFIG_USER_NS`/`USERFAULTFD`/`NF_TABLES`
- `CONFIG_MODULES=y`, no `STATIC_USERMODEHELPER` → `modprobe_path` overwrite = root
- 1 GB RAM → direct reclaim (needed for eviction) trivially reachable; **pressure >~1 GB
  panics the kernel on its own** (unrelated lowmem/OOM bug) — keep spray ≤ 900 MB, use ~700 MB

### UAPI quirks hit during PoC development (r26p0, `_IOC_TYPE 0x80`)
- `MEM_ALLOC` union is 32 bytes (`in` has 4 × u64 incl. `extent`)
- flags must include `BASE_MEM_PROT_GPU_RD|WR` (bits 2|3), not legacy R|W
- **tracking-page mmap required before any alloc**: `mmap(fd, offset=3<<12, PROT_NONE)`
- `JOB_SUBMIT` stride must equal `sizeof(base_jd_atom_v2)` = **48** (`base_jd_prio`/`base_jd_dep_type` are u8 typedefs)
- JIT: `MEM_JIT_INIT` (nr 14, v2 struct), alloc/free are **soft jobs** via `JOB_SUBMIT`
  (`BASE_JD_REQ_SOFT_JIT_ALLOC`=0x209, `...FREE`=0x20a; `jc`=user ptr, `nr_extres`=count)
- JIT alloc result is written by the kernel through `info->gpu_alloc_addr` (a GPU VA you must
  pre-allocate and pass)

### Stage-1 differential (proof the bug fires)
| evictable object | pressure | result |
|---|---|---|
| none | 900 MB | survived |
| none | 1300 MB | panic (system lowmem bug — unrelated) |
| normal region + DONT_NEED | 700 MB | survived |
| **JIT region + DONT_NEED** | **700 MB** | **panic in reclaim path** |

Panic occurs during eviction itself (`evictable_reclaim_scan_objects` → `backing_lost` →
destroy worker) — the dangling refs (`jit_alloc[]`, evict list) are walked before we ever
submit `JIT_FREE`. Stage 2 must win the race: reallocate the freed `kbase_va_region` with our
own `MEM_ALLOC` spray while pressure is still running.

## Artifacts

- `poc/stage2.c` — stage-2 exploit (modes: `step`/`uaf`/`spstep`/`spfree`/`spray`/`keys`)
  — `spray 700` = full oracle run; survives and pauses (kill to clean up)
- `poc/mustang_jit_uaf.c` — stage-1 PoC (modes: `jit N` / `control N` / `pressure N`)
- `poc/build.sh` — zig cross-build (static musl armv7)
- `kernel/vmlinux` — symbols recovered from the exact OTA build (vmlinux-to-elf)
- `kernel/config-*` — `/proc/config.gz` dump from the running device
- `ksrc/` — Amazon OSS source (platform.tar + extracted `midgard-r26p0` tree)
- OTA: `/tmp/opencode/mustang_ota.bin` (sha256 `6068515a…` matches fireos-archive)
  and 2.2 GB kernel-source tarball kept at `~/Desktop/amazon-mustang/`
- Source tree path: `ksrc/kernel/mediatek/mt8163/4.9/drivers/misc/mediatek/gpu/gpu_mali/mali_midgard/midgard-r26p0/`

## Build & run

```
nix-shell -p zig --run 'zig cc -target arm-linux-musleabihf -static -O2 -o juaf poc/mustang_jit_uaf.c'
adb push juaf /data/local/tmp/juaf && adb shell chmod 755 /data/local/tmp/juaf
adb shell /data/local/tmp/juaf jit 700      # full trigger (~reboots device)
adb shell /data/local/tmp/juaf control 700  # no-JIT control
adb shell /data/local/tmp/juaf pressure 700 # raw memory-pressure control
```

## References

- GHSL-2022-054 advisory: https://securitylab.github.com/advisories/GHSL-2022-054_Arm_Mali/
- Mo's Pixel 6 exploit writeup: https://github.blog/2023-01-23-pwning-the-all-google-phone-with-a-non-google-bug/
- Fire HD 10 (trona) precedent, same bug family: ericpardee.github.io/fire-hd-ownership
- Amazon OSS portal: amazon.com gp/help/customer/display.html nodeId=200203720
- XDA unlock thread (dead for this hw rev): xdaforums.com/t/fire-7-2019-mustang-unbrick-downgrade-unlock-root.3944365/


## Session 3 addendum (deep syscall-stamp survey)

Copy-source depths measured (absolute vs syscall-entry sp0; waiter spans -0x1d8..-0x1a8):
- sendto sockaddr @ -0xc4 | process_vm iov @ -0x104 | recvmsg iov @ -0x11c
- sendmsg iov @ -0x12c | recvmmsg iov @ -0x154 | select fds @ -0x174
- pselect6 fds @ -0x19c | **sendmmsg iov @ -0x1bc (BEST — 0x1c short of waiter+0x00)**
- poll entries @ -0x3e0 (entirely below; wrong side)

Ruled out this session:
- io_submit chain too shallow (~-0x130) | semtimedop: CONFIG_SYSVIPC=n (stub)
- configfs mounted but ZERO subsystems registered (no mkdir targets)
- /sys/kernel/debug, /config: SELinux-denied for shell
- /proc/sys/kernel: getdents works (29 entries listed), only pid_max OPENABLE;
  kptr_restrict/hotplug/hostname/domainname reads all denied
- Write value is ALWAYS waiter+0 (kernel stack addr, executable, shellcode at
  +0x1c): rb_link_node *link = node, insert_color writes parent-color — no
  controlled-value variant possible without tree-field stamping (gap -0x1d8..-0x1bc)
- Double-deref dispatch fields read *(waiter+0)=1, *(waiter+4/+8)=0 — BLX 1/0
  (nf_hooks, net_families, inet[6]_protos, seq_file->op all dead)
- timer_list.function@+0xc and work_struct.func@+0xc would read *(waiter+0xc) =
  pi_tree self-ptr = EXECUTABLE waiter+0xc — but no path queues waiter+0 as
  timer/work (link corruption / no indirect queue sources)
- Tree-root-nonzero (sysctl handler slot) = deterministic pointer-chase through
  .text as rb-tree; terminates at a zero word — offline-simulable, but landing
  in a useful writable slot is implausible

Remaining leads for session 4:
1. ioctl deep paths: dev_ioctl ifreq copy (40B user data) — measure
   SyS_ioctl→sock_ioctl→dev_ioctl chain depth vs -0x1d8
2. Any other 0x1c-deeper copy than sendmmsg (nothing found yet)
3. If stamp-surface hunt fails: reconsider walk-chained constructs or
   hunt writable-zero-called slot classes not yet enumerated


## SESSION 4 — THE TWO BREAKTHROUGHS

### 1. MTK's rtmutex_common.h is the whole mystery
MTK replaced upstream's NULL-safe rt_mutex_top_waiter with:
```c
w = rb_entry(lock->waiters_leftmost, struct rt_mutex_waiter, tree_entry);
BUG_ON(w->lock != lock);   // compiled to: ldr sb,[lock+8]; ldr r3,[sb+0x1c]; cmp; bne→udf#0x12
```
NO NULL CHECK + BUG_ON. Every all-zero anchor dies at *(NULL+0x1c); garbage
anchors die at the udf. THE WALK REQUIRES: lock->waiters_leftmost (lock+8)
must point at a fake waiter W (writable) with W->lock (+0x1c) == lock.

Walk flow fully mapped (rt_mutex_adjust_prio_chain @ 0xc0189a58):
- 9b44-9b54: retry head; pi_blocked_on==NULL → clean exit ret 0
- 9abc-9adc: orig_waiter==NULL → skip pi_waiters checks (adjust_pi always passes NULL)
- 9b10-9b28: prio check (prio==task->prio + MIN → exit 9b58)
- 9b2c-9b38: trylock(lock+0) — ticket; fails → retry loop w/ counter bail (9a90-9aa8, limit @ *(0xc11189c8))
- 9ba4-9bc0: deadlock checks
- 9bcc-9bd8: THE BUG_ON (leftmost→W→W->lock==lock or die)
- 9bdc-9c04: dequeue (leftover tree RB_CLEAR_NODE'd = EMPTY → safe skip), prio/deadline write
- 9c04 bl: rt_mutex_enqueue → *link = waiter+0 at lock+4 ← THE WRITE
- 9c3c+: owner==NULL → clean exit path

### 2. The kernel-stack-address leak (kills the address-free requirement)
/proc/self/task/<tid>/stat field 28 (kstkesp) returns REAL kernel SP for
syscall-blocked threads from SHELL context (verified: nonzero values observed).
- waiter blocks in read(blocking_pipe) → stat → kstkesp
- stack base = kstkesp & ~0x1fff (arm32 THREAD_SIZE=8192)
- rt_waiter abs addr = base + fixed delta (computable: sp0 = base+0x2000-0x48 pt_regs; waiter = sp0-0x1d8)
- ALL self-referential stamp values become computable!

### Full self-consistent stamp (after leak):
- L = waiter+0x24 (fake lock IN THE WINDOW — all 4 words controllable)
- iov[0].base (waiter+0x1c lock) = L
- iov[0].len (waiter+0x20 prio) = 1 (≠139)
- W = waiter+0x1c; stamp *(W+0x1c) = *(waiter+0x38) = L (BUG_ON passes)
- lock+0 (waiter+0x24) = 0; lock+4 (waiter+0x28) = 0 (write lands here);
  lock+8 (waiter+0x2c) = W; lock+0xc (waiter+0x30) = 0 (owner NULL)

### Oracle status
- crash during walk = walk ran (dead-lock probe: deterministic crash, clean code)
- clean walk + no write = trylock-fail retry-bailout (kptr anchor: runtime word nonzero)
- Everything is now deterministic post-pollution-fix.

### Next session TODO
1. Implement leak: waiter blocks on pipe, main reads stat, computes base
2. Stamp self-consistent window, fire walk → crash-free completion = write proven
3. Weaponize: write always lands at lock+4 (rb_link_node) — lock must live in
   the window (only fully-controlled memory), so target selection research:
   either find called-slot-in-window trick, or two-stage construction.


## SESSION 4 FINAL STATE — THE WALL (precisely characterized)

### The complete picture
The walk fires deterministically (dead-lock probe: crash every time, clean code).
The write cannot land because of a 3-way kernel-hardening coincidence:

1. **MTK rtmutex BUG_ON variant**: lock+8 (leftmost) MUST point at W with
   *(W+0x1c)==lock. All-zero/garbage anchors die. No static self-referential
   pattern exists (6571 candidates scanned, 0 hits). Runtime pointers unknown.
2. **No kernel-address disclosure from shell**:
   - kstkesp on arm32 = USER SP (task_pt_regs->ARM_sp) — not kernel stack. DEAD.
   - dmesg/pstore/pagetypeinfo/kallsyms/stack — all denied.
   - kptr_restrict=1 at runtime (fops anchor words also runtime-nonzero — the
     kptr anchor run exited via trylock-fail retry-bailout, not trylock success)
3. **fops tables in rodata**: trylock strex aborts (session-3 sweep crashes).

The stamp window (waiter+0x1c..0x5b) is the only controlled+known-content
memory, but its ADDRESS is the unknown we need. Self-referential constructions
all require stamping a kernel address as a constant — circular without a leak.

### gitchw comparison (why their ARM32 write worked, ours can't yet)
Their 5.4 kernel has UPSTREAM rtmutex_top_waiter (NULL-safe: `if (!leftmost)
return NULL`) — empty-tree anchors survive, their write landed on null_fops
(writable on their kernel). Even THEY are stuck at dispatch ("ioctl reboot").
Mustang's 4.9.117 MTK tree has the BUG_ON variant — Fire OS 8 tablets
(GhostLock-5.10) succeeded because their 5.10 kernels are upstream-style.

### Session-4 verified facts
- Walk retry loop has a counter bailout (limit @ *(0xc11189c8)); trylock-fail
  on runtime-nonzero anchor words → clean retry-bailout exit (kptr anchor runs)
- No-requeue path (9ce4, FULL walk) also derefs leftmost at 9d64 — no escape
- RB_CLEAR_NODE self-pointers exist as leftovers in the window (waiter+0 and
  +0xc contain their own addresses) but no check-comparison uses them in a
  way that avoids stamping known addresses
- Real-mutex candidates (chain mutex has live waiter = BUG_ON would pass) —
  but &chain_mutex is a heap address, unreachable without leak

### NEXT SESSION OPTIONS (ranked)
1. **logcat kernel-pointer hunt**: Amazon HALs/daemons are chatty; any logged
   kernel pointer (even stale) unblocks the construction. Cheap to test.
2. **/proc/net %pK behavior on THIS build**: some 4.9 trees print unhashed
   pointers in /proc/net/tcp,udp,unix for unprivileged readers. Test live.
3. **Thread-exit paths on dangling pi_blocked_on** (one-shot, different derefs).
4. Revisit shelved kbase JIT bug with accumulated 4.9 knowledge.


## SESSION 4 ADDENDUM — LEAK HUNT: EXHAUSTED (definitive)

Tested and dead from shell domain:
- /proc/net/{tcp,unix,packet,netlink,ptype}: %pK-hashed to 00000000 (kptr_restrict=1)
- /proc/timer_list: READABLE but pointers %pK-zeroed (symbols visible, no addrs)
- logcat: no kernel pointers in Amazon/wpa chatter
- kstkesp (stat f28): USER SP on arm32 (task_pt_regs->ARM_sp)
- MTK nodes (/proc/ged, mtk_cmdq_debug, mtktz, ptp, chip, aed, driver/*): all
  SELinux-denied
- /proc/{iomem,vmstat,kmsg,keys,crypto,slabs...}: denied
- /sys/kernel/notes: denied
- CONFIG_VECTORS_BASE=0xffff0000 (high vectors — NULL+0x1c faults)
- CONFIG_KUSER_HELPERS=y (kuser at 0xffff0000, not page 0)

CONCLUSION: GhostLock on mustang requires a kernel-address disclosure that
this kernel does not expose to the shell domain. The self-referential fake
lock cannot be constructed without it.

## DECISION POINT

(a) Boot-deterministic grind: reboot → calibrate stack address via crash
    oracle (~20-30 reboots), verify reproducibility. Long shot — late-boot
    thread stack allocation unlikely stable.
(b) PIVOT back to kbase CVE-2022-38181 with accumulated assets: exact-build
    vmlinux + full source + toolchain + O_SYNC trace discipline + deep 4.9
    knowledge. Original blocker (destroy-worker panic during JIT eviction)
    is a spray-timing problem, now better understood.
(c) Stop at honest ~45%: trigger proven, walk mapped to the instruction,
    write blocked by MTK BUG_ON + no-leak.

Recommended: (b) — the kbase bug is verified-present in this exact source,
had a working trigger, and its blocker is mechanical, not architectural.

## SESSION 5 — STAGE 2 PROVEN (option b executed)

### Re-diagnosis: the "unconditional destroy panic" never existed
`step` mode (alloc id=1 → DONT_NEED → 700MB pressure → MEM_QUERY, NO free)
**survives**: query=-1 (region freed by destroy worker, rbtree-clean).
The worker path is byte-identical to the legal JIT_FREE-under-pressure flow.
Session-1's crash was always the `JIT_FREE` dangling deref; its log line was
lost because the panic kills adbd mid-flush. Verified twice more with `uaf`
mode (bare free → panic, same log cutoff). **The GHSL-2022-054 flow is fully
live on this build.**

### Complete primitive inventory (exact-vmlinux disassembly)
`kbase_jit_free(kctx, reg)` @ 0xc058495c with fully-controlled fake reg:
- `reg->cpu_alloc` NULL → backed size 0 → trim block skipped (0xc0584978)
- bin decrement: `kctx+0x147dd` (byte) + `kctx+0x147de+bin_id` (byte)
- `mark_reclaim(reg->gpu_alloc)` @ 0xc059b158: chain
  `K=*(gpu_alloc+0x38)` → `*(K+0x1429c)==0` skips mm-atomics →
  atomic_sub nents@K+0x141c8, `D=*(K+4)` → atomic_sub nents@D+0x538.
  With nents=0 all writes are no-op stores (strex of same value).
- `reg->flags |= 0x100000` (write into fake, benign)
- shrink_cpu_mapping early-exits when new==old (nents=0 → return)
- `list_add(gpu_alloc->evict_node, &kctx->evict_list)`: evict_list head
  @ kctx+0x1427c; writes into gpu_alloc+0x18/0x1c (must be writable)
- WARN path (0xc0584bd4) is nonfatal (no panic_on_warn) and CONTINUES
- **UNLINK @ 0xc0584b08/b0c**: `r3=*(reg+0x3c) prev, r2=*(reg+0x38) next`
  → `*(next+4)=prev; *(prev+0)=next` — two arbitrary write-whats-wheres,
  then relink of reg+0x38 into jit_pool_head @ kctx+0x148e8

### Static fake-gpu_alloc chain (offline vmlinux scan, /tmp/opencode/scan_s.py)
9 candidates; **S=0xc118b7ec** (xfrm data, dormant on this device):
`*(S+8)=0` (nents), `*(S+0x18)=S+0x18` (empty evict_node → no WARN),
`K=*(S+0x38)=0xc118b820` → `*(K+0x1429c)=0`, K/D+0x141c8/+0x538 all in
writable data. Oracle targets staged: `init_uts_ns.name.nodename=0xc110d561`
("(none)", readable via uname), scratch P=0xc118bd58 (xfrm zeros).
Avoid S=0xc111cba4 (tracepoint-adjacent). CONFIG_DEBUG_RODATA=y → all write
targets must be in .data/.bss (bss 0xc11d9000-0xc12d9000).

### Spray engineering (what worked, what didn't)
- `add_key` (CONFIG_KEYS=y): SELinux-denied for shell. Dead.
- `setxattr` value buffer: kvmalloc(96)+copy_from_user happens BEFORE the
  SELinux check → alloc dance is SELinux-proof even when the call fails;
  transient (freed at syscall end), bytes persist at +4..95 (freelist ptr
  clobbers +0..3 = rblink, unused by kbase_jit_free)
- **kbase_va_region itself: kzalloc(72) → kmalloc-96!** MEM_ALLOC(va=0x40,
  commit=0x10) puts ONLY the region in kmalloc-96 (phy alloc → 384) →
  deterministic reclaim type. A real-region victim makes kbase_jit_free
  complete through fully-legal state (empty jit_node → self-unlink).
- Sequential post-pressure spray: ALWAYS misses — the worker frees the slot
  mid-pressure into partial slabs (SLUB: free to non-active slab ≠ cpu
  freelist); under pressure our allocs fail → zero net volume → no rotation
- Pinned sprayers + caps: still miss (512-cap exhausted before eviction;
  worker may run on any cpu)
- **WINNER: commit_pages=0 spray** — no phys pages → MEM_ALLOCs succeed
  through the whole pressure storm → ~6000 net allocations → partial-list
  rotation guaranteed. 8 threads (2/cpu, cpus 0-3 hardcoded — /proc/cpuinfo
  is shell-filtered to 1 core, use Cpus_allowed_list) + pressure child
  pinned to cpu0 + 16-alloc retention batch after join.
- query(jit_va) trap: post-reclaim, spray regions reuse the freed VA in the
  custom zone → query=0 is ambiguous (live-original vs spray-covering-VA)

### ORACLE HIT — machine-verified redirect
`spray 700` run 2026-09-11: 5895 regions sprayed during pressure, JIT_FREE
on dangling id=1 completed on a reclaimed region, then
`JIT_ALLOC(0x40, bin 0)` walked jit_pool_head and returned **sprayed region
#4251's VA (0x142701000)** — the exact region the dangling pointer consumed.
Process kill after: kctx teardown clean, no crash. **Stage 2 complete:
deterministic UAF redirect with controlled object type + contents.**

### Stage 3 plan (raw-byte unlink)
Region-type reclaim gives legal-dance survival but jit_node is INIT'd
self → no unlink primitive. Need raw bytes at +0x38/+0x3c:
1. xattr stamping: alternate region-alloc bursts (net volume → slab
   rotation) with xattr storms (stamp every head slot, bytes persist
   post-free) → quiet window → deref
2. or pinned sendmsg cmsgs (optmem_max=10240 → ~106 × 96B held)
3. then: W1 `*(N+4)=P` with P=userland shellcode page (no PAN!) —
   candidates: const fops are .rodata (DEBUG_RODATA) → target non-const
   fn ptr in .data, or binfmt `formats` list head, or sysctl proc_handler
   (verify table writability). fallback: modprobe_path via byte-chained
   writes (values must be writable addrs — use pointer-shaped targets)
4. no-KASLR + exact vmlinux: prepare_kernel_cred 0xc0149e3c,
   commit_creds 0xc014993c

## SESSION 5B — STAGE 3: weapon built, reclaim race not yet won

### Done
- **Stage-3 weapon complete & staged** (`poc/stage3.c`):
  - Target: `kern_table[pid_max].proc_handler @ 0xc1113f40` (writable
    .data, verified via string-pointer scan + handler == proc_dointvec_minmax)
  - N = shellcode entry 0x11111112 (mmap 0x11111000; W1 clobbers entry+4,
    skipped by `b +8`; W2 writes N at P = handler field)
  - arm32 ring0 shellcode hand-encoded: prepare_kernel_cred(0) +
    commit_creds + ret 0; trigger = `read /proc/sys/kernel/pid_max`
    (readable from shell); runs in own task context → creds apply to us
  - benign oracle mode writes uts nodename (0xc110d561, unaligned ok)
- **Spray primitive selection**:
  - NETLINK_USERSOCK sendmsg pins (msg_control kmalloc-96 copy, held
    while blocked, never parsed): **SELinux-denied** (socket create EACCES)
  - unix/UDP sendmsg: cmsg parsing poisons payload bytes ✗
  - **inotify events**: `inotify_handle_event` kmallocs name_len+0x1d,
    name bytes (fully controlled, NUL/slash-free constraint) at event+0x1c;
    name_len=60 → kmalloc-96; queued → held; 4 instances → 4 events per
    rename; SELinux-OK from shell. Fake redesigned NUL-free: cpu_alloc
    points at S (nents@S+8 = 0 → same semantics as NULL)
- **Mechanical chain validated end-to-end** (drain4, no-eviction run):
  20K drained events + 13.5K multi-cpu trailing renames + JIT_FREE +
  oracle + pause, all clean. O_SYNC log (/data/local/tmp/s3.log) survives
  panics — exact crash-point forensics.

### Reclaim attempts on the freed slot (all missed so far)
| variant | result |
|---|---|
| concurrent rename sprayers during storm | renames stall (journal/GFP_NOFS) → 128 total → garbage deref |
| pre-drain 12K events + pressure + small trailing | crash at deref |
| + kill-child-at-eviction (10ms poll) | crash at deref |
| + cpu0-pinned lifecycle (drain3) | crash at deref |
| stepped pressure (drain4 v1) | children freed memory on exit → no eviction (validated legal path) |

Working hypothesis: **storm-junk race** — between the destroy worker
freeing the slot (mid-storm) and child-kill/quiet, residual reclaim
activity takes the sole-free-slot of the victim slab with non-payload
bytes. Region spray (stage 2) wins because it allocates continuously
DURING the storm; renames can't.

### Gotchas hit
- spray toggle bug: rename source must be the payload name (was temp
  name → ENOENT after 2 waves → only 512 events ever)
- device hostname is "localhost"/varies — oracle compares before/after
- paused st3 + pkill → device WEDGE (teardown with 33K events?!) — kill
  paused processes only via reboot; second hard-wedge of the session
- /proc/cpuinfo shows 1 cpu to shell; use Cpus_allowed_list

### Next moves (ranked)
1. drain4 @ 500MB (eviction threshold confirmed there), 1ms poll, instant
   kill, 4-cpu trailing × 3200 — shrink the storm window
2. xattr-stamp churn (setxattr alloc-copy happens BEFORE SELinux check —
   SELinux-proof) concurrent with storm + region rotation, end-with-stamp
3. accept region-reclaim (proven) + find a second-stage primitive on the
   region-victim state (double jit_free analysis negative so far)

## SESSION 5C — the blocker, precisely characterized

### Empirical results this session
- drain4@500 (1ms poll, instant kill, +4.5K renames): still crash at deref
- overlap trailing with kill (drain5): crashes EARLIER (renames during
  kill-recovery storm hit a system-level fault) — overlap abandoned
- **ISOLATING EXPERIMENT (`iso` mode)**: identical timing, trailing with
  commit-0 REGIONS + stage-2 pool-reuse oracle → **ORACLE HIT**
  → timing/reachability are FINE; events are the problem
- mask-cycled events (MOVED_TO/CREATE/DELETE rotation to defeat
  inotify_merge): still crash at deref
- CONFIG_MEMCG=n → events and regions share ONE kmalloc-96 (memcg theory
  dead); inotify_merge compares names too (merge theory dead — our
  toggling names never merged; events were queued and held all along)
- /proc/slabinfo absent; /proc/self/pagemap readable but PFN-zeroed
  (post-4.0 masking, no CAP_SYS_ADMIN)

### THE ACTUAL BLOCKER (two parts, both proven)
1. **Soft-job finish runs in kbase job-scheduler WORKER context**
   (jd_run_atom ← js dispatch, mali_kbase_jd.c:81-112/677), not inline in
   the submit ioctl → `current->mm` is a kernel thread's → the elegant
   "point the fake's pointers into our own userspace mmap" design (no PAN!)
   FAULTS nondeterministically. 5/5 crashes with an otherwise-perfect fake.
2. Therefore gpu_alloc must point at KERNEL memory with a survivable
   runtime chain: `K=*(S+0x38)` readable, `*(K+0x1429c)==0` at runtime
   (skips mm-atomics), `K+0x141c8` writable, `D=*(K+4)` → `D+0x538`
   writable, nents `*(S+8)` preferably 0. The 9 offline S-candidates were
   validated against FILE bytes — runtime drift (xfrm/tracepoint init)
   makes them unverified. A wrong chain = crash = reboot (~3 min cycle).

### Session-6 plans (both fully specified)
A. **Physmap-spray fake (ret2dir, classic arm32 no-PAN)**: spray ~450MB of
   user pages each containing the fake pattern baked for ONE guessed
   address G (G&0xfff = 0x141 for NUL-free name bytes; S=G; K=G-0x141b4 so
   K+4 lands in-page; K+0x141c8/+0x1429c → G+0x10/+0xd4 in-page; D=G+0x300;
   stray sub-0 stores hit random mapped RAM - harmless with nents=0).
   Spray doubles as the eviction pressure (dirty anon = unevictable →
   only ~100-200MB extra needed). Odds ≈ 45% (page hit) × ~50% (foreign
   K+0x1429c word is zero... if K+0x1429c kept in-page per layout above,
   odds = page-hit only). Miss = crash = reboot, retry.
B. **Brute-force the 9 static S-candidates** (xfrm 0xc118b7ec first,
   tracepoint-adjacent 0xc111cba4 second...): 1 reboot per candidate,
   benign-oracle payload first, weapon on hit.
C. pagemap-based exact G (dead: PFNs masked) — do not revisit.

## SESSION 5D — physmap fake built; G-sweep 0/3; confounds eliminated

### Established this session (all binary/device-verified)
- **Cache identity CONFIRMED same**: region = kmem_cache_alloc_trace(
  kmalloc_caches[7], GFP|0x8000, 0x48) [kbase_alloc_free_region disasm];
  event = __kmalloc(89, GFP) → kmalloc-96. Events and regions CAN share
  the victim's cache. (MEMCG off; single cache set.)
- inotify queue: ≥5000 events held, no overflow, no merge collapse
  (qmeas 1000 & 5000 runs) — the event spray persists
- **iso2 (physmap spray + region trailing + oracle): HIT** — the physmap
  spray does NOT break region reclaim; machinery sound
- events vs regions reclaim: regions 3/3 (iso, iso2, stage-2), events 0/10
  BUT the 3 pmap runs are explained by G-misses at 0.3-0.45 odds each
  (P(3 misses|events-work) ≈ 0.2-0.3 — not conclusive)
- mix mode confounded: 480MB spray suffocates post-kill renames (+0);
  350MB OK (+4452); spinning failed-rename threads also disturb region
  reclaim (mix crashed, iso2 clean)
- query_commit returns -1 on EINVAL too — instrumented; EINVAL observed =
  rbtree lookup miss = genuinely freed ✓ (not a false positive)

### Current pmap design (in stage3.c, mode pmap/mix/iso2)
- G baked into every sprayed page (offset 0x2a4): nents@+0x2ac=0,
  evict self@+0x2bc/0x2c0, K=G+0x100@+0x2dc, D=G+0x200@+0x3a8;
  K+0x141c8/-0x1429c land ~20 pages up (sub-0 store harmless / read must
  be 0-or-valid). PM_SPRAY_MB 350, G sweep tried: c2a412a4, c2f4b2a4,
  c2a7d2a4 — all crash at deref
- physmap range sanity: RAM 1GB → physmap ~0xc0000000-0xc3fffffff;
  MTK carveouts (GPU/M4U/secure) may occupy chunks — G landmines

### Session-6 TODO (ranked)
1. **Extract the full kernel source** (2.2GB tarball at
   ~/Desktop/amazon-mustang/ — platform.tar): get arch/arm + mm/ +
   drivers/of + MTK reserve mappings → compute the carveout map →
   target G into verified-RAM physmap subranges; also verify kmalloc
   cache geometry (ARCH_KMALLOC_MINALIGN!) and the 0x8000 GFP bit
2. G sweep with placement-informed guesses (multiple reboots, vary spray
   size to decorrelate)
3. If G sweep exhausts: reconsider multi-G payload or S-candidates from
   runtime-plausible statics (uts-adjacent pointer fields failed: NULL-K)

## SESSION 6 — zram discovery, source extraction, event question still open

### Full kernel source now extracted
`/tmp/opencode/ksrc2/kernel/mediatek/mt8163/4.9/` (arch/arm incl.
mustang.dtsi, mm/, fs/eventpoll.c, fs/notify) from ksrc/platform.tar.
Findings:
- 0x8000 GFP bit = ___GFP_ZERO (just kzalloc; no cache split)
- kmalloc-96 is a true 96-byte cache (no HWCACHE_ALIGN on kmalloc caches)
- mustang.dtsi: memory node 0x40000000/512MB — extended by preloader
  (device shows MemTotal 977MB); CONFIG_VMSPLIT_3G, HIGHMEM=y
- **zram0 ACTIVE (SwapCached > 0)** → "dirty anon = unevictable" was
  WRONG: the physmap spray swaps out under pressure → G alias goes stale
  → added `physmap_retouch()` after the kill (faults all spray pages
  back in before the trailing/deref)

### Runs this session (all O_SYNC logged, ~6 reboots)
| run | result |
|---|---|
| pmap G=c2a412a4 400MB | crash at deref |
| pmap G=c2f4b2a4 480MB | crash; +0 post-kill renames (480MB suffocates fs) |
| iso2 (spray + regions + oracle) | **REGION HIT — spray doesn't break reclaim** |
| mix v1 (concurrent events+regions) | crash; confounded (spinning event threads) |
| pmap G=c2a7d2a4 350MB + retouch | crash; +4452 renames OK |
| mix2 (sequential: 2s events THEN regions) | crash; +7126 renames (28K event allocs), 2715 regions |

### Verdict on events (Bayesian, honest)
Regions reclaim: 3/3. Events: 0/~12 attempts including 28K exclusive
allocations with head start and correct-by-construction fake. If events
reclaim with p_hit(G)≈0.35, five pmap misses ≈ 11.6% — possible but now
unlikely (~10-15%). Either events structurally cannot take this slot
(reason unknown — same cache, same context, same timing) or our G guesses
are systematically missing (highmem-boundary skew, allocator placement).

### Session-7 decision tree
1. **Settle G first** (cheap, no exploit): temporarily instrument the
   ISO2 flow — region trailing + oracle — but make the PAYLOAD event a
   physmap fake and check whether ANY G in a swept range produces a
   nodename change without regions racing (pure pmap, G sweep over
   ~0xc1500000-0xc2a00000 lowmem center, 1 G per reboot, 4-5 reboots)
2. If G sweep exhausts → events declared dead → hunt alternative
   raw-byte kmalloc-96 allocators reachable from shell (audit: seq_file,
   tty ldisc, fdtable, sk_filter (blocked: code-field at +0x38),
   netlink nlmsg (skb ✗), keys (denied)) — or revisit two-stage region
   primitives (analysis negative so far)
3. Consider UART/ramoops unlock via root later; do not chase

## SESSION 7 — cmdline bombshells; event mystery now precisely bounded

### mustang_defconfig CONFIG_CMDLINE (ground truth for placement):
`vmalloc=496M slub_max_order=0 slub_debug=O loglevel=8 initcall_debug`
1. **vmalloc=496M → physmap = 0xc0008000..~0xc2080000 ONLY (low 520MB
   of RAM)** — ALL prior G guesses (0xc2a4xxxx+) were in VMALLOC SPACE.
   Every "G-miss" conclusion from sessions 5D/6 is invalidated; the
   crash-interpretation stands but the sweep was aimed at the wrong map.
2. slub_max_order=0: all slab pages order-0
3. KMALLOC_MIN_SIZE = ARCH_KMALLOC_MINALIGN = 64 (L1_CACHE_SHIFT 6) →
   kmalloc_index() special-cases for 96/192 are DISABLED →
   region kzalloc(0x48=72) → caches[7]; event __kmalloc(89) → caches[7]
   (disasm + include/linux/slab.h:287 verified) — BOTH in the merged
   128-byte "kmalloc-128/96" cache. Cache identity: RE-CONFIRMED equal.
4. zram active → replaced anon physmap spray with **kbm_spray**: 160 ×
   2MB kbase MEM_ALLOC regions (GFP_KERNEL → ZONE_NORMAL → lowmem-only,
   pinned → zram-immune), pattern written via CPU mmap — correct range,
   ~65% lowmem coverage

### Runs (O_SYNC logged)
- kbm + G=0xc16412a4: crash at deref (+4831 renames)
- kbm + G=0xc1c4b2a4 @200MB: NO eviction (query=16 — pressure
  calibration varies with pinned spray; legal free, survived)
- kbm + G=0xc1c4b2a4 @400MB: eviction ✓, +4053 renames, crash at deref
- Valid-range G record: 0/2. If events work with ~65% coverage:
  P(2 misses) ≈ 12%. Question still open but narrower than ever.

### The question, final form
Regions take the victim slot 3/3; events 0/13. Same cache (proven at
source + disasm level), same process context, same pinned cpus, same
post-kill timing, thousands of allocations with exclusive head start.
Mechanism unknown. Remaining suspects: allocation-rate/frequency
correlation with partial-list rotation (region ioctls ~1ms apart vs
event renames ~100µs apart — opposite directions?), or SLUB freelist
ordering details under slub_max_order=0 that favor... unclear.

### Session-8 TODO
1. Instrument-grade experiment: TWO event payload variants with
   DIFFERENT N/P values alternating (two name sets) — if the nodename
   ever changes, the LAST winner is identified; sweep G in
   [0xc1200000..0xc2000000] with kbm spray, 3-4 reboots budget
2. If still 0/N: abandon events. Alternatives ranked:
   a. **pipe_buf arrays via F_SETPIPE_SZ(4096 → 1 buf? no — 16 bufs =
      kcalloc(16, 28)=448→512 ✗)** — dead
   b. audit fs/notify + fs for other name/data-carrying kmalloc-128
      objects (fanotify events? mq off; fanotify needs groups...)
   c. **seq_file buffers** (kmalloc(PAGE_SIZE) ✗)
   d. sock filters (code-field collision at +0x38 ✗)
   e. accept the region-type reclaim + chain a SECOND bug/technique
3. Re-examine WHY regions win — maybe instrument via multiple jit ids:
   N dangling slots, region-vs-event race per slot, oracle detects which
   spray took which slot → statistical fingerprint of the mechanism

## SESSION 8 — ARBITRARY WRITE ACHIEVED ON DEVICE; dispatch mystery left

### THE MILESTONE
```
[+] uname.nodename="X?lhost" (was "localhost") <<< ORACLE HIT
```
**The full raw-byte chain works on the live device**: event reclaims the
freed region slot → kbase_jit_free derefs our fake (S=physmap page from
the kbm spray, G=0xc154b2a4) → the unlink executes our two writes.
Verified repeatedly with the benign payload (nodename write).

### Session chain of discoveries
1. kbm pages were GFP_HIGHUSER → HIGHMEM, invisible to physmap
   (mali_kbase_mem_pool.c:164!) — fixed by zonelist spill: 260 × 2MB
   spray > highmem-free → surplus lands in ZONE_NORMAL (physmap)
2. First weapon attempts crashed: W1 target N+4 was a USER page —
   unlink runs in kworker ctx (no mm) → fault. Fixed by baking the ring-0
   shellcode INTO the physmap pattern at page+0x600 (direct map RWX on
   arm32 non-LPAE) — kernel-resident code, no ret2usr needed
3. ctl_table offset bug: proc_handler is at entry+0x14, not +0x18 (the
   original scan had it right; my define was wrong) — was writing extra1
4. Over-pressure regression found & reverted: kid budget 20×100MB +
   trailing 10s broke the reclaim; the working config is 2 kids/200MB +
   5s/+3200 trailing (benign hit 1/1 after revert)
5. **diag2: W2 → &pid_max global (0xc1114d7c) → read returns our value
   (-1055861411 = 0xc110d55d as int32) — write + readback PROVEN**

### The remaining mystery (one experiment from closed)
diag1 with the CORRECT handler address (0xc1113f3c): W1 fires (nodename
changes), W2 must have executed (next instruction) — yet pid_max reads
still return clean values → the handler field we write is not the one
the inode dispatches through. diag3 (queued; needs a hit boot): W2 →
entry->data FIELD (0xc1113f2c) pointing at nodename — if the read then
shows nodename-bytes-as-int, our entry IS live and only the handler
offset is somehow wrong; if unaffected, the inode uses a shadow table
copy and we hunt the live one.

### Hit-rate reality
Per-boot coin flip (~25-40%), clustered; several safe-miss/crash boots
in a row is normal. Roughly 1 in 3-4 boots is a hit. Keep the working
config EXACTLY (2 kids, 5s trailing, 260-region kbm, G=0xc154b2a4).

### Session-9 TODO
1. Complete diag3 on a hit boot (roll until "W1 FIRED")
2. If entry live: re-check handler offset empirically (write
   proc_dostring's address as handler via... N must equal a useful
   value — use the unlink to write entry->data instead and pivot: e.g.,
   data=selinux_enforcing-adjacent...)
3. If shadow table: locate the live one — kallsyms has no data symbols;
   candidates: scan /proc/sys behavior, or find a second ctl_table
   region via the header list pattern in .data (0x20-stride entries
   with handler=proc_dointvec_minmax and maxlen=4 — enumerate ALL and
   diag-write each)
4. Alternative target class that avoids dispatch entirely: .data
   function pointers called from shell-reachable paths (audit needed)
5. The write primitive itself is DONE — any reliable kernel-address
   target now suffices for root

## SESSION 9 — nf-WEAPON: reclaim+unlink+G-hit PROVEN IN-WEAPON; only the hook walk remains

### The new trigger design (replaces the sysctl-handler path entirely)
User's idea translated to kernel memory: no SUID file (system is
dm-verity RO; primitive writes kernel RAM). Instead: **fake netfilter
hook**. This kernel has the Android-common backport of the NEW
nf_hook_entries API, but implemented as a LINKED LIST (verified by
disasm of nf_hook_slow + helper 0xc09897d4):
- `__ip_local_out(net, sk, skb)` loads the entries CELL from
  **[net+0x58c]**, stores into state+0x1c, calls nf_hook_slow
- walk: `entry = *cell`; while(entry){ if (state->[4] <= entry->[0x20])
  call entry->[0xc](entry->[0x14], skb, state); entry = entry->[0]; }
  — i.e. **fn@entry+0x0c, priv@entry+0x14, priority@entry+0x20,
  next@entry+0x00**; state+4 = INT_MIN threshold (always passes)
- init_net = **0xc1104548** (CONFIG_NET_NS=n → sock_net() inlines the
  constant; 6678 movw/movt refs, histogram champion; cross-confirmed by
  nf_hook_slow's own literal). TARGET: **[init_net+0x58c] = 0xc1104ad4**
- LOCAL_OUT hook runs in the SENDER's process context → our hookfn's
  commit_creds(prepare_kernel_cred(0)) roots the process that sent the
  packet. Trigger = sendto(127.0.0.1:9) UDP.

### nf mode layout (poc/stage3.c, mode `nf 200`)
- kbm pattern pages (page-relative, single source of truth — the old
  weapon had THREE bugs now fixed: proc_handler@+0x14 not +0x18; W1
  target must be KERNEL mem (kworker ctx, no mm); baked code at
  page+0x600 vs entry G+0x600=page+0x8a4 mismatch):
  - +0x2ac/+0x2bc/+0x2c0/+0x2dc/+0x3a8: fake phy-alloc chain (unchanged)
  - +0x600: nf_code hookfn (marker store + prepare_kernel_cred +
    commit_creds + return NF_ACCEPT(1))
  - +0x700: fake entry {next=0, fn=PM_PAGE+0x600, priv=0, prio=0x100}
  - +0x740: cell → PM_PAGE+0x700
- payload: N = PM_PAGE+0x740 (0xc154b740), P = 0xc1104ad4
  → W1: *(cell+4)=P (lands in our page), W2: *(init_net+0x58c)=cell

### SELF-DIAGNOSING instrumentation (kbm_scan_for)
The kbm CPU mappings are kept; after the free we scan every sprayed
page for a known word:
- scan(HOOKS_PTR_ADDR) at page+0x744 → proves reclaim + unlink + reveals
  which phys page backs the G guess
- scan(0x600d600d) at page+0x7f0 → proves the hookfn EXECUTED
  (nf_code writes this marker as its 2nd action)

### THE RUN THAT MATTERS (2026-09-11, late session 9)
```
[+] W1 CONFIRMED: region 135 page+0x185000 <- 0xc1104ad4 (reclaim + G hit!)
[+] nf trigger done, uid=2000 euid=2000
```
**The full weapon chain fired on a live boot**: event reclaimed the
slot, the fake ran, the unlink executed, the G-guess page (0xc154b000)
was genuinely ours (region 135 page 389). W2 = *(0xc1104ad4)=cell is
the adjacent instruction — it must have executed. Yet UDP sendto did
not root us → the failure is INSIDE the hook path: walk semantics,
[state+0x1c] plumbing, priority compare, or the entry fields.
(The marker experiment to discriminate hookfn-ran-vs-not was added;
only crash-boots before session end — no clean data yet.)

### Hit-rate / boot-state learnings (hard-won)
- WORKING CONFIG (do not touch): 2 kids × 100MB stepped pressure,
  trailing 100×50ms/+3200 renames, 260×2MB kbm spray, G=0xc154b2a4,
  pre-drain ~5000 renames
- Over-pressure (20 kids / 10s trailing) BREAKS the reclaim — reverted
- Boot settle matters: runs launched immediately after boot_completed
  race the system's startup allocations → cold streaks; settle 60-90s
  after boot before running
- "W1 did not fire" (nodename check) is MEANINGLESS for nf payload —
  W1 writes into our page; use kbm_scan_for instead
- Crash-at-free boots ≈ garbage slot or G-miss conversions; benign
  control (`pmap 200`) is the environment sanity check (4/4 hits when
  warm; crash-miss when cold)
- /data/local/tmp/.w* dirs are cleaned at run start (accumulated dirs
  degrade reclaim)

### Session-10 TODO (decision tree, in order)
1. Run `nf 200` on settle-delayed boots until the W1-CONFIRMED line
   appears, then read the MARKER line:
   a. marker PRESENT, uid!=0 → shellcode's creds failed (check
      prepare_kernel_cred/commit_creds addrs; blx encodings)
   b. marker ABSENT → walk never called us: verify with a SECOND
      marker written by... next diagnostics: hookfn that ONLY writes
      the marker and returns 1 (no creds) — if still absent:
      - dump our actual entry bytes via the CPU mapping right before
        trigger (they're ours to read!)
      - check whether [init_net+0x58c] is even consulted: use the
        write to instead corrupt something observable (e.g. point it
        at a cell whose *cell = entry with fn = a kernel function like
        kfree → immediate crash on trigger = field IS consulted)
      - re-verify 0x58c offset: maybe hooks_ipv4[NF_INET_LOCAL_OUT]
        lives at a different index (NF_INET_POST_ROUTING=4?)
2. If the walk calls us: fix creds → root → then the user's plan:
   setenforce 0; cp /system/bin/sh /data/local/tmp/su; chown root;
   chmod 6755; verify `ls -la`; leave marker files
3. Persistence (post-root): boot-image patch via /dev/block/by-name/boot
   + disable dm-verity, or Magisk-style; su on /data alone is uid0-in-
   shell-domain after reboot (SELinux enforcing again) — setenforce 0
   is runtime-only
4. Cleanup notes: paused st3 processes have corrupt kctx state — kill
   via reboot only; nf hijack breaks LOCAL_OUT hooks for all traffic —
   reboot after root to restore

### Tonight's asset additions
- `poc/stage3.c` modes: pin/root/drain{,2,3,4,5}/iso — full weapon +
  oracle + isolation harness, O_SYNC crash-point forensics
- userland-fake infrastructure (ufake_prep) — KEEP but only usable if a
  context-inline deref path is ever found
- tools/: kdis/scan_s/resolve/dumpb/findsysctl offline vmlinux analysis

## SESSION 10 — ROOT ACHIEVED (2026-09-11)

### The three bugs that were blocking the nf-weapon, all fixed
1. **Wrong `init_net`**: `0xc1104548` is `__stack_chk_guard` (the movw/movt
   histogram was polluted by stack-canary loads — 2025 built the whole nf plan on
   it). Real `init_net = 0xc1185040` (confirmed: `ip_send_skb(net,...)` called
   with this literal; ~994 refs all in the net stack). IPv4 LOCAL_OUT cell =
   `init_net+0x58c = 0xc11855cc`.
2. **Double-deref bug**: `nf_iterate` treats `[init_net+0x58c]` **as the
   `nf_hook_ops` pointer itself** — it reads `fn@+0xc, priv@+0x14, prio@+0x20`
   directly from that value. The session-9 fake entry lived at
   `PM_PAGE+0x700` with the cell *pointing* at it (unused `next`/`fn` fields
   at the cell → `fn=0` → crash). The fake entry MUST live **at the cell
   address** `PM_PAGE+NF_CELL_OFF` (0xc154b740). With this fixed, the hook call
   was proven (`probe` mode = SAFE_FN processes all 200 sendtos cleanly).
3. **Physmap direct map is XN above `kernel_x_end`**: `arch/arm/mm/mmu.c`
   `map_lowmem()` maps lowram below kernel text `MT_MEMORY_RWX`, but everything
   above `kernel_x_end` `MT_MEMORY_RW` → `PMD_SECT_XN` (line 509). Baked
   shellcode at `0xc154b600` prefetch-aborts. Payload must be a **real kernel
   function pointer**, not code in the physmap.

### The SELinux wall and the 2-packet bypass
`commit_creds(prepare_kernel_cred(0))` / `override_creds(&init_cred)` gives
uid 0 but lands in the `kernel` SELinux SID, which this Fire OS policy does
**not** allow to write `/data` or `/sys/fs/selinux/enforce` (verified: EACCES).
Real `init` SID (7) also denied (fake `struct cred` test). `enforcing_setup`
is `__init` (freed → crash). `mark_reclaim`'s `atomic_sub` needs nents=1 which
breaks `shrink_cpu_mapping`'s early-exit.

**The win:** the exploit process keeps the kbm CPU mappings, so the fake nf
entry can be rewritten in place between packets:
- `selroot` mode: entry = `{fn=0xc01d503c (mov r3,#0;str r3,[r0];bx lr),
  priv=0xc1213ea8 (selinux_state.enforcing)}`.
- Packet 1: `*(enforcing)=0` → **SELinux Permissive**.
- Rewrite the entry via `kbm_cpu[reg]+off` to `{fn=commit_creds,
  priv=&init_cred}`.
- Packet 2: `commit_creds(&init_cred)` in the sender's task → **uid 0** with
  a permissive SELinux → usable root, all in one reclaim, no chain needed.

### Verified on device (2026-09-11)
```
[+] W1 CONFIRMED: region 67 page+0xad000 <- 0xc11855cc (reclaim + G hit!)
[*] sendto 0 -> -1 errno=1 uid=0 euid=0
[+] nf trigger done, uid=0 euid=0 <<< HOOK RAN - commit_creds OK
[+] ROOT: uid=0 euid=0
[+] setenforce write=1
[+] su copied bytes=236220
```
- `getenforce` → **Permissive**; paused st3 is `Uid: 0 0 0 0`,
  `CapEff: 3fffffffff`.
- `/data` is mounted **nosuid** so a setuid `su` cannot work. A tiny
  `rootshell` (send UDP → `commit_creds` on self → `execl sh`) gives an
  interactive root shell: `uid=0(root) context=u:r:kernel:s0`.
- Root can read/write `/dev/block/by-name/*` (`dd if=boot ...` OK).

### Stage-3 code state (`poc/stage3.c`)
- modes: `nf <mb> [probe|uprobe|oc|chain|fc <sid>|notrig|selroot]`
- `selroot` is the working weapon. Key statics: `init_net=0xc1185040`,
  `HOOKS_PTR_ADDR=0xc11855cc`, `ENFORCING_ADDR=0xc1213ea8`,
  `ZERO_GADGET=0xc01d503c`, `commit_creds=0xc014993c`,
  `init_cred=0xc1114f54`.
- Post-exploit is direct syscalls (no `system()`); keep the kctx alive
  (`pause()`) to avoid teardown crash.

### Remaining (Stage 4/5)
- Persistence across reboot (verity / boot image / recovery), since the cell
  hijack + permissive SELinux are runtime-only and re-running the exploit needs
  the ~1/3 reclaim coin flip.
- `su` will need a non-nosuid home (`/system`) or a launcher that re-triggers.

## SESSION 11 — PERSISTENCE RECON (Track B + Track A) and the RE handoff

Goal was persistent root. Two tracks were scoped:
- **Track B**: disable verified boot (dm-verity / SELinux) so `/system` can be patched.
- **Track A**: re-run the exploit at boot.

Both reduce to the same blocker: **make LK treat the device as `eng`/`unlocked`.**

### Verified-boot facts (exact build)
- Bootloader locked, AVB `green`, `ro.boot.unlocked_kernel=false`, `ro.boot.secure_cpu=1`,
  `rpmb_state=1`. Bootrom patched (no BROM); preloader only via CMD short.
- `/system` is mounted by **Android dm-verity from the lk-built kernel cmdline**:
  `root=/dev/dm-0 dm="system none ro,0 1 android-verity PARTUUID=b6404ef3-… "`,
  `veritykeyid=id:f3530e18f64d11fc25eb2dd762979f078de990bf`, `androidboot.veritymode=eio`,
  `skip_initramfs` (system-as-root). `dm-0` = verity device named `system`; `dm-1` = `/vendor`.
- LK: Amazon **UFBL**, `ro.boot.lk_version=0x0006`, build `0db73c9-20231025_030009`;
  preloader `pl_version=0x000a`, build `80c6fcb-20230523_065640`. `/dev/block/by-name/lk` = mmcblk0p5 (1 MB).
- Full GPT (16 partitions, no `persist`/`seccfg`/`nvram`/`protect`/`para`):
  `proinfo` p0, `PMT` p1, `kb` p2, `dkb` p3, `lk` p4, `tee1` p5, `tee2` p6, `metadata` p7,
  `MISC` p8, `reserved` p9, `boot` p10, `recovery` p11, `system` p12, `vendor` p13,
  `cache` p14, `userdata` p15. eMMC boot0 (1 MB) = preloader (`EMMC_BOOT` magic);
  boot1 (4 MB) = IDME store.

### LK (UFBL) static findings
`lk.img` header: `88 16 88 58 | 00052974 | "LK"`; ARM vector table at 0x200, rest Thumb-2,
position-independent/relocated (literal pools use `ldr+add pc`, so naive base-relative disasm fails).
Relevant strings (file offsets): `amzn_image_verify`, `amzn_verify_unlock`, `amzn_verify_code_internal`,
`unlock_code`, `unlock code error`, `unlock failed`, `$Common Kernel Signing Engineering CA0`,
`seccfg`, `para`, `ENV_v1`, `LK_ENV`, `Kfos_flags`/`Kdev_flags`/`Kusr_flags`/`Kunlock_code`/`Kunlock_version`,
`FOS_FLAGS_{NONE,ADB_ON,ADB_ROOT,CONSOLE_ON,RAMDUMP_ON,VERBOSITY_ON,ADB_AUTH_DISABLE,FORCE_DM_VERITY,DM_VERITY_OFF,BOOT_DEXOPT}`,
`[DM-VERITY] verify for system(root) is enabled`, `[DM-VERITY] verify off by fos_flags`,
`[DM-VERITY] disabled by fos_flags on eng devices or unlocked device`,
`[SELINUX] set to permissive mode by dev_flags`, `androidboot.prod=1|0`, `androidboot.unlocked_kernel=%s`.
**Conclusion: LK gates `fos_flags`/`dev_flags` security effects on eng/unlocked.**

### IDME store (eMMC **boot1**) — writable, persistent, read by LK and Android
- Magic `beefdeed` + `"2.1\0"` + count(0x19=25) at 0x0; items from 0x10.
- Item format: `char name[16]; u32 size; u32 type(=1); u32 magic(=0x124); u8 data[size] (pad4)`.
- Item offsets (pristine): `board_id@0x10 serial@0x3c mac_addr@0x68 mac_sec@0x94 bt_mac_addr@0xd0
  bt_mfg@0xfc product_name@0x198 productid@0x1d4 productid2@0x210 region@0x24c bootmode@0x26c
  postmode@0x28c bootcount@0x2ac manufacturing@0x2d0 unlock_code@0x4ec sensorcal@0x908 alscal@0x9c4
  KB@0xa00 DKB@0x1e1c device_type_id@0x2238 dev_flags@0x2274 fos_flags@0x2298 usr_flags@0x22bc
  wifi_mfg@0x22e0 unlock_version@0x26fc`. Values are ASCII (flags are **hex strings**).
- Runtime read: `/proc/idme/<name>` (read-only). Last-boot values cached; a write to boot1 takes
  effect next boot. Write path requires clearing `/sys/block/mmcblk0boot1/force_ro` (root).
- **Confirmed LK reads boot1**: changing `serial` changed `ro.boot.serialno` on next boot.
  But LK **truncates serial to 16 bytes** and ignored `fos_flags=0x80`, `dev_flags=0xff`,
  all-ones, etc. — verity/selinux/`prod` unchanged. So cmdline injection via serial fails.

### Android-side consumers of the IDME flags
- `/init.fosflags.sh` (service `fosflags`, `u:r:fosflags:s0`): `FOS_FLAGS_ADB_ON=0x1`,
  `CONSOLE_ON=0x4`, `RAMDUMP_ON=0x8`, `VERBOSITY_ON=0x10`, `ADB_AUTH_DISABLE=0x20`,
  `BOOT_DEXOPT=0x100`. Verified: setting flags takes effect (`sys.usb=adb`, `noadbauth=1`).
- **adbd** (unstripped ARM ET_EXEC; `.text` VA 0x8160 / file 0x160; fileoff = VA-0x8000):
  - `amzn_is_root_allowed` @0x2d5b8 = `amzn_is_dev_unlocked() && (fos_flags & 0x2)`
  - `amzn_is_adb_auth_disable_allowed` @0x2d5e8 = `fos_flags & 0x20` (ungated)
  - `amzn_is_dev_unlocked` @0x2d5fc = `/proc/cmdline` contains `androidboot.prod=0` **or**
    `androidboot.unlocked_kernel=true`
  - `fos_read_debug_flags` @0x2d724 reads `/proc/idme/<name>` and parses **hex**
  - `restart_root_service` @0xcb74 / `restart_unroot_service` @0xcc64
  - strings: `amzn_fos: ADB: Auto-root succeeded`, `… eng_device=%d`, `… unlocked_kernel=%d`,
    `adbd cannot run as root in production builds`, `ro.debuggable`
  - `adb root` → "cannot run as root in production builds" (`ro.debuggable=0`) — so even with the
    auto-root gate satisfied, the AOSP prod check gates the command path.

### Why Session-10 root doesn't persist
- SELinux permissive + cell hijack + root are runtime-only.
- `/data/metrics` is a **vpartition**: `/system/bin/vpartition.sh` mounts `/data/vp/metrics.img`
  (ext4, non-nosuid/noexec) at `/data/metrics` on every boot; `su` written there does **not**
  survive reboot. (Also why setuid `su` gave uid 0 but **zero caps**.)

### Track A (boot-time re-exploit) — blocked
- No init `.rc` trigger executes controllable code (imports all verified; `persist.*` triggers only
  `start` fixed services; scripts in `/system`/`/vendor`).
- Root services read `/data` configs but never exec from them (`perfmonitord`, `amazonfiled`,
  `vpartition.sh`, `kisd`, …).
- Only boot executor = an **app**, but the exploit's paused footprint is **VmRSS 534 MB**
  (`kbm` spray) → lmkd kills it; plus a lost reclaim panics (`PANIC_ON_OOPS`) → bootloop.
- **adbd auto-root** exists but is gated on the LK-built cmdline (`prod=0`/`unlocked_kernel=true`).

### Conclusion / next target (chosen: Track B RE)
Everything hinges on making LK report `eng`/`unlocked`. In reach:
`androidboot.prod=1|0` and `androidboot.unlocked_kernel=false` are set by LK. Reverse LK to find:
1. where it reads `fos_flags`/`dev_flags`/`usr_flags` (the `K*` items) and the exact gate;
2. the `prod`/`unlocked` determination (IDME item? buildvariant? `amzn_verify_unlock` result?);
3. `amzn_verify_unlock` (libtomcrypt RSA verify) for a bypass or a weak unlock_code/version path;
4. the `seccfg`/`para`/`ENV_v1`(LK_ENV) storage (not in any dumped partition — maybe tee-protected);
5. preloader (`boot0`, `EMMC_BOOT`) for a bug.
If any of these lets us set eng/unlocked (persistently, via boot1 or a raw partition write), then
`FOS_FLAGS_DM_VERITY_OFF` disables system(root) verity and `/system` can be patched persistently.

### Artifacts (from this session)
`/tmp/opencode/mustang-dumps/` (may be cleared on host reboot): `lk.img`, `boot1.img` (pristine),
`boot.img`, `MISC.img`, `metadata*.img`, `pmt.img`, `mbr.img`, `kb.img`, `dkb.img`, `reserved.img`,
`cache.img`, `boot0.img`, `boot1.img`, `adbd.bin`, `perfmonitord.bin`, `amazonfiled.bin`.
Helpers: `tools/findinitnet.py`, `findgadget*.py`, `findstores.py`, `adbd_sym.py` (in /tmp);
repo has `run.sh`, `poc/stage3.c` (`selroot`), `poc/su.c`, `rootcmd.sh`.

### Handy commands
```
# IDME read
/data/metrics/su sh -p -c 'for f in fos_flags dev_flags usr_flags serial region device_type_id unlock_version; do echo -n "$f="; cat /proc/idme/$f; echo; done'
# write boot1 (root; su lives only until reboot -> re-run run.sh first)
/data/metrics/su sh -p -c 'echo 0 > /sys/block/mmcblk0boot1/force_ro; dd if=/data/local/tmp/boot1.img of=/dev/block/mmcblk0boot1 bs=4096 count=4; sync; echo 1 > /sys/block/mmcblk0boot1/force_ro'
# dump a partition to host
adb exec-out '/data/metrics/su dd if=/dev/block/by-name/lk bs=4096 2>/dev/null' > lk.img
```

## SESSION 12 — LK RE: the eng/unlocked gate is real, and unsigned flag stores do not exist

Goal: get LK to treat the device as `eng`/`unlocked`, or find a preloader/LK bug,
so verity/SELinux can be disabled persistently.  Result: **reversed the relevant
LK code path end-to-end; the flip is not reachable by the available stores.**
No device was bricked; the one boot1 experiment was reverted to pristine.

### LK is Thumb-2 PIC, relocated to base 0xFF400000
`lk.img` begins with a tiny ARM stub (file 0x200).  The relocator at 0x224
copies from `0x200` to a literal destination and branches to a literal entry:

| literal (file off) | value        | meaning                       |
|--------------------|--------------|-------------------------------|
| 0x270              | `0xFF4002F8` | `str r4,[r6]` scratch         |
| 0x274              | `0xFF40027C` | destination (base+0x27C)      |
| 0x278              | `0xFF54A440` | copy end (incl. BSS)          |
| 0x27C              | `0xFF400484` | entry point                   |

So **runtime address = 0xFF400000 + file offset** for offsets >= 0x200.
Everything after the stub is Thumb-2, position-independent.  Strings are built
with `ldr rT,[pc,#imm]` (T1 offset = imm8*4; `ldr.w` offset = imm12) followed by
`add rT, pc`; the target is `(add+4) + *pool`.  A robust scanner that survives
the ARM stub and literal pools was added as `tools/lk_xref.py` (handles 16- and
32-bit forms, scans every 2 bytes).  All offsets below are **file offsets**;
add 0xFF400000 for runtime addresses.

### Decoded control flow (offset -> meaning)
| offset | function |
|--------|----------|
| `0xdf7c` | `is_secure_or_prod()` -> `byte[ [[g]+0 ] + 0x163 ]`; `g` = global @0x52838. 1 on this unit. |
| `0x20b4` | `verify_stored_unlock()` = memset(buf,0,0x100); read IDME/env `unlock_code` (0x100) via `0x57c`; `bl 0x222c`; return `(verify==0)`. |
| `0x222c` / `0x20f0` | `amzn_verify_unlock(code,len)` — libtomcrypt RSA/PKCS#1 verify (see below). |
| `0xda3e` | `is_unlocked()` = `is_secure_or_prod() && verify_stored_unlock()`. |
| `0x29a28` | `is_verity_disabled()` = `(fos_flags & 0x80) && !(is_secure_or_prod() && verify_stored_unlock())`; cached in global @0x50c74. |
| `0x29974` | SELinux cmdline builder: `dev_flags & 0x20` -> `androidboot.selinux=enforce`, `dev_flags & 0x40` -> `...=permissive` (each gated by `byte[+0x162]`). |
| `0x118xx`/`0x11bxx` | kernel cmdline builder (`unlocked_kernel`, `prod=1/0`, `verifiedbootstate`, `rpmb_state`, `secure_cpu`, versions, `root=`). |
| `0x27af8` | UART gate: `fos_flags & 0x4` -> `printk.disable_uart=0`, else `=1`. |
| `0x12fd4` | **LK env loader**: partition `"para"`, 0x4000 bytes, magic `ENV_v1`, checksum = sum of bytes over 0x3ffc compared to word @0x3ffc. |
| `0x1efd0` | partition lookup by name (used for `"para"`, `"boot"`, ...). |
| `0x57c` | getter dispatcher through callback slot @0x58218; slots @0x58200..0x5821c are registered from a table at 0x5a8-0x734. |
| `0x2a19c` | `fastboot oem unlock`: `bl 0x222c(code,len)`; on success writes `unlock_code` (0x100) via `0x408`. |

### The unlock code is Amazon-RSA-signed — not forgeable
`0x20b4` reads the `unlock_code` IDME item (0x400 bytes, **all zero** on this
unit) and runs `amzn_verify_unlock` (0x222c -> 0x20f0).  That function drives
libtomcrypt (dozens of `/features/libtomcrypt/src/pk/asn1/der/...` paths and
RSA verify), and the image embeds the certificate material:
`Sunnyvale` / `Amazon Lab126` / `"$Common Kernel Signing Engineering CA0"` at
0x317d9+, plus the diagnostics
`Image FAILED AUTHENTICATION on PRODUCTION device` (0x3166e),
`Authentication failed on engineering device with production certificate` (0x316a0),
`Image FAILED AUTHENTICATION on ENGINEERING device` (0x31703),
`Image AUTHENTICATED with PRODUCTION certificate` (0x31736).
There is no empty-code / length / version shortcut: `verify(zeros) != 0`, hence
`unlocked_kernel=false` (confirmed in `/proc/cmdline`).  Flipping
`androidboot.unlocked_kernel` or `androidboot.prod` requires either a valid
Amazon-signed `unlock_code` (private key unavailable) or a code-execution bug in
the verifier.  Nothing exploitable (bounds/size) was found statically in
0x20b4/0x222c/0x20f0.  => **the eng/unlocked flip via the documented path is
cryptographically infeasible.**

### The verity/SELinux flags do not come from a store that exists
The security flags are read through the getter at `0x57c`.  Empirical test:

```
# boot1 IDME item fos_flags data (offset 0x22B4, 8 bytes) set to "00000080"
dd if=/dev/block/mmcblk0boot1 ... ; reboot
/proc/idme/fos_flags  -> 00000080        (persisted, Android sees it)
ro.boot.veritymode    -> eio             (unchanged!)
root=/dev/dm-0 dm="system none ro,0 1 android-verity PARTUUID=..."  (unchanged)
androidboot.prod=1 / secure_cpu=1 / buildvariant=user  (unchanged)
```
`fos_flags=0x80` is `FOS_FLAGS_DM_VERITY_OFF`; the decoded gate would have turned
verity off **if** the getter had returned it.  It did not.  Therefore the getter
(at least at verity-protection time) is **not** reading the boot1 IDME items.

The other candidate store is the **LK env**, loaded from a partition literally
named `"para"` (loader 0x12fd4, magic `ENV_v1`, checksum @0x3ffc).  LK's own
partition table (0x4fcc0..0x50340) lists preloader/proinfo/nvram/protect1/
protect2/persist/seccfg/secro/**para**/logo/custom/expdb/tee1/tee2/metadata/
system/cache/userdata — but the tablet's actual GPT has **only 16 entries**, all
type `af3dc60f838472478e793d69d8477de4`:

```
#0 proinfo 0x400   #1 PMT 0x1c00    #2 kb 0x4000     #3 dkb 0x4800
#4 lk 0x5000       #5 tee1 0x5800   #6 tee2 0x8000   #7 metadata 0xa800
#8 MISC 0x1e400   #9 reserved 0x1e800  #10 boot 0x22800  #11 recovery 0x2a800
#12 system 0x34800 #13 vendor 0x644000 #14 cache 0x6b4800 #15 userdata 0x7ae800
```
There is **no `para`, `seccfg`, `nvram`, `protect`, or `persist` partition** on
this product (and `PMT`/`pmt.img` dumps are all-zero).  So the LK env is empty,
the `Kfos_flags`/`Kdev_flags` keys never exist, and all `fos_flags`/`dev_flags`
checks resolve to 0 — independently of what the IDME items contain.  The boot1
IDME items are consumed by Android (`/init.fosflags.sh`, `adbd`,
`/proc/idme/*`) but not by LK's security gates.

### Conclusion — why persistent eng/unlock is blocked
1. `unlocked_kernel` requires an Amazon-signed `unlock_code` (RSA/libtomcrypt,
   embedded CA).  Not forgeable offline; no verifier bug found.  **Hard block.**
2. The `DM_VERITY_OFF` / `selinux=permissive` flags are consumed from the LK env
   (`para`/`ENV_v1`), which does not exist on this GPT.  IDME `fos_flags` is
   empirically ignored by LK (0x80 persisted, verity stayed `eio`).  **Hard
   block** unless the partition table is modified.
3. Even a successful `fos_flags=0x80` would only set `androidboot.veritymode=
   disabled` and a non-`dm-0` `root=`; it would not unlock, and SELinux would
   still need `dev_flags` from the same absent env to go permissive.
4. Track A (boot-time re-exploit) therefore remains blocked exactly as in
   SESSION 11: its only unlock path is the same LK gate.

### Remaining avenues (future, higher risk; not attempted)
- **Synthesize a `para`/`ENV_v1` store**: add a GPT entry named `para` (primary
  + backup GPT must both be updated) in the free space after `userdata`
  (userdata ends LBA 0x3a3dfde; disk = 30535680 sectors), then craft an env with
  `fos_flags=0x80` and `dev_flags=0x40` (checksum at +0x3ffc = byte sum over
  0x3ffc).  This is the only remaining route to verity-off.  Risks: corrupting
  the primary/backup GPT can brick; and it was **not proven** that the verity
  gate actually reads `para` (only that it is not boot1 IDME).
- **Preloader (`boot0`/`EMMC_BOOT`) bug**: not reversed this session.  Writing
  boot0 is forbidden until a pristine copy and a recovery path exist.
- **Verifier research**: the engineering-certificate path (0x316a0/0x31703) is
  only reachable with a device identity accepted as "engineering" plus a code
  signed by the engineering key; no private key is available.

### Artifacts / reproducibility
- Tool added: `tools/lk_xref.py` — base-independent LK string-xref resolver.
- Dumps used: `/tmp/opencode/mustang-dumps/lk.img`, `boot1.img` (pristine),
  `boot0.img`, `mbr.img` (GPT), `pmt.img` (all-zero).
- boot1 experiment image (fos_flags=0x80) kept at
  `/tmp/opencode/s12/boot1_f80.img`; **device restored to pristine boot1**
  (verified `/proc/idme/fos_flags` -> `0`).

### Handy commands (root required; re-arm with `./run.sh`)
```
# re-arm runtime root (~1/3 per boot)
./run.sh --no-build

# confirm LK's decisions without a UART
/data/metrics/su /system/bin/sh -p -c 'cat /proc/cmdline'
#   watch: root=/dev/dm-0 dm="system ... android-verity ..."  (verity on)
#          androidboot.veritymode=eio ; androidboot.selinux=enforce ; prod=1

# IDME read (Android copy; NOT what LK's gates use)
for f in fos_flags dev_flags usr_flags unlock_version serial; do cat /proc/idme/$f; echo; done
```
