# QEMU end-to-end control experiment (CVE-2026-43499 on the real aristotle kernel)

`./run.sh` boots the **device kernel** (`../build/Image`, extracted from the
firmware boot.img) on QEMU virt with a freestanding init that reproduces the
whole exploit sequence and proves — with no phone involved — that the bug's
write primitive works:

* waiter thread: `FUTEX_LOCK_PI`(chain) → `FUTEX_WAIT_REQUEUE_PI` → ETIMEDOUT
* owner thread: holds the uaddr2 PI mutex, then blocks on the chain mutex
  (this is what makes `CMP_REQUEUE_PI` return EDEADLK)
* main: `FUTEX_CMP_REQUEUE_PI` → EDEADLK → **dangling `task->pi_blocked_on`**
* waiter: grows the fdtable (so `core_sys_select` does not clamp `n`), installs a
  5.10 flat `rt_mutex_waiter` overlay in the `pselect(nfds=320)` fdsets, dup2s a
  never-ready timerfd onto every set bit (else `max_select_fd()` → `-EBADF`), and
  blocks in one long `pselect`
* consumer: `sched_setattr` on the waiter tid, **alternating the fair policy** so
  `__sched_setscheduler` always reaches `change:` and really calls
  `rt_mutex_adjust_pi()` (identical policy+nice returns 0 without walking)
* proof: the rb-erase store is aimed at `&sysctl_bootid`, and the init mounts
  /proc and prints `/proc/sys/kernel/random/boot_id` before and after

## Result (2026-07-25, kernel 5.10.136-android12-9)

```
PIB pid=126 pib=0xffffffc012cdbc30      <- dangling task->pi_blocked_on
SFD stack_fds=0xffffffc012cdbc30        <- pselect fdset of the same thread
BOOTID_BEFORE=1e84ead7-fa40-4436-94b2-a027d905e12d
BOOTID_AFTER =00019f12-c0ff-ffff-94b2-a027d905e12d
```

`00 01 9f 12 c0 ff ff ff` = little-endian `0xffffffc0129f0100`, the planted
`write_value`. So on this exact kernel:

1. the dangling `pi_blocked_on` **survives the clean ETIMEDOUT** (no signal
   needed — `handle_early_requeue_pi_wakeup` returns non-zero and
   `futex_wait_requeue_pi` `goto out`s past the cleanup),
2. it points **exactly** at the `pselect` fdset base (so `fops.c`'s
   `PSELECT_WAITER_WORD_SHIFT = -2`, which lands fake-waiter word0 on fdset
   word 0, is correct),
3. the 5.10 flat word table is correct, and
4. `rt_mutex_adjust_prio_chain` → `rt_mutex_dequeue` → `rb_erase` really performs
   the arbitrary 8-byte store, and the process survives.

The overlay is fully static: the fake `rt_mutex` is a zeroed .bss scratch
(`KBASE+0x29f0000`, deep inside the 192 KiB hole after `lt_pinner`, untouched on
QEMU virt), so no leaked kernel address is needed.

## Failure modes this harness reproduces (useful when debugging the device)

* walk firing **outside** the `pselect` window → it reads the stack the syscall
  return path has already clobbered (`waiter->lock == 0` → NULL-deref Oops, or a
  silent early return). This is why the device build keeps the window long and
  fires many walks inside it.
* `n` clamped by `max_fds` (few open fds) → the kernel lays the 6 fdsets out with
  1 long each instead of 5 → the overlay words land in the wrong places.
* any set bit naming a closed fd → `max_select_fd()` → `pselect` returns
  `-EBADF` immediately, so no window at all.

Requirements: `qemu-system-aarch64`, `gdb-multiarch`, `clang`, `cpio`.
