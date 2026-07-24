# QEMU harness — aristotle (XIG04) 5.10.136

Boots the **real device kernel** (extracted from the firmware `boot.img`) in
QEMU `virt`, deterministically and without a phone — so offsets and exploit
logic can be verified with gdb instead of on-device (which reboots on any slip).

## Requirements
`sudo apt-get install -y qemu-system-arm gdb-multiarch` (+ clang, cpio, python3).

## Use
```
./run.sh boot   # smoke test: boots to userspace, prints marker, powers off
./run.sh gdb    # boots headless w/ gdbstub :1234 and runs verify.gdb
./run.sh shell  # boots and stays up with gdbstub :1234 (Ctrl-a x to quit)
```
The kernel Image is regenerated from `boot.img` into `build/` (gitignored).
`init.c` is a tiny freestanding static aarch64 init (raw syscalls, no libc/NDK).

## What it confirmed (2026-07-24)
- The aristotle 5.10.136 kernel **boots on QEMU virt (cortex-a72, PL011 console)**
  and reaches userspace.
- gdb (nokaslr, base 0xffffffc010000000) verified against the live kernel:
  - `task_struct` real_cred=0x778, cred=0x780 (→ init_cred), task_group=0x310,
    usage=0x40, prio=0x84, pi_blocked_on=0x898 — all correct.
  - **`TASK_COMM_OFF` corrected 0x830 → 0x790** ("swapper/0" @ init_task+0x790).
  - selinux_state @ RVA 0x2a25b90 reads a valid enforcing field.

## Caveats
- QEMU's physical layout is ours, so this does NOT reveal the device's real
  kernel physical-load DELTA. It validates offsets + leak/UAF *logic* given a
  known delta; it cannot confirm the on-device P0_KERNEL_PHYS_LOAD.
- Futex-PI is a timing race; TCG timing != hardware. Use gdb to force/observe
  the UAF rather than relying on the race to fire naturally.
