#!/bin/bash
set -e
SP="$(cd "$(dirname "$0")" && pwd)"
IMG="$SP/../build/Image"
OUT="${TMPDIR:-/tmp}/aristotle_e2e"; mkdir -p "$OUT/root"
clang --target=aarch64-linux-gnu -ffreestanding -nostdlib -static -Wl,-e,_start \
  -o "$OUT/root/init" "$SP/init_e2e.c"
( cd "$OUT/root" && find . -print0 | cpio --null -o --format=newc 2>/dev/null ) > "$OUT/initramfs.cpio"
QEMU=(qemu-system-aarch64 -M virt -cpu cortex-a72 -smp 4 -m 2048
  -kernel "$IMG" -initrd "$OUT/initramfs.cpio"
  -append "console=ttyAMA0 nokaslr rdinit=/init panic=-1" -nographic -no-reboot)
"${QEMU[@]}" -s >"$OUT/qemu.log" 2>&1 &
QPID=$!
trap 'kill $QPID 2>/dev/null' EXIT
for i in $(seq 1 60); do grep -q "userspace reached" "$OUT/qemu.log" 2>/dev/null && break; sleep 0.5; done
timeout 45 gdb-multiarch -q -batch -x "$SP/e2e.gdb" > "$OUT/gdb.log" 2>&1 || true
echo "--- gdb head ---"; grep -E "^(SCRATCH_PRE|PIB)" "$OUT/gdb.log" | head -4
echo "--- gdb tail ---"; grep -E "^(SCRATCH_PRE|PIB)" "$OUT/gdb.log" | tail -3
echo "PIB count: $(grep -c '^PIB' "$OUT/gdb.log" || true)"
grep -E "Error|Cannot" "$OUT/gdb.log" | head -3 || true
echo "--- guest output ---"
grep -E "E2E3|BOOTID|WAITER|REQUEUE|PSELECT|CONSUMER|mount|Oops|panic|BUG|Call trace" "$OUT/qemu.log"
kill $QPID 2>/dev/null || true
