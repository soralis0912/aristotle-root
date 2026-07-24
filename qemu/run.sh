#!/bin/bash
# QEMU harness for the aristotle (XIG04) 5.10.136 kernel.
# Boots the real device kernel deterministically (no phone, no reboots) and
# exposes a gdb stub for offset/logic verification.
#
#   ./run.sh boot   # boot to userspace and exit (smoke test)
#   ./run.sh gdb    # boot in background with gdbstub :1234, run verify.gdb
#   ./run.sh shell  # boot and leave QEMU running with gdbstub (Ctrl-a x to quit)
#
# Needs: qemu-system-arm, gdb-multiarch, clang, cpio, and the device boot.img.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
BOOTIMG="${BOOTIMG:-$HERE/../../../../aristotle/aristotle_XIG04_images_V14.0.3.0.TMFJPKD/images/boot.img}"
OUT="$HERE/build"; mkdir -p "$OUT"

# 1) extract + gunzip the kernel Image from the Android boot.img (v3/v4)
if [ ! -f "$OUT/Image" ]; then
  python3 - "$BOOTIMG" "$OUT/kernel.gz" <<'PY'
import sys,struct
d=open(sys.argv[1],'rb').read(); ks=struct.unpack_from('<I',d,8)[0]
open(sys.argv[2],'wb').write(d[4096:4096+ks])
PY
  gzip -dc "$OUT/kernel.gz" > "$OUT/Image"
fi

# 2) build the freestanding static /init and a newc initramfs
clang --target=aarch64-linux-gnu -ffreestanding -nostdlib -static -Wl,-e,_start \
  -o "$OUT/init" "$HERE/init.c"
rm -rf "$OUT/root" && mkdir -p "$OUT/root" && cp "$OUT/init" "$OUT/root/init"
( cd "$OUT/root" && find . -print0 | cpio --null -o --format=newc 2>/dev/null ) > "$OUT/initramfs.cpio"

QEMU=(qemu-system-aarch64 -M virt -cpu cortex-a72 -smp 2 -m 2048
  -kernel "$OUT/Image" -initrd "$OUT/initramfs.cpio"
  -append "console=ttyAMA0 nokaslr rdinit=/init panic=-1" -nographic -no-reboot)

case "${1:-boot}" in
  boot)  timeout 60 "${QEMU[@]}" ;;
  gdb)   "${QEMU[@]}" -s >"$OUT/qemu.log" 2>&1 & QPID=$!
         until grep -q "userspace reached" "$OUT/qemu.log" 2>/dev/null; do sleep 1; done
         gdb-multiarch -q -batch -x "$HERE/verify.gdb"
         kill $QPID 2>/dev/null ;;
  shell) "${QEMU[@]}" -s ;;
  *) echo "usage: $0 {boot|gdb|shell}"; exit 1 ;;
esac
