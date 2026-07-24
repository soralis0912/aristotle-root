# 5.10 slide overlay — findings from oppo-ghostlock (working 5.10 reference)

Ref: https://github.com/pubglite55/oppo-ghostlock — OPPO Find N2, **kernel
5.10.236-android12-9**, CVE-2026-43499, su_daemon (ghostlock lineage = same as
aristotle). Its slide leak works. Full target.h saved as
`REF_oppo-ghostlock_target.h`.

## Confirmed
- **The overlay is the NESTED 13-word table** (tree_pc@0, tree_left@2,
  tree_prio@3, pi0@5, pi2@7, task@10, lock@11, wake_state@12, ww_ctx@13) — the
  SAME as duchamp. **The flat 10-word remap in the old popsicle-derived fork
  (CVE-2026-43499-aristotle) was the bug.** aristotle-root already ships the
  nested table (duchamp slide.c), so the overlay itself is correct.
- oppo uses the **consumer** trigger + **fixed** PSELECT_WAITER_WORD_SHIFT 0 (no
  SIGALRM, no shift sweep). duchamp/aristotle-root add SIGALRM + sweep; both are
  supersets, shift 0 is covered.
- read_stext is identical: `off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  stext = leaked - off`.

## Fixed in aristotle target.h
- **Anchor equality**: oppo sets `SLIDE_NFULNL_LOGGER == SLIDE_LOGGERS_0_1`
  (same address). aristotle had them different (nfulnl 0x2771450 vs
  loggers[0][1] 0x2771380). Since the overlay writes SLIDE_LOGGERS_0_1 and
  read_stext subtracts off(SLIDE_NFULNL_LOGGER), they MUST match → set both to
  0x2771380 (&loggers[0][1]).

## OPEN — prime suspect: physical load DELTA
- oppo: `P0_PHYS_OFFSET 0x80000000`, `P0_KERNEL_PHYS_LOAD 0xa8000000` →
  **DELTA = 0x28000000, "XBL firmware verified"**. i.e. the kernel is NOT loaded
  at memstart; delta is device-specific and must be verified from the bootloader.
- aristotle: currently `P0_KERNEL_PHYS_LOAD 0x40000000` (delta 0), an ASSUMPTION
  (duchamp "all targets delta0"). The ORIGINAL aristotle value was 0x40080000
  (delta 0x80000, MTK-typical); a prior session "fixed" it to 0 — **possibly a
  regression**. The linear-map aliases P0_DATA_ALIAS_CONST() depend on delta; a
  wrong delta sends the rb write to the wrong physical page → boot_id never
  changes (exactly the observed on-device symptom).
- ACTION: determine aristotle's real kernel physical load address (vendor_boot
  DTB /memory + LK/preloader load addr, or read runtime memstart_addr via the
  exploit), then set P0_KERNEL_PHYS_LOAD accordingly.

## Recommendation
oppo-ghostlock (5.10.236, ghostlock lineage, working leak, su_daemon) is a much
closer base for aristotle (5.10.136) than duchamp-root (6.1) — its slide.c,
fops.c and root.c are already 5.10-correct (e.g. WAKE_STATE/WW_CTX = -1 handling,
5.10 flat waiter). Consider re-basing aristotle on oppo-ghostlock and swapping in
the measured aristotle target.h, rather than back-porting duchamp (6.1) code.
