# rt_mutex_adjust_prio_chain walk trace — aristotle 5.10.136 (CVE-2026-43499 pselect overlay)

Static disasm of the real device kernel (`qemu/build/Image`, file-offset==RVA, VA base
`0xffffffc010000000`). Goal: find the first faulting instruction of the fake-waiter chain
walk and the minimal fix. Trigger: consumer `sched_setattr(waiter_tid)` →
`rt_mutex_adjust_pi(task)` → `rt_mutex_adjust_prio_chain(task, MIN_CHAINWALK=0, orig_lock=NULL,
next_lock=fake_lock, orig_waiter=NULL, top_task=task)`.

Registers in `rt_mutex_adjust_prio_chain` (0x1e78bc): `x19=task` (real waiter thread),
`x28=waiter=task->pi_blocked_on` (@0x898), `x27=lock=waiter->lock` (@0x38), `x20`=preempt-count
ptr, `x25=&task->pi_lock` (task+0x86c).

## (a) The dequeue WRITE is SAFE and correct — CONFIRMED
- 0x1e7d34–0x1e7d84: leftmost/rb_next bookkeeping, then **`bl 0xa82150` = `rb_erase(&waiter->tree_entry, &lock->waiters.rb_root)`**.
- fake `tree_entry` = {`__rb_parent_color`=fake_fops, `rb_right`(+8)=0, `rb_left`(+16)=target=&ashmem_misc_fops}.
- `rb_erase`→`__rb_erase_augmented`: `child=rb_right=0`, `tmp=rb_left=target`. Hits the **"has left child, no right child"** branch:
  `tmp->__rb_parent_color = node->__rb_parent_color` ⇒ **`*ashmem_misc_fops = fake_fops`** (the intended fops swap),
  `__rb_change_child(node,tmp,parent=fake_fops,root)` touches only the fake_fops page, `rebalance=NULL`.
- **No `__rb_erase_color` (0xa82728), no rotation.** The overlay rb-shape is correct; the write is a clean single write into our page + target. `PSELECT_WAITER_WORD_SHIFT`/rb-shape are NOT the problem.

## (b)/(c) The owner-boost path does NOT fault — CORRECTS the prior hypothesis
After the write: `waiter_update_prio` (waiter->prio=task->prio @0x1e7da4, waiter->deadline=task->dl.deadline @0x1e7dac), `rt_mutex_enqueue` (`bl 0xa81f80` rb_insert_color @0x1e7e38), release task->pi_lock.

Owner decision at **0x1e8234–0x1e8250**:
```
1e8234 add  x8, x27, #0x18      ; &lock->owner
1e8238 ldar x9, [x8]            ; owner = fake_task|1
1e823c cmp  x9, #1
1e8240 b.ls 0x1e8ca0            ; owner<=1 -> clean "no owner" exit
1e8248 and  x19, x8, #~1        ; x19 = owner&~1 = fake_task  (boost target)
```
With `owner=fake_task|1` it takes the boost path: get_task_struct(fake_task), lock fake_task->pi_lock, dequeue_pi/enqueue_pi on fake_task->pi_waiters (writes `*target=fake_fops` again — harmless), then the lone **`bl 0x19ff4c` = `rt_mutex_setprio(fake_task, pi_task)` at 0x1e898c**.

Call-site: `pi_task = task_top_pi_waiter(fake_task)->task` = `*(leftmost+0x18)` = **waiter->task = INIT_TASK** (0x1e8980-0x1e8984). **Not NULL.**

`rt_mutex_setprio` (0x19ff4c): `w25 = __rt_effective_prio` = min(fake_task->normal_prio=120, INIT_TASK->prio=120) = 120.
```
19ff94 ldr  x8,[x20,#2192]      ; fake_task->pi_top_task (0x890) = INIT_TASK
19ff98 cmp  x8, x21            ; == pi_task(INIT_TASK) ?
19ff9c b.eq 0x1a0244           ; EQUAL -> early-exit branch
1a0248 ldr  w8,[x20,#132]       ; fake_task->prio (0x84) = 120
1a024c cmp  w25, w8            ; 120 == 120
1a0250 b.eq 0x1a0478           ; -> clean epilogue (ldp.../ret), NO __task_rq_lock, NO sched_class
```
So **`rt_mutex_setprio` early-returns cleanly** (`p->pi_top_task==pi_task && prio==p->prio && !dl_prio`).
The prior hypothesis (pi_task=NULL ⇒ setprio derefs rq/sched_class ⇒ Oops) is **WRONG**: pi_task is
INIT_TASK (waiter->task), which matches fake_task->pi_top_task=INIT_TASK, and prio==fake_task->prio.
After setprio, next chain = fake_task->pi_blocked_on(0x898)=0 ⇒ chain ends, clean exit.

The `owner<=1` path (0x1e8ca0) is also clean: computes top_waiter, optionally
`wake_up_state(top_waiter->task=INIT_TASK, 3)` (`bl 0x196b2c` @0x1e8d64 — INIT_TASK is a real task,
safe), unlocks lock->wait_lock (0x1e8d70), returns.

**Conclusion: for a CORRECTLY-PLACED fake waiter, the walk does NOT Oops on either owner value.**
Every fake-structure field the walk dereferences (waiter@0x38/0x40/0x48/task, fake_lock->owner/
waiters, fake_task->prio/normal_prio/pi_top_task/pi_waiters/pi_lock/pi_blocked_on/usage) matches the
payload and the verified aristotle task offsets.

## Therefore the Oops is RECLAIM/PLACEMENT, not walk logic
If `task->pi_blocked_on` (x28) is a wild/partly-controlled pointer (fake waiter not landing where
pi_blocked_on references), the FIRST deref faults — earliest at **0x1e79b0 `ldr x8,[x28,#56]`
(waiter->lock)** or **0x1e7a44 `ldar w8,[x27]` (lock->wait_lock)** once x27=waiter->lock is wild.

### (e) KEY DISCOVERY — the pselect fdset is HEAP, not stack
`PSELECT_ROUTE_NFDS=640` ⇒ `core_sys_select` FDS_BYTES=80/set, 6 sets = 480 B > stack_fds(256)/6
⇒ the fake-waiter words are copied into a **kmalloc-512** buffer, **not the thread stack**. So the
"pselect fdset overwrites the freed stack `rt_mutex_waiter`" model cannot hold (a heap fdset can't
alias a stack object; also sizeof(rt_mutex_waiter)≈0x50 ⇒ kmalloc-128, a different slab than
kmalloc-512). The reclaim topology must be heap-based and the freed object / its size class must be
reconciled. This mismatch is the prime suspect for the Oops and must be resolved with the on-device
ckpt log (which attempt/shift) plus the futex-requeue allocation + heap-grooming analysis
(pipe.c/heap_spray.c/futex path) — out of scope of the pure walk disasm.

## Recommendations (for the parent to apply, not applied here)
1. **owner=NULL robustness (cheap, low-risk, NOT the root cause):** set `fake_lock->owner=NULL`
   (util.c prepare_skb_payload, FOPS branch currently writes `LOCK_OFF+0x18 = fake_task|1`). This
   makes the walk exit at 0x1e8ca0 right after the write, deleting ~200 instructions of fragile
   fake-owner/enqueue_pi/setprio traversal. Static trace shows this exit is clean. Do this to shrink
   the attack surface, but do not expect it to stop the reboot by itself.
2. **Root-cause the reclaim (the real fix):** get the device ckpt log to learn which `pselect
   attempt=N` (and thus timing) faults, and reconcile the freed-object size class with the
   kmalloc-512 fdset. Likely levers: `PSELECT_ROUTE_NFDS` (to change the fdset slab / place the fake
   waiter at the freed object's offset), the grooming order, and `PSELECT_WAITER_WORD_SHIFT` (byte
   offset of the fake waiter within the 512-B buffer to align with the freed object).
3. If the ckpt log shows the fault is BEFORE `pselect attempt=1 arming` (i.e., in
   CMP_REQUEUE_PI/WAIT_REQUEUE_PI), the dangling-waiter creation itself is faulting — a different
   problem than the walk.

## RVA index
rt_mutex_adjust_prio_chain 0x1e78bc; dequeue rb_erase call 0x1e7d84; enqueue rb_insert_color 0x1e7e38;
owner branch 0x1e8240; owner<=1 clean exit 0x1e8ca0; setprio call 0x1e898c; rt_mutex_setprio 0x19ff4c;
setprio early-exit test 0x1a0244→ret 0x1a0478; rb_erase 0xa82150; __rb_erase_color 0xa82728;
rb_insert_color 0xa81f80.

## Reclaim alignment / WORD_SHIFT (device log: nfds=320, on-stack, walk faults @attempt1 shift0)

Device confirmed the walk analysis: `CMP_REQUEUE_PI errno=35(EDEADLK)`, `WAIT_REQUEUE_PI
errno=110(ETIMEDOUT)` **still leaves `task->pi_blocked_on` dangling** (the walk ran → Oops during
pselect). With nfds=320 the pselect fdset is on the kernel stack (`words_per_set=5`, 6·40=240 B ≤
stack_fds[256]), so it can alias the freed `rt_waiter`. The fault is pure MIS-ALIGNMENT.

### Same-thread VMAP_STACK reuse — frame summing
Both syscalls enter at the identical divergence sp (`SP_DIV`, the indirect call in invoke_syscall;
`__arm64_sys_futex(regs)` and `__arm64_sys_pselect6(regs)` are both called there). `bl` doesn't move
sp and the intermediate helpers are inlined (no `do_pselect6`/`__se_sys_*` symbols, no extra frames),
so only prologue `sub sp,sp,#N` count. Object addresses are taken from the `add xN,sp,#imm` that
feeds the callee that consumes them.

FUTEX path (rt_waiter):
- `__arm64_sys_futex` 0x297068: `sub sp,#0x90`; `bl do_futex` @0x297114.
- `do_futex` 0x28d7d4: `sub sp,#0x70`; `bl futex_wait_requeue_pi` @0x28d888.
- `futex_wait_requeue_pi` 0x292110: `sub sp,#0x1a0`. rt_waiter @ **sp+0x90** — proven twice:
  `rt_mutex_wait_proxy_lock`(0x1e9b24) arg x2 = `add x2,sp,#0x90` @0x2923bc; and
  `rt_mutex_cleanup_proxy_lock`(0x1e9cd8) arg x1 = `add x1,sp,#0x90` @0x292410.
- rt_waiter_addr = SP_DIV − (0x90+0x70+0x1a0) + 0x90 = SP_DIV − **0x210**.

PSELECT path (stack_fds):
- `__arm64_sys_pselect6` 0x572410: `sub sp,#0xa0`; `bl core_sys_select` @0x5725b8 (do_pselect6 inlined).
- `core_sys_select` 0x570edc: `sub sp,#0x1c0`. small-nfds branch → `add x23,sp,#0x50` @0x571070 =
  `bits=&stack_fds`; confirmed by `fds.in/out/ex/res_* = x23 + k·size` (@0x57107c..0x5710a8) and
  `fds` struct stored @sp+0x20, passed to `do_select`(0x5716a8) @0x5711b8.
- stack_fds_addr = SP_DIV − (0xa0+0x1c0) + 0x50 = SP_DIV − **0x210**.

### Result
`rt_waiter_addr == stack_fds_addr == SP_DIV − 0x210` (exactly). The fake waiter currently starts at
`stack_fds + 0x10` (global word 2), i.e. 0x10 (two longs) ABOVE the freed rt_waiter. So the walk reads
waiter fields 0x10 high — e.g. it reads `waiter->lock` from `rt_waiter+0x48` instead of `+0x38`,
`waiter->task` from `+0x40` instead of `+0x30` — garbage → fault at 0x1e79b0/0x1e7a44.

**PSELECT_WAITER_WORD_SHIFT = −2** (move the fake-waiter base from long 2 to long 0 = stack_fds+0).
Formula: shift = (D_stackfds − D_rtw − 0x10)/8 = (0x210 − 0x210 − 0x10)/8 = −2.

Wiring note: the current `fops.c prepare_pselect_fdsets` uses FIXED word indices {2..12} and
`pselect_put_waiter_word` sets `global_word = waiter_word` — PSELECT_WAITER_WORD_SHIFT is NOT applied.
Apply it: `global_word = waiter_word + PSELECT_WAITER_WORD_SHIFT` (or hardcode indices {0..10}). All 11
words then occupy longs 0..10 (bytes 0x00..0x58) — inside the 240-byte (30-long) select buffer. OK.

### Exit-path independence (Q3)
rt_waiter is a fixed stack local (fwrp sp+0x90) regardless of timeout vs EINTR/signal exit, so the
shift is the same either way — refoot: −2. The device log proves the ETIMEDOUT(110) path already
leaves pi_blocked_on dangling AND runs the walk, so NO pthread_kill(SIGALRM) is needed. (If a signal
exit were ever used, it would NOT change rt_waiter's offset, hence not the shift.)

### Confidence / ranked candidates
Every number is from a clean single-`sub sp` prologue plus an `add xN,sp,#imm` arg-setup, so **−2 is
high confidence**. If any one frame is mis-read by a single 8-byte slot, the next candidates (test in
this order, fewest reboots): **−2**, then −1, −3, then 0/−4. Constraint: keep shift ≥ −2 so global
word 0 (tree_pc) stays ≥ 0; a more-negative shift underflows the buffer (words <0 dropped → broken
overlay, exactly the earlier `cannot place tree_pc` symptom).

## configfs R/W method (EINVAL on the fops-swap write)

Device: after shift=−2 the walk survives and the pselect route reaches try_cfi_stage; the first
`configfs_write_once` (pwrite at pos 0 on the swapped-fops ashmem fd) returns **EINVAL(22)**.

### The EINVAL is vfs_write's FMODE_CAN_WRITE gate, NOT configfs
`configfs_write_bin_file` real entry = **0x6b5208** (via `.cfi_jt` 0x182f330: `bti c; b 0x6b5208`).
Args `(file=x0, buf=x1, count=x2, ppos=x3)`, `buffer = file->private_data` (`ldr x24,[x0,#216]`
@0x6b5228). Return codes: read_in_progress(buffer+0x54)!=0 → −26 ETXTBSY (0x6b5250);
len>bin_buffer_size && cb_max_size && len>cb_max_size → −27 EFBIG (0x6b52ac); **`*ppos<0` → −22 EINVAL
(0x6b52b8 `tbnz x25,#63`→0x6b53ac)**; copy_from_user fail → −14 EFAULT. The exploit pwrites at pos 0,
so `configfs_write_bin_file` would NEVER return EINVAL if it were called. Therefore the EINVAL comes
from `vfs_write`: `if (!(f_mode & FMODE_CAN_WRITE)) return -EINVAL;`.

`FMODE_CAN_WRITE` is set at open iff `f_op->write || f_op->write_iter`. Real `ashmem_fops` (@0x229d120)
is: owner=0, llseek=0x181f2e8, **read=0, write=0, read_iter=0x1821cc8, write_iter=0** (raw dump). So an
fd opened on the REAL ashmem gets FMODE_CAN_READ but **NOT FMODE_CAN_WRITE** ⇒ pwrite → EINVAL. **The
write fd is seeing real ashmem_fops, i.e. the fops swap is not in effect on it.**

### configfs_buffer offsets — CORRECT (no change)
Both `configfs_write_bin_file` and `configfs_read_bin_file`(0x6b4f90) use `file->private_data` at
file+0xd8 and these fields, all matching the exploit's CFG_*:
`read_in_progress` 0x54, `write_in_progress` 0x55, **`needs_read_fill` 0x50** (CFG_NEEDS_READ_FILL 80),
**`bin_buffer` 0x58** (CFG_BIN_BUFFER 88), **`bin_buffer_size` 0x60**(int) (96), **`cb_max_size` 0x64**
(100). CFG_PAGE_OFF 16 is unused on the bin path (needs_read_fill=0 → simple copy from bin_buffer).

### fake_fops method bug (the real bug) + fix
`put_fake_fops_table` (util.c) and `refresh_fake_fops_text` (fops.c) currently set the WRONG slots:
`read_iter(0x20)=CONFIGFS_READ_ITER(0x6b4794)`, `write_iter(0x28)=CONFIGFS_BIN_WRITE_ITER(0x2157220)`,
`read(0x10)=write(0x18)=0`. aristotle configfs bin files dispatch via **.read/.write**
(`configfs_read_bin_file`/`configfs_write_bin_file`), and 0x2157220 is the `configfs_bin_file_operations`
DATA TABLE, not a function — if the swap ever landed, `write_iter=table` would be called and executed as
code → Oops. The genuine tables (ashmem_fops, configfs_bin_file_operations) store **`.cfi_jt`** addresses
(ashmem llseek=0x181f2e8, ioctl=0x18368e0; configfs_bin_file_operations.read=0x182ee20,
.write=0x182f330); kernel CFI checks indirect fop calls, so fake_fops MUST use the `.cfi_jt` form.

Concrete fix (address form = `.cfi_jt`):
- target.h: `#define CONFIGFS_READ_BIN_JT_OFF  0x0182ee20`  (`configfs_read_bin_file.cfi_jt`)
             `#define CONFIGFS_WRITE_BIN_JT_OFF 0x0182f330`  (`configfs_write_bin_file.cfi_jt`)
  and `#define CONFIGFS_READ_BIN_JT (KIMAGE_TEXT_BASE+CONFIGFS_READ_BIN_JT_OFF)` (same for WRITE).
  (CONFIGFS_READ_ITER_OFF/CONFIGFS_BIN_WRITE_ITER_OFF are wrong — retire or ignore them.)
- util.c `put_fake_fops_table` AND fops.c `refresh_fake_fops_text` — set:
    FOPS_READ_OFF(0x10)       = text_addr(CONFIGFS_READ_BIN_JT)    (was 0)
    FOPS_WRITE_OFF(0x18)      = text_addr(CONFIGFS_WRITE_BIN_JT)   (was 0)
    FOPS_READ_ITER_OFF(0x20)  = 0                                  (was CONFIGFS_READ_ITER)
    FOPS_WRITE_ITER_OFF(0x28) = 0                                  (was CONFIGFS_BIN_WRITE_ITER)
  This also fixes FMODE_CAN_WRITE at open (write≠0) and FMODE_CAN_READ (read≠0).
  configfs_write_once/read_once (pwrite/pread at pos 0) work unchanged: `.write(file,buf,count,ppos)`
  and `.read` are the exact vfs signatures; no wrapper change.

### Swap-landing (Q4) — the method fix is also the diagnostic
With the CURRENT build, IF the swap had landed, the post-swap open would set FMODE_CAN_WRITE (write_iter
non-NULL) and pwrite would call the data table → panic, not EINVAL. Since we get EINVAL, the swap is
**not in effect on the write fd** even though the dequeue rb_erase (0x1e7d84, Case-2) statically should
write `*ASHMEM_MISC_FOPS_alias = fake_fops`. The fd timing is fine (`try_cfi_stage` opens fresh AFTER
pselect returns). So either the walk exits before [7] with the real device's live values, or the rb
write doesn't stick (target not writable via the linear alias / MTE tag mismatch / wrong value).

Apply the method fix first — it is required regardless AND disambiguates:
- EINVAL → success/EFBIG: the swap WAS landing; the method slot was the only bug. Done.
- EINVAL persists: the swap is genuinely not landing → next, prove the write executes. Cheapest
  diagnostic: right after the pselect route, `pr_success`-log a fresh `open("/dev/ashmem",O_RDWR)` then
  attempt a 1-byte `pwrite` and log errno — EINVAL still ⇒ real fops (no swap); a non-EINVAL/crash ⇒
  fake fops present. (A kernel read-back of *ASHMEM_MISC_FOPS needs the physrw we don't have yet.)

### RVA index (configfs)
configfs_read_bin_file 0x6b4f90 (.cfi_jt 0x182ee20); configfs_write_bin_file 0x6b5208 (.cfi_jt
0x182f330); configfs_bin_file_operations table 0x2157220; ashmem_fops 0x229d120; ashmem_misc 0x28c6670
(.fops @ +0x10 = 0x28c6680). EINVAL @ configfs_write_bin_file 0x6b53ac (ppos<0 only).

## Why the swap write doesn't land (build 51a9d15: survives, landed=0, EINVAL)

Two of the candidate causes are RULED OUT by disasm/section evidence:

### (1b) "timeout cleared pi_blocked_on → walk never ran" — FALSE. The walk runs.
- `remove_waiter` clears pi_blocked_on via `str xzr,[x20,#2200]` @0x1e72c4 (x20=`current`, 2200=0x898).
- On the normal requeued-timeout path, `futex_wait_requeue_pi` DOES reach `rt_mutex_cleanup_proxy_lock`
  (bl 0x1e9cd8 @0x292418, guarded by `cbz w23` @0x29240c: skipped only when ret==0/acquired) →
  remove_waiter → clears the WAITER's pi_blocked_on. So a *clean requeued timeout* would clear it.
- BUT the exploit's `CMP_REQUEUE_PI` returns **EDEADLK** (the requeue itself detects the
  waiter→f_pi_target→owner→f_pi_chain→waiter cycle). On that path `__rt_mutex_start_proxy_lock`
  (0x1e989c): `try_to_take_rt_mutex`(0x1e98c8) → `task_blocks_on_rt_mutex`(0x1e98e8) sets
  **waiter_task->pi_blocked_on = &rt_waiter** BEFORE returning -EDEADLK; the subsequent cleanup
  `remove_waiter` runs in the MAIN thread's context, so `current->pi_blocked_on` = the MAIN thread's,
  NOT the waiter's. The waiter's `pi_blocked_on` is left **dangling** at the (about-to-be-freed) stack
  `rt_waiter`. This is exactly why the shift matters: at shift=0 the consumer's sched_setattr walk
  derefs a mis-overlaid waiter (waiter->lock @rt_waiter+0x38 = write_target, a .data alias treated as
  an rt_mutex → garbage owner → **Oops**); at shift=-2 waiter->lock = fake_lock (our page) → survives.
  **⇒ The walk is running. SIGALRM/EINTR is NOT required** (contradicts the (1b)/popsicle hypothesis).

### rodata_full RO on the write target — FALSE. The .data linear alias is RW.
Section map (symbols): `_stext=0x10000, __start_rodata=_etext=0x1a30000, __end_rodata=0x2459000,
__init_begin=0x2460000, __init_end=_data=0x2760000, _edata=0x296ca00, __bss_start=0x296d000`.
`ashmem_misc` @0x28c6670 is inside **.data [0x2760000, 0x296ca00)**. arm64 `mark_linear_text_alias_ro`
marks only the linear alias of `[_stext, __init_begin) = [0x10000, 0x2460000)` (text+rodata) RO; .data
is above __init_end, so its linear alias stays **RW**. The store to `ffffff80028c6680`
(= __va(PHYS_OFFSET+0x28c6680), the correct alias of &ashmem_misc.fops) does not fault. No MTE issue
either: linear addrs carry tag 0xff (KASAN_HW_TAGS match-all). ⇒ if the dequeue store executes, it
lands.

### So: walk runs + target writable, yet landed=0. Remaining causes (ranked)
Static trace says the walk reaches [7] rt_mutex_dequeue (prio 3 ≠ task->prio 139 ⇒ requeue needed;
lock==next_lock==fake_lock; owner=fake_task≠top_task ⇒ no deadlock-exit) and rb_erase hits Case-2
(rb_right=0, rb_left=write_target) → `*write_target = fake_fops`. It should land. Since it doesn't:

1. **Reclaim off by a small (±8B) amount** (MEDIUM). My frame-sum gives EXACT overlap (both objects at
   SP_DIV−0x210 ⇒ shift −2), but if any one frame/offset is off by a single slot the walk still
   *survives* (waiter->lock happens to land on a valid page) while tree_entry.rb_left is read from the
   wrong long ⇒ the store goes to the wrong address / a different rb_erase case ⇒ ashmem_misc.fops
   untouched. Cheap test: also try **shift −1 and −3**.
2. **The reclaimed pi_blocked_on target isn't our overlay bytes in [7]'s view** (MEDIUM): e.g. do_select
   or a prior burst-iteration's `rt_mutex_enqueue` (which sets the fake waiter's rb_left=0,
   rb_right=self) mutated the tree_entry before the *first* value-carrying dequeue, so Case-2 never
   fires with rb_left=write_target.
3. write lands but fresh-open still real ashmem — RULED OUT (EINVAL is definitive for real ashmem).

### Decisive NON-circular diagnostic (recommended before any more guessing)
Point `write_target` at a **scratch qword inside the sprayed page_base** (not ashmem_misc.fops) and set
`write_value` to a magic constant; run the route; read that scratch back via the **sk_buff recv path**
the exploit already uses to build/verify the sprayed page (NOT via configfs/ashmem).
- scratch == magic ⇒ the walk reaches [7] and writes correctly; the bug is specific to the
  ashmem_misc.fops target address/overlay-value on-device (re-derive ASHMEM_MISC_FOPS and the tree_left
  word actually planted).
- scratch unchanged ⇒ the dequeue isn't producing the write; dump the reclaimed `pi_blocked_on`
  target bytes (via the same sk_buff read of page_base / a stack peek) to see what tree_entry actually
  holds, and sweep shift ∈ {−1,−2,−3}.

### Bottom line
Highest-confidence conclusions: **the walk runs (no SIGALRM needed)** and **the target is writable (not
rodata)**. The write not landing is a placement/overlay-content problem at the dequeue; the scratch
read-back localizes it in one device run. RVAs: task_blocks_on_rt_mutex 0x1e6a80;
__rt_mutex_start_proxy_lock 0x1e989c; rt_mutex_cleanup_proxy_lock 0x1e9cd8; remove_waiter 0x1e7204
(pi_blocked_on clear @0x1e72c4); futex cleanup call @0x292418.

## rt_mutex_adjust_pi early-exit (scratch diag: diffs=0, walk body never runs)

`rt_mutex_adjust_pi` @0x1e9274. Guard disassembly:
```
1e92e8 ldr  x8,[x19,#2200]   ; waiter = task->pi_blocked_on (0x898)
1e92ec cbz  x8, 0x1e9314     ; (A) !waiter -> early return (NO chain walk)
1e92f0 ldr  w9,[x19,#132]    ; right->prio = task->prio (0x84)  [task_to_waiter uses task->prio directly]
1e92f4 ldr  w10,[x8,#64]     ; left->prio  = waiter->prio (0x40)
1e92f8 cmp  w10, w9
1e92fc b.ne 0x1e9380         ; prio != -> PROCEED (reads next_lock=waiter->lock @0x1e9384, bl adjust_prio_chain @0x1e93e4)
1e9300 tbz  w9,#31,0x1e9314  ; (B) prio == and task->prio>=0 -> early return
1e9304 ...deadline compare (dl_prio only)...
```

### (B) waiter_equal is DISPROVEN
The consumer does `sched_setattr_tid(tid, nice=19)` with **SCHED_BATCH** (util.c:264-270) ⇒
`task->prio = 120+19 = 139`. The fake `wake_prio` word `(130<<32)|3` ⇒ `waiter->prio(@0x40)=3`.
`3 ≠ 139` ⇒ 0x1e92fc `b.ne` is taken ⇒ **the guard PROCEEDS to the chain walk**. So the early-exit is
NOT `rt_mutex_waiter_equal`.

### The chain walk, if entered, reaches the dequeue — verified exhaustively
For the overlay/payload-intended state every branch from `rt_mutex_adjust_prio_chain` entry to
`rt_mutex_dequeue` PASSES: next_lock==waiter->lock (0x1e79b8); trylock fake_lock->wait_lock=0 succeeds
(0x1e8ff0 CAS, net-zero); lock!=orig_lock (0x1e7c54); rt_mutex_owner(fake_lock)=fake_task ≠ top_task
(0x1e7c68); w26=1 ⇒ requeue-needed (0x1e7c74); prerequeue `BUG_ON(fake_w0->lock!=fake_lock)` — target
0x1e8f80 is **`brk #0x800`** (would crash) but the device SURVIVES and `put_p9_fops_waiter` sets
`fake_w0->lock=fake_lock`, so it passes; then rb_erase Case-2 writes `*write_target`. ⇒ if the chain
walk ran, the scratch WOULD change.

### Conclusion: (A) `!waiter` — pi_blocked_on is NULL when the consumer walks it
`diffs=0` + waiter_equal-disproven + no static early-exit before the dequeue ⇒ the chain walk is not
being entered at all: `rt_mutex_adjust_pi` returns at **`cbz x8,0x1e9314` (0x1e92ec)** because
`task->pi_blocked_on == NULL`. i.e. the requeue-PI + timeout cleanup CLEARED the waiter's pi_blocked_on
before the consumer's sched_setattr ran. (Confirming machinery: on the requeued-timeout path
`futex_wait_requeue_pi` calls `rt_mutex_cleanup_proxy_lock` @0x292418 → `remove_waiter` which does
`str xzr,[x20,#2200]` @0x1e72c4 = `current->pi_blocked_on=NULL`.) The earlier shift-dependent crash is
consistent with this being RACY: sometimes the dangling pointer survives to the walk (mis-aligned →
crash at shift0), most runs it's already cleared (diffs=0, survive at shift-2). Reliable exploitation
needs the dangling pointer to exist *at the moment the chain is walked*.

### FIX (single, highest-confidence): re-introduce the SIGALRM signal-interrupt (popsicle/duchamp)
The dangling `pi_blocked_on` must be created by **interrupting the requeue-PI waiter with a signal**
while it is blocked in `rt_mutex_wait_proxy_lock`, and doing the priority bump from inside the handler,
so the futex returns via EINTR (leaving the waiter enqueued / pi_blocked_on set) instead of the clean
timeout/cleanup path that NULLs it. Concretely (as the working duchamp build did, dropped by the oppo
base):
  - waiter thread installs a SIGALRM handler (sigaction, **SA_RESTART cleared**) that calls
    `setpriority(PRIO_PROCESS, 0, N)`.
  - ~50 ms after `FUTEX_CMP_REQUEUE_PI`, the driver does `pthread_kill(waiter_tid, SIGALRM)`.
  - The handler's setpriority → __sched_setscheduler → rt_mutex_adjust_pi runs the chain WHILE
    pi_blocked_on is still set → the dangling waiter is created; then the (mis)aligned pselect overlay
    reclaim + the consumer walk drive the rb-erase write.
This matches HANDOFF §2A which documents SIGALRM+setpriority as the ONLY reliable way to generate the
dangling rt_mutex_waiter. Rank: (1) re-add SIGALRM [high]; (2) if diffs stays 0, verify the scratch
diag actually redirected tree_left and that the recv reads the scratch offset (rule out an MTE
async-drop by using a 0xff-tagged write_target). RVAs: adjust_pi guard 0x1e92ec/0x1e92fc/0x1e9300;
remove_waiter pi_blocked_on clear 0x1e72c4; cleanup_proxy_lock call 0x292418; prerequeue BUG brk
0x1e8f80.
