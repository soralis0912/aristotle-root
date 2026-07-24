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
