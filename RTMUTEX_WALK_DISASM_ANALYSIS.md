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
