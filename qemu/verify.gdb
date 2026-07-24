set pagination off
set architecture aarch64
target remote :1234
echo \n===== OFFSET VERIFICATION (nokaslr, base 0xffffffc010000000) =====\n
echo init_task=0xffffffc01277bf80  init_cred=0xffffffc012790930\n

echo \n--- [TASK] comm (expect "swapper/0"; TASK_COMM_OFF=0x790) ---\n
x/s 0xffffffc01277bf80+0x790

echo \n--- [TASK] real_cred(0x778)/cred(0x780): expect init_cred=0xffffffc012790930 ---\n
x/2gx 0xffffffc01277bf80+0x778

echo \n--- [TASK] parent region 0x5c8..0x618: expect pid0/tgid0, real_parent0x5d8 & parent0x5e0 & group_leader0x608 == &init_task=0xffffffc01277bf80 ---\n
x/20gx 0xffffffc01277bf80+0x5c8

echo \n--- [TASK] pi_blocked_on(0x898): expect 0 ---\n
x/gx 0xffffffc01277bf80+0x898

echo \n--- [TASK] pid(0x5c8)/tgid(0x5cc): init_task=swapper -> both 0; atomic_flags(0x5d8) ---\n
x/2wx 0xffffffc01277bf80+0x5c8
x/gx 0xffffffc01277bf80+0x5d8

echo \n--- [TASK] seccomp(0x8e8): mode(+0)/filter_count(+4)/filter(+8) expect 0/0/0 for init ---\n
x/2wx 0xffffffc01277bf80+0x8e8
x/gx 0xffffffc01277bf80+0x8e8+0x8

echo \n--- [TASK] thread_info.flags(0x00) sanity (bit11=TIF_SECCOMP) ---\n
x/gx 0xffffffc01277bf80+0x00

echo \n===== CRED LAYOUT (init_cred; root uid=0, caps: inh=0 perm/eff/bset=FULL amb=0) =====\n
echo --- head dump 0x00..0x60 as 32-bit words (find zero uid-run then CAP_FULL) ---\n
echo (CAP_FULL 0x000001ffffffffff shows as word pair: ffffffff 000001ff)\n
x/24wx 0xffffffc012790930
echo \n--- caps as 64-bit giants at CRED_CAPS_OFF=0x30 (expect 0, FULL, FULL, FULL, 0) ---\n
x/5gx 0xffffffc012790930+0x30
echo \n--- uid(0x08)=0, securebits(0x28)=0 ---\n
x/wx 0xffffffc012790930+0x08
x/wx 0xffffffc012790930+0x28
echo \n--- security(0x80): expect a kernel pointer (0xffffffc0.. or 0xffffff80..) ---\n
x/gx 0xffffffc012790930+0x80

echo \n===== SYMBOL SANITY =====\n
echo --- selinux_state.enforcing @0xffffffc012a25b90 (+0) ---\n
x/wx 0xffffffc012a25b90
echo --- root_task_group @0xffffffc012976040 ---\n
x/gx 0xffffffc012976040
echo --- init_cred first words @0xffffffc012790930 ---\n
x/4gx 0xffffffc012790930
echo \n===== DONE =====\n
detach
quit
