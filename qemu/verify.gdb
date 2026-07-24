set pagination off
set architecture aarch64
target remote :1234
echo \n===== OFFSET VERIFICATION (nokaslr, base 0xffffffc010000000) =====\n
# init_task = base + 0x277bf80
echo \n--- init_task comm (expect "swapper/0"; target.h TASK_COMM_OFF=0x830) ---\n
x/s 0xffffffc01277bf80+0x830
echo --- scan init_task+0x800..0x860 for comm string ---\n
x/24c 0xffffffc01277bf80+0x800
echo \n--- init_task real_cred(0x778) / cred(0x780): expect init_cred=0xffffffc012790930 ---\n
x/2gx 0xffffffc01277bf80+0x778
echo \n--- init_task pi_blocked_on(0x898): expect 0 ---\n
x/gx 0xffffffc01277bf80+0x898
echo \n--- init_task usage(0x40) prio(0x84) : sanity ---\n
x/wx 0xffffffc01277bf80+0x40
x/wx 0xffffffc01277bf80+0x84
echo \n--- selinux_state @0xffffffc012a25b90 : enforcing(+0) ---\n
x/wx 0xffffffc012a25b90
echo \n--- verify a few symbol addrs hold sane data (root_task_group, init_cred) ---\n
x/gx 0xffffffc012976040
x/4gx 0xffffffc012790930
echo \n===== DONE =====\n
detach
quit
