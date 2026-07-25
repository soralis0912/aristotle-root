set pagination off
set confirm off
set architecture aarch64
target remote :1234
printf "SCRATCH_PRE lock=%016lx %016lx %016lx %016lx parent=%016lx %016lx bootid=%016lx\n", *(unsigned long*)0xffffffc0129f0000, *(unsigned long*)0xffffffc0129f0008, *(unsigned long*)0xffffffc0129f0010, *(unsigned long*)0xffffffc0129f0018, *(unsigned long*)0xffffffc0129f0100, *(unsigned long*)0xffffffc0129f0108, *(unsigned long*)0xffffffc012a3f345
# rt_mutex_adjust_pi `cbz x8`: x8 = task->pi_blocked_on, x19 = task
break *0xffffffc0101e92ec
commands
  silent
  printf "PIB pid=%d pib=0x%lx bootid=%016lx root=%016lx\n", *(int*)($x19+0x5c8), $x8, *(unsigned long*)0xffffffc012a3f345, *(unsigned long*)0xffffffc0129f0008
  continue
end
continue
