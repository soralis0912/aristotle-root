static long sys(long n,long a,long b,long c,long d,long e,long f){
  register long x8 __asm__("x8")=n; register long x0 __asm__("x0")=a;
  register long x1 __asm__("x1")=b; register long x2 __asm__("x2")=c;
  register long x3 __asm__("x3")=d; register long x4 __asm__("x4")=e;
  register long x5 __asm__("x5")=f;
  __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory");
  return x0;
}
#define SYS_write 64
#define SYS_nanosleep 101
static void puts_(const char*s){long n=0;while(s[n])n++;sys(SYS_write,1,(long)s,n,0,0,0);}
void _start(void){
  puts_("\n=== QEMU-ARISTOTLE-INIT: userspace reached (looping for gdb) ===\n");
  for(;;){ long ts[2]={3600,0}; sys(SYS_nanosleep,(long)ts,0,0,0,0,0); }
}
