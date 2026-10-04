/* Linux x86-64 only. This header is shared by the trusted pre-exec bootstrap
 * and a constructor with no external imports. No native call is run by unit tests. */
#ifndef V98_NATIVE_BOUNDARY_H
#define V98_NATIVE_BOUNDARY_H
#if !defined(__linux__) || !defined(__x86_64__)
#error "The reviewed native boundary requires Linux x86-64"
#endif
#include "native-filter.h"
struct v98_program { v98_u16 len; struct v98_filter *filter; };
struct v98_ruleset { v98_u64 fs; };
struct v98_beneath { v98_u64 allowed; int fd; } __attribute__((packed));

static long v98_call(long n,long a,long b,long c,long d,long e,long f) {
  register long r10 __asm__("r10")=d;
  register long r8 __asm__("r8")=e;
  register long r9 __asm__("r9")=f;
  long r;
  __asm__ volatile("syscall" : "=a"(r) : "a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9) : "rcx","r11","memory");
  return r;
}
__attribute__((noreturn)) static void v98_boundary_die(void) {
  static const char message[]="V98_NATIVE_BOUNDARY_REFUSED\n";
  v98_call(1,2,(long)message,sizeof(message)-1,0,0,0);
  v98_call(231,125,0,0,0,0,0);
  __builtin_unreachable();
}
__attribute__((unused)) static int v98_equal(const char *a,const char *b) {
  for (unsigned i=0;i<4096;i++) { if(a[i]!=b[i]) return 0; if(!a[i]) return 1; }
  return 0;
}
static void v98_single_thread(void) {
  long fd=v98_call(257,-100,(long)"/proc/self/task",0x90000,0,0,0);
  if(fd<0) v98_boundary_die();
  char b[8192]; long n; unsigned tasks=0;
  while((n=v98_call(217,fd,(long)b,sizeof(b),0,0,0))>0) {
    for(long i=0;i<n;) {
      v98_u16 length=*(v98_u16*)(b+i+16);
      if(length<20 || i+length>n) v98_boundary_die();
      if(b[i+19]!='.') tasks++;
      i+=length;
    }
  }
  v98_call(3,fd,0,0,0,0,0);
  if(n<0 || tasks!=1) v98_boundary_die();
}
static void v98_rule(long set,const char *path,v98_u64 rights,int directory) {
  /* O_PATH|O_NOFOLLOW|O_CLOEXEC: Landlock rules pin the inode, never a symlink. */
  long fd=v98_call(257,-100,(long)path,0x2a0000,0,0,0);
  if(fd<0) v98_boundary_die();
  unsigned char st[144];
  if(v98_call(5,fd,(long)st,0,0,0,0)<0) v98_boundary_die();
  v98_u32 mode=*(v98_u32*)(st+24);
  if((mode & 0170000u)!=(directory?0040000u:0100000u)) v98_boundary_die();
  if(directory && (mode & 0777u)!=0700u) v98_boundary_die();
  if(directory && *(v98_u32*)(st+28)!=1000u) v98_boundary_die();
  struct v98_beneath p={rights,(int)fd};
  if(v98_call(445,set,1,(long)&p,0,0,0)<0) v98_boundary_die();
  v98_call(3,fd,0,0,0,0,0);
}
__attribute__((unused)) static void v98_stage_rule(long set,const char *path) {
  static const char *const names[]={"/scratch","cache","openclaw"};
  long fd=-100;
  for(unsigned i=0;i<4;i++) {
    const char *name=i<3?names[i]:path+sizeof("/scratch/cache/openclaw/")-1;
    long next=v98_call(257,fd,(long)name,0x2b0000,0,0,0);
    if(fd!=-100)v98_call(3,fd,0,0,0,0,0);
    if(next<0)v98_boundary_die();
    unsigned char st[144];
    if(v98_call(5,next,(long)st,0,0,0,0)<0 ||
       (*(v98_u32*)(st+24)&0177777u)!=0040700u || *(v98_u32*)(st+28)!=1000u)v98_boundary_die();
    fd=next;
  }
  struct v98_beneath p={((1ul<<15)-1)&~1ul,(int)fd};
  if(v98_call(445,set,1,(long)&p,0,0,0)<0)v98_boundary_die();
  v98_call(3,fd,0,0,0,0,0);
}
static long v98_ruleset_create(void) {
  if(v98_call(444,0,0,1,0,0,0)<3) v98_boundary_die();
  if(v98_call(157,38,1,0,0,0,0)<0) v98_boundary_die();
  struct v98_ruleset r={(1ul<<15)-1};
  long set=v98_call(444,(long)&r,sizeof(r),0,0,0,0);
  if(set<0) v98_boundary_die();
  return set;
}
static void v98_read_rules(long set,const char *list) {
  long fd=v98_call(257,-100,(long)list,0xa0000,0,0,0);
  if(fd<0) v98_boundary_die();
  static char paths[1048576]; long total=0,n;
  while((n=v98_call(0,fd,(long)(paths+total),sizeof(paths)-1-total,0,0,0))>0) {
    total+=n; if((v98_u64)total>=sizeof(paths)-1) v98_boundary_die();
  }
  if(n<0 || total==0 || paths[total-1]!='\n') v98_boundary_die();
  v98_call(3,fd,0,0,0,0,0);
  long start=0;
  for(long i=0;i<total;i++) if(paths[i]=='\n') {
    paths[i]=0;
    if(paths[start]!='/' || i==start || i-start>=4096) v98_boundary_die();
    for(long j=start;j<i;j++) if(paths[j]=='\r') v98_boundary_die();
    v98_rule(set,paths+start,4,0); start=i+1;
  }
}
static void v98_restrict(long set) {
  if(v98_call(446,set,0,0,0,0,0)<0) v98_boundary_die();
  v98_call(3,set,0,0,0,0,0);
}
/* Every admitted syscall traces, allowing a freshly forked libuv child to have
 * a stricter pre-exec role without injecting any syscall or replacing execFile.
 * Unknown syscalls and all network/descriptor-stealing/namespace/async paths
 * fail in the kernel. TRACE without the supervisor fails closed. */
static void v98_trace_filter(void) {
  struct v98_filter filters[256]; unsigned count=v98_build_filter(filters);
  if(!count)v98_boundary_die();
  struct v98_program p={(v98_u16)count,filters};
  if(v98_call(317,1,1,(long)&p,0,0,0)!=0) v98_boundary_die();
}
__attribute__((unused)) static void v98_bootstrap_boundary(void) {
  if(v98_call(436,3,0xffffffffu,0,0,0,0)!=0) v98_boundary_die();
  v98_single_thread();
  long set=v98_ruleset_create();
  v98_read_rules(set,"/proof/policy/parent-read-paths.txt");
  v98_rule(set,"/usr/local/bin/node",5,0);
  v98_rule(set,"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",5,0);
  v98_rule(set,"/scratch",((1ul<<15)-1)&~1ul,1);
  /* Device access is handled separately because regular-file rule validation
   * intentionally rejects device nodes supplied by the read list. */
  long fd=v98_call(257,-100,(long)"/dev/null",0x2a0000,0,0,0);
  if(fd<0) v98_boundary_die();
  struct v98_beneath p={6,(int)fd};
  if(v98_call(445,set,1,(long)&p,0,0,0)<0) v98_boundary_die();
  v98_call(3,fd,0,0,0,0,0); v98_restrict(set); v98_trace_filter();
}
#endif
