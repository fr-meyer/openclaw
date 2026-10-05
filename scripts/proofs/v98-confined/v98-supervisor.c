#define _GNU_SOURCE
#if !defined(__linux__) || !defined(__x86_64__)
#error "Linux x86-64 is required; portable tests compile native-policy.c only"
#endif
#include "native-policy.h"
#include "native-sha256.h"
#include "native-boundary.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define V98_PTRACE_OPTIONS (PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC|PTRACE_O_TRACESECCOMP|PTRACE_O_TRACEEXIT|PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL)
struct task {
  pid_t tid,tgid;
  enum v98_role role;
  int stopped,status,assigned,waiting_exit,confined;
  double born;
  long syscall_number;
  unsigned long arguments[6];
};
static struct task tasks[V98_MAX_TASKS];
static struct v98_fds parent_fds,helper_fds;
static struct v98_entitlement entitlement;
static pid_t initial_pid,helper_pid;
static unsigned live;
static int failed,initial_result=-1;
static double deadline;
static struct stat node_identity;
static struct stat stage_identity;
static struct v98_stage_guard stage_guard;
static const char *const *initial_argv;
static size_t initial_argc;
static struct task *guard_owner;

static double now_seconds(void) {
  struct timespec t;
  if(clock_gettime(CLOCK_MONOTONIC,&t)<0) _exit(125);
  return t.tv_sec+t.tv_nsec/1e9;
}
static void report(const char *event,unsigned phase,long value) {
  printf("{\"event\":\"%s\",\"phase\":%u,\"value\":%ld}\n",event,phase,value);
  if(fflush(stdout)) failed=1;
}
static void refuse(const char *reason) { report(reason,entitlement.phase,0);failed=1; }
static struct task *find(pid_t tid) {
  for(unsigned i=0;i<V98_MAX_TASKS;i++) if(tasks[i].tid==tid) return &tasks[i];
  return NULL;
}
static struct task *add(pid_t tid) {
  struct task *t=find(tid);
  if(t) return t;
  for(unsigned i=0;i<V98_MAX_TASKS;i++) if(!tasks[i].tid) {
    tasks[i]=(struct task){.tid=tid,.born=now_seconds()};live++;return &tasks[i];
  }
  refuse("task_limit_refused");return NULL;
}
static int trace(long operation,pid_t tid,void *address,void *data) {
  if(ptrace((enum __ptrace_request)operation,tid,address,data)<0) {refuse("ptrace_operation_refused");return 0;}
  return 1;
}
static int resume(struct task *t,int syscall_exit,int signal_number) {
  if(!t->assigned || !t->stopped) {refuse("unowned_resume_refused");return 0;}
  if(!trace(syscall_exit?PTRACE_SYSCALL:PTRACE_CONT,t->tid,0,(void *)(long)signal_number))return 0;
  t->stopped=0;return 1;
}
static void receive(pid_t pid,int status) {
  struct task *t=find(pid);
  if(WIFEXITED(status)||WIFSIGNALED(status)) {
    if(!t) {refuse("unknown_exit_refused");return;}
    if(pid==initial_pid)initial_result=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
    if(pid==helper_pid)report("helper_reaped",entitlement.phase,WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status));
    if(t==guard_owner&&stage_guard.holding)refuse("helper_tightening_failed");
    if(t->assigned&&t->tid!=t->tgid)report("thread_reaped",entitlement.phase,pid);
    if(t==guard_owner)guard_owner=NULL;
    memset(t,0,sizeof(*t));live--;return;
  }
  if(!WIFSTOPPED(status)) {refuse("unexpected_wait_status");return;}
  if(!t)t=add(pid); /* A newborn stop may be delivered before the parent event. */
  if(t) {t->stopped=1;t->status=status;}
}
static int poll_wait(void) {
  int status;pid_t pid=waitpid(-1,&status,__WALL|WNOHANG);
  if(pid>0){receive(pid,status);return 1;}
  if(pid<0 && errno!=EINTR && errno!=ECHILD)refuse("wait_failed");
  return 0;
}
static void small_pause(void) {struct timespec t={0,1000000};nanosleep(&t,0);}
static int quiesce(struct task *owner) {
  if(guard_owner && guard_owner!=owner){refuse("overlapping_guard_refused");return 0;}
  guard_owner=owner;
  for(unsigned i=0;i<V98_MAX_TASKS;i++) if(tasks[i].tid && !tasks[i].stopped)
    if(!trace(PTRACE_INTERRUPT,tasks[i].tid,0,0))return 0;
  for(;;) {
    int complete=1;
    for(unsigned i=0;i<V98_MAX_TASKS;i++)if(tasks[i].tid&&!tasks[i].stopped)complete=0;
    if(complete)return 1;
    if(failed||now_seconds()>deadline){refuse("quiescence_deadline_refused");return 0;}
    if(!poll_wait())small_pause();
  }
}
static int memory_read(pid_t tid,unsigned long address,void *out,size_t bytes) {
  if(bytes>ULONG_MAX-address)return 0;
  unsigned char *p=out;
  for(size_t offset=0;offset<bytes;) {
    unsigned long at=address+offset,base=at&~(unsigned long)(sizeof(long)-1);
    size_t within=(size_t)(at-base);
    errno=0;long word=ptrace(PTRACE_PEEKDATA,tid,(void *)base,0);
    if(errno)return 0;
    size_t n=bytes-offset;if(n>sizeof(word)-within)n=sizeof(word)-within;
    memcpy(p+offset,(unsigned char *)&word+within,n);offset+=n;
  }
  return 1;
}
static int remote_string(pid_t tid,unsigned long address,char *out) {
  for(size_t i=0;i<V98_STRING_BYTES;i++) {
    if(!memory_read(tid,address+i,out+i,1))return 0;
    if(!out[i])return 1;
  }
  return 0;
}
static int remote_vector(pid_t tid,unsigned long address,char storage[][V98_STRING_BYTES],
                         const char **vector,size_t maximum,size_t *count) {
  for(size_t i=0;i<=maximum;i++) {
    unsigned long pointer;
    if(!memory_read(tid,address+i*sizeof(pointer),&pointer,sizeof(pointer)))return 0;
    if(!pointer){*count=i;return 1;}
    if(i==maximum||!remote_string(tid,pointer,storage[i]))return 0;
    vector[i]=storage[i];
  }
  return 0;
}
static int vector_equal(size_t n,const char *const *actual,size_t wanted,const char *const *expected) {
  if(n!=wanted)return 0;
  for(size_t i=0;i<n;i++)if(strcmp(actual[i],expected[i]))return 0;
  return 1;
}
static int bind_stage(const char *path) {
  static const char *const names[]={"/scratch","cache","openclaw"};
  int fd=AT_FDCWD;
  for(unsigned i=0;i<4;i++) {
    const char *name=i<3?names[i]:path+sizeof("/scratch/cache/openclaw/")-1;
    int next=openat(fd,name,O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd!=AT_FDCWD)close(fd);
    if(next<0)return 0;
    struct stat st;
    if(fstat(next,&st)<0||!v98_stage_directory(st.st_mode,st.st_uid)){close(next);return 0;}
    fd=next;stage_identity=st;
  }
  int scan=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(scan<0){close(fd);return 0;}
  DIR *directory=fdopendir(scan);if(!directory){close(scan);close(fd);return 0;}
  struct dirent *entry;int owner_seen=0,okay=1;
  while((entry=readdir(directory)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,"..")) {
    struct stat st;
    if(fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)<0||!v98_stage_token_entry(entry->d_name,st.st_mode,st.st_uid,st.st_nlink)){okay=0;break;}
    if(!strcmp(entry->d_name,"owner.sqlite"))owner_seen=1;
  }
  closedir(directory);close(fd);return okay&&owner_seen;
}
static int exec_request(struct task *t,struct user_regs_struct *r) {
  static char a[V98_MAX_ARGV][V98_STRING_BYTES],e[V98_MAX_ENV][V98_STRING_BYTES],filename[V98_STRING_BYTES];
  const char *av[V98_MAX_ARGV],*ev[V98_MAX_ENV];size_t ac,ec;
  if(!remote_string(t->tid,r->rdi,filename)||strcmp(filename,V98_NODE)||
     !remote_vector(t->tid,r->rsi,a,av,V98_MAX_ARGV,&ac)||
     !remote_vector(t->tid,r->rdx,e,ev,V98_MAX_ENV,&ec)||!v98_exact_environment(ec,ev))return 0;
  if(t->role==V98_BOOTSTRAP)return vector_equal(ac,av,initial_argc,initial_argv);
  return t->role==V98_PENDING_HELPER&&entitlement.phase==3&&!entitlement.helper_execs&&
    v98_helper_argv(ac,av)&&bind_stage(av[5]);
}
static int proc_vector(pid_t pid,const char *name,char storage[][V98_STRING_BYTES],
                       const char **vector,size_t maximum,size_t *count) {
  char path[128];snprintf(path,sizeof(path),"/proc/%ld/%s",(long)pid,name);
  int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return 0;
  unsigned char buffer[(V98_MAX_ARGV+1)*V98_STRING_BYTES];size_t total=0;ssize_t n;
  while((n=read(fd,buffer+total,sizeof(buffer)-total))>0) {total+=(size_t)n;if(total==sizeof(buffer)){close(fd);return 0;}}
  close(fd);if(n<0||!total||buffer[total-1])return 0;
  size_t start=0,items=0;
  for(size_t i=0;i<total;i++)if(!buffer[i]) {
    if(items==maximum||i-start>=V98_STRING_BYTES)return 0;
    memcpy(storage[items],buffer+start,i-start+1);vector[items]=storage[items];items++;start=i+1;
  }
  *count=items;return 1;
}
static int only_stdio(pid_t pid) {
  char path[128];snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid);
  DIR *d=opendir(path);if(!d)return 0;struct dirent *entry;int okay=1;
  while((entry=readdir(d)))if(entry->d_name[0]!='.') {
    char *end;long fd=strtol(entry->d_name,&end,10);
    if(*end||fd<0||fd>2)okay=0;
  }
  closedir(d);return okay;
}
static int proc_fd_stat(pid_t pid,int descriptor,struct stat *st) {
  if(descriptor<0)return 0;
  char path[128];snprintf(path,sizeof(path),"/proc/%ld/fd/%d",(long)pid,descriptor);
  int fd=open(path,O_PATH|O_CLOEXEC);if(fd<0)return 0;
  int okay=fstat(fd,st)==0;close(fd);return okay;
}
static int pair_inode(const struct v98_fds *fds,const struct stat *st) {
  if(!S_ISSOCK(st->st_mode))return 0;
  for(unsigned i=0;i<fds->created;i++) {
    const struct v98_pair *p=&fds->pairs[i];
    if((p->a_device==(uint64_t)st->st_dev&&p->a_inode==(uint64_t)st->st_ino)||
       (p->b_device==(uint64_t)st->st_dev&&p->b_inode==(uint64_t)st->st_ino))return 1;
  }
  return 0;
}
static int helper_stdio(pid_t pid) {
  for(int fd=0;fd<=2;fd++) {
    struct stat st;if(!proc_fd_stat(pid,fd,&st)||!pair_inode(&helper_fds,&st))return 0;
  }
  return 1;
}
static int committed_exec(struct task *t) {
  char path[128];snprintf(path,sizeof(path),"/proc/%ld/exe",(long)t->tid);
  int fd=open(path,O_PATH|O_CLOEXEC);struct stat st;
  if(fd<0)return 0;
  int inode=fstat(fd,&st)==0&&st.st_dev==node_identity.st_dev&&st.st_ino==node_identity.st_ino;
  close(fd);if(!inode||!only_stdio(t->tid))return 0;
  static char a[V98_MAX_ARGV][V98_STRING_BYTES],e[V98_MAX_ENV][V98_STRING_BYTES];
  const char *av[V98_MAX_ARGV],*ev[V98_MAX_ENV];size_t ac,ec;
  if(!proc_vector(t->tid,"cmdline",a,av,V98_MAX_ARGV,&ac)||
     !proc_vector(t->tid,"environ",e,ev,V98_MAX_ENV,&ec)||!v98_exact_environment(ec,ev))return 0;
  if(t->role==V98_BOOTSTRAP) {
    if(!vector_equal(ac,av,initial_argc,initial_argv))return 0;
    t->role=V98_PARENT;report("initial_exec_verified",entitlement.phase,t->tid);
    report("base_boundary_installed",entitlement.phase,t->tid);return 1;
  }
  if(t->role!=V98_PENDING_HELPER||entitlement.helper_execs||!v98_helper_argv(ac,av)||!helper_stdio(t->tid))return 0;
  t->role=V98_HELPER;entitlement.helper_execs=1;helper_pid=t->tgid;
  v98_stage_begin(&stage_guard,stage_identity.st_dev,stage_identity.st_ino);
  /* The committed exec FD census proved that every non-stdio endpoint was
   * closed by CLOEXEC. Retire the copied table before fd numbers can be reused. */
  for(unsigned i=0;i<helper_fds.created;i++){helper_fds.pairs[i].a=-1;helper_fds.pairs[i].b=-1;}
  report("helper_exec_verified",entitlement.phase,t->tid);return 1;
}
static struct v98_fds *fd_table(struct task *t) {return t->tgid==initial_pid?&parent_fds:&helper_fds;}
static int scoped_helper_alive(void) {
  for(unsigned i=0;i<V98_MAX_TASKS;i++)if(tasks[i].tid&&helper_pid&&tasks[i].tgid==helper_pid)return 1;
  return 0;
}
static int pending_syscall(long nr) {
  switch(nr) {
    case 1:case 3:case 13:case 14:case 32:case 33:case 39:case 59:case 60:
    case 72:case 102:case 104:case 107:case 108:case 186:case 218:case 231:case 273:case 292:case 436:return 1;
    default:return 0;
  }
}
static int guarded(long nr) {
  switch(nr) {
    case 3:case 32:case 33:case 53:case 54:case 56:case 57:case 59:case 62:
    case 72:case 200:case 234:case 292:case 436:case 444:case 445:case 446:return 1;
    default:return 0;
  }
}
static int syscall_allowed(struct task *t,struct user_regs_struct *r) {
  long nr=(long)r->orig_rax;unsigned long a=r->rdi,b=r->rsi,c=r->rdx,d=r->r10,e=r->r8;
  if(!v98_canonical_syscall(r->orig_rax))return 0;
  if(fd_table(t)->owner_tgid!=t->tgid)return 0;
  if(t->role==V98_PARENT&&scoped_helper_alive()&&v98_namespace_mutator(nr))return 0;
  if(nr==41)return 0; /* Trace the negative socket probe, always deny creation. */
  if(t->role==V98_HELPER&&!t->confined&&nr==444) {
    if(a==0&&b==0&&c==1)return 1;
    uint64_t rights;
    return stage_guard.ruleset_fd<0&&b==sizeof(rights)&&c==0&&memory_read(t->tid,a,&rights,sizeof(rights))&&rights==32767;
  }
  if(t->role==V98_HELPER&&!t->confined&&nr==445) {
    struct v98_beneath attribute;
    if((int)a!=stage_guard.ruleset_fd||b!=1||d!=0||!memory_read(t->tid,c,&attribute,sizeof(attribute)))return 0;
    struct stat st;
    if(!proc_fd_stat(t->tid,attribute.fd,&st))return 0;
    return v98_stage_add_request(&stage_guard,(int)a,attribute.allowed,st.st_dev,st.st_ino,st.st_mode,st.st_uid);
  }
  if(t->role==V98_HELPER&&!t->confined&&nr==446)
    return v98_stage_restrict_request(&stage_guard,(int)a,b);
  if(t->role==V98_PENDING_HELPER&&!pending_syscall(nr))return 0;
  if(t->role==V98_PENDING_HELPER&&nr==1) {
    struct stat st;
    if(!proc_fd_stat(t->tid,(int)a,&st)||!(S_ISFIFO(st.st_mode)||pair_inode(&helper_fds,&st)))return 0;
    if(a>2&&c!=sizeof(int))return 0; /* libuv's anonymous exec-error pipe only. */
  }
  if(t->role==V98_HELPER&&!t->confined) {
    /* Loader/constructor can only read files and configure tighter Landlock;
     * no write-capable opens or preopened filesystem FDs exist at EXEC stop. */
    if((nr==2||nr==257) && ((nr==257?c:b)&(3|0100|01000|020000000)))return 0;
    if(nr==18||nr==20||nr==40||nr==73||nr==74||nr==75||nr==76||nr==77||
       nr==82||nr==83||nr==84||nr==85||nr==86||nr==87||nr==90||nr==91||
       nr==258||nr==260||nr==261||nr==263||nr==264||nr==265||nr==267||nr==280)return 0;
    if(nr==1 && a>2)return 0;
  }
  if(nr==59)return exec_request(t,r);
  if(nr==16) {
    struct stat st;
    return (b==0x5421||b==0x541b)&&proc_fd_stat(t->tid,(int)a,&st)&&
           (S_ISFIFO(st.st_mode)||S_ISSOCK(st.st_mode));
  }
  if(nr==56) {
    if(v98_thread_flags(a))return t->role==V98_PARENT || (t->role==V98_HELPER&&t->confined);
    if(!v98_process_flags(nr,a))return 0;
    return v98_grant_fork(&entitlement,t->role);
  }
  if(nr==57)return v98_grant_fork(&entitlement,t->role);
  if(nr==53)return v98_pair_request(entitlement.phase,t->role,a,b,c)&&fd_table(t)->created<V98_MAX_PAIRS;
  if(nr==54) {
    int value;
    struct stat st;
    return memory_read(t->tid,d,&value,sizeof(value))&&proc_fd_stat(t->tid,(int)a,&st)&&
      pair_inode(fd_table(t),&st)&&v98_socket_option(fd_table(t),(int)a,b,c,e,value);
  }
  if(nr==62) return v98_signal_target(t->tgid,(int)a,(int)b,helper_pid);
  if(nr==200||nr==234) {
    struct task *target=find((pid_t)(nr==234?b:a));
    return target&&target->assigned&&target->tgid==t->tgid&&
      (nr!=234||(pid_t)a==t->tgid)&&v98_signal_target(t->tgid,target->tgid,(int)(nr==234?c:b),helper_pid);
  }
  if(nr==32)return !v98_fd_tracked(fd_table(t),(int)a);
  if(nr==33||nr==292)return !v98_fd_tracked(fd_table(t),(int)a)||(b<=2);
  if(nr==72) {
    /* F_DUPFD/F_DUPFD_CLOEXEC are denied on tracked pair endpoints. */
    if((b==0||b==1030)&&v98_fd_tracked(fd_table(t),(int)a))return 0;
    return b==0||b==1||b==2||b==3||b==4||b==5||b==6||b==1030;
  }
  if(nr==436)return a<=UINT32_MAX&&b<=UINT32_MAX&&c==0;
  if(nr==157)return a==38&&b==1&&c==0&&d==0&&e==0;
  return 1;
}
static int finish_syscall(struct task *t,struct user_regs_struct *r) {
  long result=(long)r->rax,nr=t->syscall_number;
  if(nr==3&&result<0&&(result!=-EBADF||v98_fd_tracked(fd_table(t),(int)t->arguments[0])))return 0;
  if(nr==445&&t->role==V98_HELPER&&!t->confined)v98_stage_add_result(&stage_guard,result);
  /* Restart/pseudo-results are refused while borrowed memory or FD tables are
   * locked. A fresh attempt must never reuse an earlier argument decision. */
  if(result<=-512&&result>=-516)return 0;
  if(result>=0) {
    struct v98_fds *fds=fd_table(t);
    if(nr==53) {
      int pair[2];if(!memory_read(t->tid,t->arguments[3],pair,sizeof(pair))||!v98_pair_record(fds,pair[0],pair[1]))return 0;
      struct stat a,b;
      if(!proc_fd_stat(t->tid,pair[0],&a)||!proc_fd_stat(t->tid,pair[1],&b)||!S_ISSOCK(a.st_mode)||!S_ISSOCK(b.st_mode))return 0;
      struct v98_pair *p=&fds->pairs[fds->created-1];
      p->a_device=a.st_dev;p->a_inode=a.st_ino;p->b_device=b.st_dev;p->b_inode=b.st_ino;
    } else if(nr==3)v98_fd_close(fds,(int)t->arguments[0]);
    else if(nr==33||nr==292) {if(!v98_fd_duplicate(fds,(int)t->arguments[0],(int)t->arguments[1]))return 0;}
    else if(nr==436) {
      for(unsigned i=0;i<fds->created;i++) {
        if((unsigned)fds->pairs[i].a>=t->arguments[0]&&(unsigned)fds->pairs[i].a<=t->arguments[1])fds->pairs[i].a=-1;
        if((unsigned)fds->pairs[i].b>=t->arguments[0]&&(unsigned)fds->pairs[i].b<=t->arguments[1])fds->pairs[i].b=-1;
      }
    }
    if(nr==444&&t->role==V98_HELPER&&!t->confined&&t->arguments[0])stage_guard.ruleset_fd=(int)result;
    if(nr==446&&t->role==V98_HELPER&&!t->confined) {
      if(!v98_stage_restrict_result(&stage_guard,(int)t->arguments[0],t->arguments[1],result))return 0;
      t->confined=1;report("helper_landlock_tightened",entitlement.phase,t->tid);
    }
    if(nr==74||nr==75)report("fsync_completed",entitlement.phase,t->tid);
  }
  return 1;
}
static void syscall_stop(struct task *t) {
  struct user_regs_struct r;if(!trace(PTRACE_GETREGS,t->tid,0,&r))return;
  long nr=(long)r.orig_rax;
  int lock=guarded(nr)||(nr==1&&t->role==V98_PENDING_HELPER);
  if(lock&&!quiesce(t))return;
  if(!syscall_allowed(t,&r)) {
    r.orig_rax=(unsigned long)-1;r.rax=(unsigned long)-EPERM;
    if(!trace(PTRACE_SETREGS,t->tid,0,&r))return;
    /* A denied syscall is skipped; overwrite ENOSYS at its exit stop. */
    t->syscall_number=-1;t->waiting_exit=1;report("syscall_denied",entitlement.phase,nr);
    resume(t,1,0);return;
  }
  if(lock||nr==446||nr==74||nr==75) {
    t->syscall_number=nr;t->arguments[0]=r.rdi;t->arguments[1]=r.rsi;t->arguments[2]=r.rdx;
    t->arguments[3]=r.r10;t->arguments[4]=r.r8;t->arguments[5]=r.r9;
    t->waiting_exit=1;resume(t,1,0);
  } else resume(t,0,0);
}
static void dispatch(struct task *t) {
  unsigned event=(unsigned)t->status>>16;int signal_number=WSTOPSIG(t->status);
  if(!t->assigned)return;
  if(event==PTRACE_EVENT_FORK||event==PTRACE_EVENT_CLONE||event==PTRACE_EVENT_VFORK) {
    unsigned long child;if(!trace(PTRACE_GETEVENTMSG,t->tid,0,&child))return;
    struct task *newborn=add((pid_t)child);if(!newborn)return;
    if(event==PTRACE_EVENT_VFORK) {refuse("vfork_refused");return;}
    newborn->assigned=1;
    if(t->syscall_number==56&&v98_thread_flags(t->arguments[0])) {
      newborn->tgid=t->tgid;newborn->role=t->role;newborn->confined=t->confined;
      report("thread_owned",entitlement.phase,newborn->tid);
    } else {
      if(t->role!=V98_PARENT||entitlement.phase!=3||helper_pid) {refuse("unexpected_process_creation");return;}
      newborn->tgid=newborn->tid;newborn->role=V98_PENDING_HELPER;helper_pid=newborn->tid;
      helper_fds=parent_fds;helper_fds.owner_tgid=newborn->tgid;helper_fds.generation++;
      report("helper_fork_owned",entitlement.phase,newborn->tid);
    }
    resume(t,1,0);return;
  }
  if(event==PTRACE_EVENT_EXEC) {
    if(guard_owner!=t||!committed_exec(t)) {refuse("committed_exec_refused");return;}
    t->waiting_exit=0;if(!stage_guard.holding)guard_owner=NULL;resume(t,0,0);return;
  }
  if(event==PTRACE_EVENT_SECCOMP) {syscall_stop(t);return;}
  if(event==PTRACE_EVENT_EXIT) {resume(t,t->waiting_exit,0);return;}
  if(signal_number==(SIGTRAP|0x80)) {
    if(!t->waiting_exit) {refuse("unexpected_syscall_exit");return;}
    struct user_regs_struct r;if(!trace(PTRACE_GETREGS,t->tid,0,&r))return;
    if(t->syscall_number==-1) {r.rax=(unsigned long)-EPERM;if(!trace(PTRACE_SETREGS,t->tid,0,&r))return;}
    else if(!finish_syscall(t,&r)) {refuse("syscall_commit_refused");return;}
    t->waiting_exit=0;if(guard_owner==t&&!stage_guard.holding)guard_owner=NULL;resume(t,0,0);return;
  }
  if(event==PTRACE_EVENT_STOP) {resume(t,t->waiting_exit,0);return;}
  /* No external signal sender exists in the isolated namespace. Internal
   * SIGCHLD/SIGPIPE retain real Node behavior; other unexpected signals abort. */
  if(signal_number==SIGCHLD||signal_number==SIGPIPE)resume(t,t->waiting_exit,signal_number);
  else refuse("unexpected_signal_refused");
}
static int verify_file(const char *path,const char *wanted,struct stat *identity) {
  int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 0;
  struct stat before,after;int okay=fstat(fd,&before)==0&&S_ISREG(before.st_mode);
  if(!okay){close(fd);return 0;}
  struct v98_sha256 s;v98_sha_init(&s);unsigned char buffer[65536];ssize_t n=0;
  while(okay&&(n=read(fd,buffer,sizeof(buffer)))>0)v98_sha_update(&s,buffer,(size_t)n);
  if(okay&&n<0)okay=0;
  char actual[65];v98_sha_final(&s,actual);
  if(fstat(fd,&after)<0||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size||strcmp(actual,wanted))okay=0;
  close(fd);if(okay&&identity)*identity=before;return okay;
}
static int host_gate(const char *mode) {
  int sentinel=open("/dev/shm/v98-outside-sentinel",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
  static const char contents[]="V98_OUTSIDE_SENTINEL\n";
  if(sentinel<0||write(sentinel,contents,sizeof(contents)-1)!=(ssize_t)sizeof(contents)-1)return 0;
  if(close(sentinel))return 0;
  printf("{\"event\":\"host_gate_ready\",\"mode\":\"%s\"}\n",mode);fflush(stdout);
  double until=now_seconds()+5;
  while(now_seconds()<until) {
    int fd=open("/scratch/host-admitted",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd>=0) {
      struct stat st;char b[19];
      int okay=fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_nlink==1&&st.st_size==18&&
        st.st_uid==0&&st.st_gid==1000&&(st.st_mode&0777)==0440;
      ssize_t n=okay?read(fd,b,sizeof(b)):-1;
      okay=okay&&n==18&&!memcmp(b,"V98_HOST_ADMITTED\n",18);
      close(fd);return okay;
    }
    if(errno!=ENOENT)return 0;
    small_pause();
  }
  return 0;
}
static void kill_join(void) {
  for(unsigned i=0;i<V98_MAX_TASKS;i++)if(tasks[i].tid)kill(tasks[i].tid,SIGKILL);
  double until=now_seconds()+2;
  while(live&&now_seconds()<until) {
    if(!poll_wait())small_pause();
    for(unsigned i=0;i<V98_MAX_TASKS;i++)if(tasks[i].tid&&tasks[i].stopped) {
      /* EXIT stops still require a tracer resume before native wait can reap.
       * Cleanup may resume only with SIGKILL; no product work is admitted. */
      if(ptrace(PTRACE_CONT,tasks[i].tid,0,(void *)(long)SIGKILL)==0)tasks[i].stopped=0;
    }
  }
  report(live?"native_join_failed":"native_tree_joined",entitlement.phase,live);
}
static int run_phase(unsigned phase,const char *const *argv) {
  initial_argv=argv;for(initial_argc=0;argv[initial_argc];initial_argc++);
  entitlement.phase=phase;initial_result=-1;guard_owner=NULL;stage_guard=(struct v98_stage_guard){0};parent_fds=(struct v98_fds){0};helper_fds=(struct v98_fds){0};helper_pid=0;
  int gate[2],ready[2];if(pipe2(gate,O_CLOEXEC)<0)return 0;
  if(pipe2(ready,O_CLOEXEC)<0){close(gate[0]);close(gate[1]);return 0;}
  pid_t child=fork();if(child<0){close(gate[0]);close(gate[1]);close(ready[0]);close(ready[1]);return 0;}
  if(!child) {
    close(gate[1]);close(ready[0]);char byte;
    /* PID1 is nondumpable to protect its trusted output/control descriptors.
     * Only this still-trusted child enables same-UID own-child tracing before
     * any product code, then acknowledges through a pipe closed before exec. */
    if(prctl(PR_SET_DUMPABLE,1)<0||write(ready[1],"r",1)!=1)_exit(125);
    close(ready[1]);
    if(read(gate[0],&byte,1)!=1)_exit(125);
    close(gate[0]);
    /* Product output has no handle to the supervisor's trusted stdout. */
    if(dup2(2,1)<0)_exit(125);
    int null=open("/dev/null",O_RDONLY|O_CLOEXEC);if(null<0||dup2(null,0)<0)_exit(125);if(null>2)close(null);
    v98_bootstrap_boundary();
    char *environment[V98_MAX_ENV+1];for(unsigned i=0;i<V98_MAX_ENV;i++)environment[i]=(char *)v98_environment[i];environment[V98_MAX_ENV]=NULL;
    execve(V98_NODE,(char *const *)argv,environment);_exit(125);
  }
  close(gate[0]);close(ready[1]);initial_pid=child;
  struct task *t=add(child);if(!t){close(gate[1]);kill(child,SIGKILL);return 0;}
  t->assigned=1;t->tgid=child;t->role=V98_BOOTSTRAP;
  parent_fds.owner_tgid=child;parent_fds.generation=phase*2+1;
  if(fcntl(ready[0],F_SETFL,O_NONBLOCK)<0){close(ready[0]);close(gate[1]);kill_join();return 0;}
  double ready_deadline=now_seconds()+2;char acknowledgement;ssize_t ready_bytes=-1;
  while(now_seconds()<ready_deadline) {
    ready_bytes=read(ready[0],&acknowledgement,1);
    if(ready_bytes==1||ready_bytes==0||(ready_bytes<0&&errno!=EAGAIN&&errno!=EINTR))break;
    small_pause();
  }
  close(ready[0]);
  if(ready_bytes!=1||acknowledgement!='r'){close(gate[1]);kill_join();return 0;}
  if(!trace(PTRACE_SEIZE,child,0,(void *)(long)V98_PTRACE_OPTIONS)||!trace(PTRACE_INTERRUPT,child,0,0)) {close(gate[1]);kill_join();return 0;}
  while(!t->stopped&&!failed){if(!poll_wait())small_pause();}
  if(write(gate[1],"x",1)!=1)refuse("bootstrap_gate_failed");
  close(gate[1]);
  if(!failed)resume(t,0,0);
  report("phase_started",phase,child);
  while(live&&!failed) {
    if(now_seconds()>deadline){refuse("native_wall_deadline");break;}
    for(unsigned i=0;i<V98_MAX_TASKS;i++)if(tasks[i].tid&&tasks[i].role==V98_PENDING_HELPER&&now_seconds()-tasks[i].born>2)refuse("pending_helper_deadline");
    if(failed)break;
    int dispatched=0;
    for(unsigned i=0;i<V98_MAX_TASKS;i++)if(tasks[i].tid&&tasks[i].stopped&&tasks[i].assigned&&(!guard_owner||guard_owner==&tasks[i])) {
      dispatch(&tasks[i]);dispatched=1;if(failed||guard_owner)break;
    }
    if(!poll_wait()&&!dispatched)small_pause();
  }
  if(failed){kill_join();return 0;}
  report("phase_joined",phase,initial_result);
  return initial_result==0;
}
int main(int argc,char **argv) {
  if(argc!=2||getuid()!=1000||getgid()!=1000||getpid()!=1)return 125;
  int fixture=!strcmp(argv[1],"--run-frozen-six-phases");
  int capability=!strcmp(argv[1],"--capability-probe"),hang=!strcmp(argv[1],"--deadline-probe");
  if(!fixture&&!capability&&!hang)return 125;
  if(prctl(PR_SET_DUMPABLE,0)<0||prctl(PR_SET_CHILD_SUBREAPER,1)<0)return 125;
  setvbuf(stdout,NULL,_IOLBF,0);
  if(!verify_file(V98_NODE,"7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c",&node_identity)||
     !verify_file(V98_WORKER,"83d25dd680526c5aeab26b0646e655cd9683df38cb7ee7f2ee9d11a6ef6fe5da",NULL)||
     !verify_file(V98_FIXTURE,"e2175143f99b35fd3cbcbac86a07951f76a0ff5f8d27744a31b39b5f63db2522",NULL))return 125;
  if(!host_gate(argv[1]))return 125;
  deadline=now_seconds()+(fixture?60:hang?5:15);
  static const char *const p1[]={V98_NODE,"--max-old-space-size=128",V98_FIXTURE,"prepare","/scratch/synthetic-parity-fixture","/proof/inputs/predecessor-state.sql","/proof/inputs/predecessor-workboard.ts","/proof/inputs/predecessor-publisher-controller.mjs",NULL};
  static const char *const p2[]={V98_NODE,"--max-old-space-size=128",V98_FIXTURE,"assert","/scratch/synthetic-parity-fixture","predecessor",NULL};
  static const char *const p3[]={V98_NODE,"--max-old-space-size=128",V98_FIXTURE,"migrate","/scratch/synthetic-parity-fixture","/app/dist/openclaw-state-db-CgJKJRub.mjs","adfe8f5551b6904d46ce157c20defff6e8f991a2ea67a6c1d32ddd66b93e6c13",NULL};
  static const char *const p4[]={V98_NODE,"--max-old-space-size=128",V98_FIXTURE,"assert","/scratch/synthetic-parity-fixture","candidate",NULL};
  static const char *const p5[]={V98_NODE,"--max-old-space-size=128",V98_FIXTURE,"restore","/scratch/synthetic-parity-fixture",NULL};
  static const char *const p6[]={V98_NODE,"--max-old-space-size=128",V98_FIXTURE,"assert","/scratch/synthetic-parity-fixture","rollback",NULL};
  const char *const *phases[]={p1,p2,p3,p4,p5,p6};
  if(fixture) {
    for(unsigned i=0;i<6;i++)if(!run_phase(i+1,phases[i]))return 125;
    if(entitlement.forks!=1||entitlement.helper_execs!=1)return 125;
  } else {
    const char *const probe[]={V98_NODE,"--max-old-space-size=128","/proof/runner/capability-probe.mjs",argv[1],NULL};
    if(!run_phase(0,probe))return 125;
  }
  report("native_attempt_joined",entitlement.phase,live);
  return 0;
}
