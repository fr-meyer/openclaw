/* Portable decision tests. This harness never imports native-boundary.h and
 * cannot activate Landlock/seccomp/ptrace, launch Node, or touch SQLite. */
#include "native-policy.h"
#include "native-sha256.h"
#include "native-filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
static void check(int condition,const char *description) {
  checks++;
  if(!condition){fprintf(stderr,"FAIL: %s\n",description);exit(1);}
}
static void digest(const char *message,size_t split,const char *expected) {
  struct v98_sha256 s;char hex[65];size_t n=strlen(message);v98_sha_init(&s);
  if(split>n)split=n;
  v98_sha_update(&s,(const unsigned char *)message,split);
  v98_sha_update(&s,(const unsigned char *)message+split,n-split);
  v98_sha_final(&s,hex);check(!strcmp(hex,expected),"SHA-256 known-answer/chunk-boundary");
}
static unsigned filter_result(unsigned arch,unsigned nr) {
  struct v98_filter f[256];unsigned n=v98_build_filter(f),a=0;
  check(n>0&&n<=256,"kernel filter has bounded nonempty program");
  for(unsigned i=0;i<n;i++) {
    switch(f[i].code) {
      case 0x20:check(f[i].k==0||f[i].k==4,"BPF reads only syscall/arch words");a=f[i].k?arch:nr;break;
      case 0x15:i+=a==f[i].k?f[i].jt:f[i].jf;break;
      case 0x45:i+=(a&f[i].k)?f[i].jt:f[i].jf;break;
      case 0x06:return f[i].k;
      default:check(0,"unexpected BPF instruction");
    }
  }
  check(0,"BPF must return");return 0;
}
int main(void) {
  check(v98_canonical_syscall(59),"canonical x64 exec number admitted for role decision");
  check(!v98_canonical_syscall(UINT64_C(0x10000003b)),"highword exec number cannot bypass role switch");
  check(!v98_canonical_syscall(UINT64_C(0x100000052)),"highword rename number cannot bypass namespace fence");
  check(!v98_canonical_syscall(UINT64_C(0x1000001b4)),"highword close_range cannot bypass FD accounting");
  check(!v98_canonical_syscall(UINT64_C(0x4000003b)),"x32 exec number rejected in native role owner too");
  check(!v98_canonical_syscall(UINT64_MAX),"negative/overflow syscall numbers denied");
  check(v98_stage_directory(0040700,1000),"exact owned private stage directory accepted");
  check(!v98_stage_directory(0120700,1000),"symlink ancestor/final component type denied");
  check(!v98_stage_directory(0040770,1000),"group-writable stage denied");
  check(!v98_stage_directory(0040700,0),"wrong stage owner denied");
  check(!v98_stage_directory(0140700,1000),"socket cannot stand in for stage directory");
  check(v98_stage_token_entry("owner.sqlite",0100600,1000,1),"source-owned token file metadata accepted");
  check(v98_stage_token_entry("owner.sqlite-journal",0100600,1000,1),"source token sidecar metadata accepted");
  check(!v98_stage_token_entry("owner.sqlite",0100600,1000,2),"preexisting token hardlink alias denied");
  check(!v98_stage_token_entry("owner.sqlite",0120600,1000,1),"preexisting token symlink denied");
  check(!v98_stage_token_entry("owner.sqlite",0100600,0,1),"wrong token file owner denied");
  check(!v98_stage_token_entry("openclaw.sqlite",0100600,1000,1),"preexisting payload cannot alias original source");
  struct v98_stage_guard stage_guard;v98_stage_begin(&stage_guard,11,22);
  check(stage_guard.holding&&!stage_guard.rule_seen,"parent writers stopped from committed helper exec");
  check(!v98_stage_restrict_request(&stage_guard,3,0),"restrict cannot release without bound writable rule");
  stage_guard.ruleset_fd=3;
  check(!v98_stage_add_request(&stage_guard,4,32766,11,22,0040700,1000),"wrong ruleset descriptor denied");
  check(!v98_stage_add_request(&stage_guard,3,32766,12,22,0040700,1000),"stage device redirection denied");
  check(!v98_stage_add_request(&stage_guard,3,32766,11,23,0040700,1000),"stage inode redirection denied");
  check(!v98_stage_add_request(&stage_guard,3,32766,11,22,0100600,1000),"candidate-family file cannot receive stage write grant");
  check(!v98_stage_add_request(&stage_guard,3,32767,11,22,0040700,1000),"execution right never admitted to stage");
  check(v98_stage_add_request(&stage_guard,3,4,99,99,0100444,0),"readonly compiled dependency rule admitted");
  v98_stage_add_result(&stage_guard,0);
  check(!stage_guard.rule_seen&&stage_guard.holding,"readonly rules never authorize release");
  check(v98_stage_add_request(&stage_guard,3,32766,11,22,0040700,1000),"exact bound writable inode admitted");
  v98_stage_add_result(&stage_guard,-1);
  check(!stage_guard.rule_seen&&stage_guard.holding,"failed kernel add retains writer stop");
  check(v98_stage_add_request(&stage_guard,3,32766,11,22,0040700,1000),"fresh successful add may follow failure");
  v98_stage_add_result(&stage_guard,0);
  check(stage_guard.rule_seen&&stage_guard.holding,"successful add alone does not release writers");
  check(!v98_stage_restrict_result(&stage_guard,4,0,0),"wrong ruleset restrict cannot release");
  check(!v98_stage_restrict_result(&stage_guard,3,1,0),"unreviewed restrict flags cannot release");
  check(!v98_stage_restrict_result(&stage_guard,3,0,-1)&&stage_guard.holding,"failed restriction cannot release");
  check(v98_stage_restrict_result(&stage_guard,3,0,0)&&!stage_guard.holding,"only exact successful add plus restriction releases writers");
  check(!v98_stage_restrict_result(&stage_guard,3,0,0),"release cannot be replayed");
  const long namespace_changes[]={82,83,84,85,86,87,88,133,258,259,263,264,265,266,316};
  for(unsigned i=0;i<sizeof(namespace_changes)/sizeof(namespace_changes[0]);i++)
    check(v98_namespace_mutator(namespace_changes[i]),"stage alias/ancestor namespace mutations identified");
  check(!v98_namespace_mutator(1)&&!v98_namespace_mutator(74)&&!v98_namespace_mutator(202),"ordinary data writes/fsync/Worker futex retain behavior");
  check(filter_result(0x40000003,59)==0x80000000,"i386 ABI cannot enter x64 syscall policy");
  check(filter_result(0xc000003e,0x40000000|59)==0x80000000,"x32 syscall namespace denied");
  check(filter_result(0xc000003e,435)==0x00050026,"clone3 exact ENOSYS fallback");
  const unsigned forbidden[]={42,43,44,45,46,47,49,50,51,52,58,101,165,166,272,308,310,311,322,323,424,425,426,427,438};
  for(size_t i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);i++)
    check(filter_result(0xc000003e,forbidden[i])==0x00050001,"network/SCM/process_vm/namespace/async/execveat paths kernel denied");
  for(unsigned i=0;i<sizeof(v98_admitted_syscalls)/sizeof(v98_admitted_syscalls[0]);i++)
    check(filter_result(0xc000003e,v98_admitted_syscalls[i])==0x7ff00000,"every admitted syscall is traced, never unguarded ALLOW");
  check(filter_result(0xc000003e,999999)==0x00050001,"future syscall defaults denied");
  const char *stage=V98_STAGING_PREFIX "AbC123";
  const char *argv[]={V98_NODE,V98_WORKER,"--openclaw-sqlite-readonly-child","sync",V98_DATABASE,stage};
  check(v98_helper_argv(6,argv),"actual exact helper admitted");
  const char *bad[]={V98_NODE,"-e","process.exit(0)","sync",V98_DATABASE,stage};
  check(!v98_helper_argv(6,bad),"generic same-binary -e denied");
  for(size_t i=0;i<6;i++) {
    const char *changed[6];memcpy(changed,argv,sizeof(changed));changed[i]="attacker";
    check(!v98_helper_argv(6,changed),"every helper argument is authoritative");
  }
  check(!v98_helper_argv(5,argv),"truncated argv denied");
  check(!v98_helper_argv(7,argv),"extra argv denied before dereferencing");
  const char *stages[]={"/scratch/cache/openclaw/other-AbC123",V98_STAGING_PREFIX "abc12",V98_STAGING_PREFIX "abc1234",V98_STAGING_PREFIX "abc12/",V98_STAGING_PREFIX "abc12.",V98_STAGING_PREFIX "abc123/../outside","/outside/openclaw-sqlite-readonly-v2-AbC123"};
  for(size_t i=0;i<sizeof(stages)/sizeof(stages[0]);i++)check(!v98_staging_path(stages[i]),"path traversal and sibling staging denied");
  check(!v98_staging_path(NULL),"null staging denied");
  check(v98_exact_environment(V98_MAX_ENV,v98_environment),"exact launcher environment accepted");
  const char *env[V98_MAX_ENV];
  for(unsigned i=0;i<V98_MAX_ENV;i++)env[i]=v98_environment[V98_MAX_ENV-1-i];
  check(v98_exact_environment(V98_MAX_ENV,env),"environment ordering irrelevant");
  env[0]=v98_environment[0];check(!v98_exact_environment(V98_MAX_ENV,env),"duplicate replacing env key denied");
  memcpy(env,v98_environment,sizeof(env));env[0]="LD_PRELOAD=/scratch/evil.so";
  check(!v98_exact_environment(V98_MAX_ENV,env),"loader substitution denied");
  env[0]="NODE_OPTIONS=--require=/scratch/evil.cjs";
  check(!v98_exact_environment(V98_MAX_ENV,env),"Node option injection denied");
  check(!v98_exact_environment(V98_MAX_ENV-1,v98_environment),"missing environment denied");
  check(!v98_exact_environment(V98_MAX_ENV+1,v98_environment),"extra environment denied before dereferencing");
  check(v98_thread_flags(0x3d0f00),"pthread flags admitted");
  for(unsigned bit=0;bit<64;bit++)if(!(V98_THREAD_ALLOWED&(UINT64_C(1)<<bit)))
    check(!v98_thread_flags(V98_THREAD_REQUIRED|(UINT64_C(1)<<bit)),"every unknown/namespace/high clone bit denied");
  for(unsigned bit=0;bit<64;bit++)if(V98_THREAD_REQUIRED&(UINT64_C(1)<<bit))
    check(!v98_thread_flags(V98_THREAD_REQUIRED&~(UINT64_C(1)<<bit)),"non-thread shared-VM/FD clone denied");
  check(v98_process_flags(57,0),"ordinary fork syscall admitted for entitlement check");
  check(v98_process_flags(56,V98_FORK_CLONE),"exact glibc fork clone admitted");
  check(!v98_process_flags(58,0),"vfork denied");
  check(!v98_process_flags(56,0x4111),"shared-MM process clone denied");
  for(unsigned phase=0;phase<=6;phase++)for(unsigned role=0;role<=V98_HELPER;role++) {
    struct v98_entitlement e={.phase=phase};
    int allowed=v98_grant_fork(&e,(enum v98_role)role);
    check(allowed==(phase==3&&role==V98_PARENT),"only internal phase3 parent gets one helper");
    if(allowed)check(!v98_grant_fork(&e,V98_PARENT),"second helper denied including failed first exec");
  }
  struct v98_entitlement e={.phase=3,.helper_execs=1};
  check(!v98_grant_fork(&e,V98_PARENT),"exec entitlement cannot be recreated");
  check(v98_pair_request(3,V98_PARENT,1,0x80001,0),"exact anonymous CLOEXEC stdio pair admitted");
  check(!v98_pair_request(3,V98_HELPER,1,0x80001,0),"helper pair denied");
  check(!v98_pair_request(2,V98_PARENT,1,0x80001,0),"other phase pair denied");
  check(!v98_pair_request(3,V98_PARENT,2,0x80001,0),"INET pair denied");
  check(!v98_pair_request(3,V98_PARENT,1,1,0),"missing CLOEXEC denied");
  check(!v98_pair_request(3,V98_PARENT,1,0x80001,1),"nonzero protocol denied");
  struct v98_fds f={0};check(v98_pair_record(&f,4,5),"pair lifetime tracked");
  check(!v98_pair_record(&f,4,6),"FD alias/reuse without retirement denied");
  check(v98_socket_option(&f,4,1,7,4,65536),"exact send buffer option admitted");
  check(v98_socket_option(&f,5,1,8,4,65536),"exact receive buffer option admitted");
  check(!v98_socket_option(&f,6,1,7,4,65536),"unowned FD denied");
  check(!v98_socket_option(&f,4,1,7,4,65535),"borrowed option mutation denied");
  check(!v98_socket_option(&f,4,1,9,4,65536),"other socket option denied");
  check(!v98_socket_option(&f,4,2,7,4,65536),"other level denied");
  check(!v98_socket_option(&f,4,1,7,8,65536),"other option length denied");
  struct v98_fds copied=f;v98_fd_close(&f,4);
  check(!v98_fd_tracked(&f,4)&&v98_fd_tracked(&copied,4),"fork copies independent FD tables");
  check(!v98_fd_tracked(&f,-1),"retired negative FD never tracked");
  check(v98_pair_record(&f,4,6),"closed FD new pair accepted within lifetime budget");
  check(v98_pair_record(&f,7,8),"third pair accepted");
  check(!v98_pair_record(&f,9,10),"pair lifetime budget cannot reset after close");
  check(!v98_fd_duplicate(&copied,4,8),"tracked alias outside stdio denied");
  check(v98_fd_duplicate(&copied,4,1),"libuv stdio dup admitted");
  check(!v98_signal_target(20,1,9,21),"supervisor signals denied");
  check(!v98_signal_target(20,-1,9,21),"broadcast signal denied");
  check(v98_signal_target(20,21,9,21),"actual cancellation child kill retained");
  check(!v98_signal_target(21,20,9,21),"helper cannot kill parent");
  check(!v98_signal_target(20,99,9,21),"unknown process signal denied");
  digest("",0,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  digest("abc",1,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  digest("abc",2,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const char *long_message="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  for(unsigned i=0;i<57;i++)digest(long_message,i,"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  printf("{\"portablePolicyChecks\":%u,\"kernelActivation\":false,\"runtimeExecution\":false}\n",checks);
  return 0;
}
