#include "native-policy.h"
#include <string.h>

const char *const v98_environment[V98_MAX_ENV] = {
  "HOME=/scratch/home", "TMPDIR=/scratch/tmp", "XDG_CACHE_HOME=/scratch/cache",
  "PARITY_FIXTURE_SCRATCH_ROOT=/scratch", "NODE_DISABLE_COMPILE_CACHE=1",
  "LD_PRELOAD=/proof/runner/v98-confine.so", "LANG=C", "LC_ALL=C", "TZ=UTC",
  "NODE_OPTIONS=--max-old-space-size=128"
};

int v98_staging_path(const char *path) {
  const size_t n = sizeof(V98_STAGING_PREFIX) - 1;
  if (!path || strncmp(path, V98_STAGING_PREFIX, n) || strlen(path) != n + 6) return 0;
  for (size_t i = n; i < n + 6; i++) {
    unsigned char c = (unsigned char)path[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return 0;
  }
  return 1;
}

int v98_thread_flags(uint64_t flags) {
  return (flags & V98_THREAD_REQUIRED) == V98_THREAD_REQUIRED &&
         !(flags & ~V98_THREAD_ALLOWED);
}

int v98_process_flags(long syscall_number, uint64_t flags) {
  return syscall_number == 57 || (syscall_number == 56 && flags == V98_FORK_CLONE);
}

int v98_grant_fork(struct v98_entitlement *state, enum v98_role role) {
  if (state->phase != 3 || role != V98_PARENT || state->forks || state->helper_execs) return 0;
  state->forks = 1;
  return 1;
}

int v98_helper_argv(size_t argc, const char *const *argv) {
  return argc == 6 && !strcmp(argv[0], V98_NODE) && !strcmp(argv[1], V98_WORKER) &&
         !strcmp(argv[2], "--openclaw-sqlite-readonly-child") && !strcmp(argv[3], "sync") &&
         !strcmp(argv[4], V98_DATABASE) && v98_staging_path(argv[5]);
}

int v98_exact_environment(size_t count, const char *const *environment) {
  unsigned seen = 0;
  if (count != V98_MAX_ENV) return 0;
  for (size_t i = 0; i < count; i++) {
    unsigned j;
    for (j = 0; j < V98_MAX_ENV; j++) if (!strcmp(environment[i], v98_environment[j])) break;
    if (j == V98_MAX_ENV || (seen & (1u << j))) return 0;
    seen |= 1u << j;
  }
  return seen == (1u << V98_MAX_ENV) - 1;
}

int v98_pair_request(unsigned phase, enum v98_role role, uint64_t domain,
                     uint64_t type, uint64_t protocol) {
  return phase == 3 && role == V98_PARENT && domain == 1 && type == 0x80001 && protocol == 0;
}

int v98_fd_tracked(const struct v98_fds *fds, int fd) {
  if (fd < 0) return 0;
  for (unsigned i = 0; i < fds->created; i++)
    if (fds->pairs[i].a == fd || fds->pairs[i].b == fd) return 1;
  return 0;
}

int v98_pair_record(struct v98_fds *fds, int a, int b) {
  if (a < 3 || b < 3 || a == b || fds->created >= V98_MAX_PAIRS ||
      v98_fd_tracked(fds, a) || v98_fd_tracked(fds, b)) return 0;
  fds->pairs[fds->created++] = (struct v98_pair){.a=a,.b=b};
  return 1;
}

void v98_fd_close(struct v98_fds *fds, int fd) {
  for (unsigned i = 0; i < fds->created; i++) {
    if (fds->pairs[i].a == fd) fds->pairs[i].a = -1;
    if (fds->pairs[i].b == fd) fds->pairs[i].b = -1;
  }
}

int v98_fd_duplicate(struct v98_fds *fds, int oldfd, int newfd) {
  int tracked = v98_fd_tracked(fds, oldfd);
  if (oldfd == newfd) return 1;
  v98_fd_close(fds, newfd);
  /* Only stdio duplication is needed by the forked libuv child. Refuse other
   * aliases rather than silently losing generation accounting. */
  if (tracked && (newfd < 0 || newfd > 2)) return 0;
  return 1;
}

int v98_socket_option(const struct v98_fds *fds, int fd, uint64_t level,
                      uint64_t option, uint64_t length, int value) {
  return v98_fd_tracked(fds, fd) && level == 1 && (option == 7 || option == 8) &&
         length == sizeof(int) && value == 65536;
}

int v98_stdio_query_request(const struct v98_fds *fds, uint64_t fd, long nr,
                            uint64_t level, uint64_t option, uint32_t length,
                            uint64_t device, uint64_t inode) {
  if (!fds || fds->created != V98_MAX_PAIRS || fd > 2 || !inode) return 0;
  /* libuv creates pipes in stdio order and dup2s each pipes[fd][1] into fd.
   * Numeric endpoint descriptors retire at exec; their inode bindings remain. */
  const struct v98_pair *p = &fds->pairs[fd];
  if (device != p->b_device || inode != p->b_inode) return 0;
  if (nr == 51) return length == 128;
  return nr == 55 && level == 1 && option == 3 && length == 4;
}

int v98_stdio_query_result(long nr, long result, uint32_t length, int value) {
  if (result != 0) return 0;
  return (nr == 51 && length == 2 && value == 1) ||
         (nr == 55 && length == 4 && value == 1);
}

int v98_signal_target(int source_tgid, int target_tgid, int signal_number,
                      int owned_helper_tgid) {
  if (target_tgid <= 1 || source_tgid <= 1) return 0;
  if (target_tgid == source_tgid) return signal_number == 0 || signal_number == 6 ||
    signal_number == 10 || signal_number == 12 || signal_number == 23;
  return target_tgid == owned_helper_tgid && owned_helper_tgid > 1 &&
         (signal_number == 0 || signal_number == 9 || signal_number == 15);
}

int v98_namespace_mutator(long nr) {
  switch(nr) {
    case 82:case 83:case 84:case 85:case 86:case 87:case 88:case 133:
    case 258:case 259:case 263:case 264:case 265:case 266:case 316:return 1;
    default:return 0;
  }
}
int v98_canonical_syscall(uint64_t number) {
  return number<UINT64_C(0x40000000);
}

int v98_stage_directory(uint32_t mode,uint32_t uid) {
  return (mode&0177777u)==0040700u&&uid==1000;
}
int v98_stage_token_entry(const char *name,uint32_t mode,uint32_t uid,uint64_t links) {
  static const char *const names[]={"owner.sqlite","owner.sqlite-journal","owner.sqlite-wal","owner.sqlite-shm"};
  if((mode&0170000u)!=0100000u||uid!=1000||links!=1)return 0;
  for(unsigned i=0;i<4;i++)if(!strcmp(name,names[i]))return 1;
  return 0;
}
void v98_stage_begin(struct v98_stage_guard *g,uint64_t device,uint64_t inode) {
  *g=(struct v98_stage_guard){.device=device,.inode=inode,.ruleset_fd=-1,.holding=1};
}
int v98_stage_add_request(struct v98_stage_guard *g,int fd,uint64_t rights,
                          uint64_t device,uint64_t inode,uint32_t mode,uint32_t uid) {
  g->add_pending=0;
  if(!g->holding||fd<0||fd!=g->ruleset_fd)return 0;
  if(rights==4)return (mode&0170000u)==0100000u;
  if(rights!=32766||g->rule_seen||device!=g->device||inode!=g->inode||!v98_stage_directory(mode,uid))return 0;
  g->add_pending=1;return 1;
}
void v98_stage_add_result(struct v98_stage_guard *g,long result) {
  if(result==0&&g->add_pending)g->rule_seen=1;
  g->add_pending=0;
}
int v98_stage_restrict_request(const struct v98_stage_guard *g,int fd,uint64_t flags) {
  return g->holding&&g->rule_seen&&fd>=0&&fd==g->ruleset_fd&&flags==0;
}
int v98_stage_restrict_result(struct v98_stage_guard *g,int fd,uint64_t flags,long result) {
  if(result!=0||!v98_stage_restrict_request(g,fd,flags))return 0;
  g->holding=0;return 1;
}
