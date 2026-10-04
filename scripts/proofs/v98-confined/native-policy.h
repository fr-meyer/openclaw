#ifndef V98_NATIVE_POLICY_H
#define V98_NATIVE_POLICY_H
#include <stddef.h>
#include <stdint.h>

#define V98_NODE "/usr/local/bin/node"
#define V98_WORKER "/app/dist/infra/sqlite-readonly-location.worker.js"
#define V98_FIXTURE "/proof/inputs/fixture.mjs"
#define V98_DATABASE "/scratch/synthetic-parity-fixture/candidate/state/openclaw.sqlite"
#define V98_STAGING_PREFIX "/scratch/cache/openclaw/openclaw-sqlite-readonly-v2-"
#define V98_MAX_TASKS 128
#define V98_MAX_PAIRS 3
#define V98_MAX_ARGV 12
#define V98_MAX_ENV 10
#define V98_STRING_BYTES 4096
#define V98_THREAD_REQUIRED UINT64_C(0x10f00)
#define V98_THREAD_ALLOWED UINT64_C(0x13d0f00)
#define V98_FORK_CLONE UINT64_C(0x1200011)

enum v98_role { V98_BOOTSTRAP, V98_PARENT, V98_PENDING_HELPER, V98_HELPER };
struct v98_entitlement { unsigned phase; unsigned forks; unsigned helper_execs; };
struct v98_pair { int a, b; uint64_t a_device,a_inode,b_device,b_inode; };
struct v98_fds { struct v98_pair pairs[V98_MAX_PAIRS]; unsigned created; uint64_t generation; int owner_tgid; };
struct v98_stage_guard { uint64_t device,inode; int ruleset_fd,holding,add_pending,rule_seen; };

extern const char *const v98_environment[V98_MAX_ENV];
int v98_staging_path(const char *path);
int v98_thread_flags(uint64_t flags);
int v98_process_flags(long syscall_number, uint64_t flags);
int v98_grant_fork(struct v98_entitlement *state, enum v98_role role);
int v98_helper_argv(size_t argc, const char *const *argv);
int v98_exact_environment(size_t count, const char *const *environment);
int v98_pair_request(unsigned phase, enum v98_role role, uint64_t domain,
                     uint64_t type, uint64_t protocol);
int v98_fd_tracked(const struct v98_fds *fds, int fd);
int v98_pair_record(struct v98_fds *fds, int a, int b);
void v98_fd_close(struct v98_fds *fds, int fd);
int v98_fd_duplicate(struct v98_fds *fds, int oldfd, int newfd);
int v98_socket_option(const struct v98_fds *fds, int fd, uint64_t level,
                      uint64_t option, uint64_t length, int value);
int v98_signal_target(int source_tgid, int target_tgid, int signal_number,
                      int owned_helper_tgid);
int v98_namespace_mutator(long syscall_number);
int v98_canonical_syscall(uint64_t number);
int v98_stage_directory(uint32_t mode,uint32_t uid);
int v98_stage_token_entry(const char *name,uint32_t mode,uint32_t uid,uint64_t links);
void v98_stage_begin(struct v98_stage_guard *guard,uint64_t device,uint64_t inode);
int v98_stage_add_request(struct v98_stage_guard *guard,int ruleset_fd,uint64_t rights,
                          uint64_t device,uint64_t inode,uint32_t mode,uint32_t uid);
void v98_stage_add_result(struct v98_stage_guard *guard,long result);
int v98_stage_restrict_request(const struct v98_stage_guard *guard,int ruleset_fd,uint64_t flags);
int v98_stage_restrict_result(struct v98_stage_guard *guard,int ruleset_fd,uint64_t flags,long result);
#endif
