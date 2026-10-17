/* Candidate only: never compile/load/run this guard on the Mac.
 * Linux AMD64 LD_PRELOAD constructor + fixed-probe Node N-API module.
 * Production build requires the pinned Linux public image and its Node headers.
 * Syntax-only host checks do not establish kernel or confinement qualification.
 */
#define _GNU_SOURCE 1
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdatomic.h>
#include <node_api.h>

#if defined(V98_SYNTAX_ONLY)
/* Layout checks can run on macOS without interpreting its syscall numbers as
 * Linux. This build is deliberately impossible to activate. */
#define V98_PRODUCTION 0
static long linux_call(long n, long a, long b, long c, long d, long e, long f) {
  (void)n; (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
  errno = ENOSYS;
  return -1;
}
#elif defined(__linux__) && defined(__x86_64__)
#define V98_PRODUCTION 1
#include <sys/prctl.h>
static long linux_call(long n, long a, long b, long c, long d, long e, long f) {
  return syscall(n, a, b, c, d, e, f);
}
#else
#error "Guard activation supports only reviewed Linux AMD64; use syntax-only elsewhere"
#endif

struct v98_sock_filter { uint16_t code; uint8_t jt, jf; uint32_t k; };
struct v98_sock_fprog { uint16_t len; struct v98_sock_filter *filter; };
struct v98_ruleset { uint64_t handled_access_fs; };
struct __attribute__((packed)) v98_path_rule { uint64_t allowed_access; int32_t parent_fd; };
_Static_assert(sizeof(struct v98_sock_filter) == 8, "BPF ABI");
_Static_assert(sizeof(struct v98_path_rule) == 12, "Landlock ABI");
_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8, "64-bit ABI");
_Static_assert(offsetof(struct v98_sock_fprog, filter) == 8, "BPF program ABI");
#include "policy.generated.h"

#define LL_READ ((1ULL << 2) | (1ULL << 3))
#define LL_FILE_READ (1ULL << 2)
#define LL_FILE_WRITE (1ULL << 1)
/* Include every filesystem right in ABI3 as handled, including EXECUTE, while
 * granting no EXECUTE, socket/FIFO/device creation anywhere. */
#define LL_HANDLED ((1ULL << 15) - 1)
#define LL_SCRATCH (LL_READ | LL_FILE_WRITE | (1ULL << 4) | (1ULL << 5) | \
                    (1ULL << 7) | (1ULL << 8) | (1ULL << 12) | (1ULL << 13) | (1ULL << 14))
#define O_LINUX_PATH 010000000
#define O_LINUX_CLOEXEC 02000000
#define POLICY_ID "v98-linux-amd64-strict-v2"

static int installed = 0;
static pid_t original_pid = -1;
static pid_t original_parent = -1;
static atomic_int addon_initialized = ATOMIC_VAR_INIT(0);
_Noreturn static void refuse(void) {
  /* Public constant only. Do not emit errno, environment, argv, or paths. */
  static const char message[] = "V98_GUARD_REFUSED\n";
  (void)write(2, message, sizeof(message) - 1);
  _Exit(125);
}

static int pipe_fd(int fd, int mode) {
  struct stat st;
  int flags = fcntl(fd, F_GETFL);
  return flags >= 0 && (flags & O_ACCMODE) == mode &&
         fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode);
}

static int single_thread(void) {
  DIR *tasks = opendir("/proc/self/task");
  if (!tasks) return 0;
  unsigned count = 0;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(tasks))) {
    if (entry->d_name[0] != '.') count++;
  }
  int good = errno == 0 && count == 1;
  if (closedir(tasks)) good = 0;
  return good;
}

static int add_path(int ruleset, const char *path, uint64_t access, int optional) {
  int fd = (int)linux_call(257, -100, (long)path,
                         O_LINUX_PATH | O_LINUX_CLOEXEC, 0, 0, 0);
  if (fd < 0) return optional && errno == ENOENT;
  struct v98_path_rule rule = {access, fd};
  int rc = (int)linux_call(445, ruleset, 1, (long)&rule, 0, 0, 0);
  int close_rc = close(fd);
  return rc == 0 && close_rc == 0;
}

static int install_landlock(void) {
  int abi = (int)linux_call(444, 0, 0, 1, 0, 0, 0);
  if (abi < 3) return -1;
  struct v98_ruleset attr = {LL_HANDLED};
  int fd = (int)linux_call(444, (long)&attr, sizeof(attr), 0, 0, 0, 0);
  if (fd < 0) return -1;
  /* The original supervisor must independently verify these mounts are public
   * and read-only. No host/home/config/database/socket mount is admissible. */
  int ok = add_path(fd, "/usr", LL_READ, 0) &&
           add_path(fd, "/lib", LL_READ, 0) &&
           add_path(fd, "/lib64", LL_READ, 1) &&
           add_path(fd, "/app", LL_READ, 0) &&
           add_path(fd, "/proof", LL_READ, 0) &&
           add_path(fd, "/etc/ld.so.cache", LL_FILE_READ, 1) &&
           add_path(fd, "/etc/localtime", LL_FILE_READ, 1) &&
           add_path(fd, "/dev/null", LL_FILE_READ | LL_FILE_WRITE, 0) &&
           add_path(fd, "/dev/urandom", LL_FILE_READ, 0) &&
           add_path(fd, "/v98-scratch", LL_SCRATCH, 0);
  if (ok) ok = linux_call(446, fd, 0, 0, 0, 0, 0) == 0;
  if (close(fd)) ok = 0;
  return ok ? abi : -1;
}

static int install_seccomp(void) {
  struct v98_sock_fprog program = {
    (uint16_t)(sizeof(v98_filter) / sizeof(v98_filter[0])),
    (struct v98_sock_filter *)v98_filter
  };
  /* seccomp(SECCOMP_SET_MODE_FILTER, TSYNC, program); exact zero only. */
  return linux_call(317, 1, 1, (long)&program, 0, 0, 0) == 0;
}

/* Parent0 is a valid namespace view for PID1 when the real parent is outside
 * the private PID namespace. Only the external original supervisor can bind
 * that view to the actual owned host-runc/init chain before releasing G. */
static int supervisory_state(void) {
  int death_signal = 0;
  return V98_PRODUCTION && installed && getpid() == original_pid &&
    getppid() == original_parent && getuid() == 1000 && geteuid() == 1000 &&
    getgid() == 1000 && getegid() == 1000 &&
    linux_call(157, 2, (long)&death_signal, 0, 0, 0, 0) == 0 && death_signal == SIGKILL &&
    linux_call(157, 21, 0, 0, 0, 0, 0) == 2 &&
    linux_call(157, 39, 0, 0, 0, 0, 0) == 1;
}

__attribute__((constructor)) static void guard_entry(void) {
  if (!V98_PRODUCTION) refuse();
  if (getuid() != 1000 || geteuid() != 1000 || getgid() != 1000 || getegid() != 1000)
    refuse();
  original_pid = getpid();
  original_parent = getppid();
  if (original_pid <= 0 || original_parent < 0 ||
      linux_call(157, 1, SIGKILL, 0, 0, 0, 0) != 0 || getppid() != original_parent)
    refuse();
  if (!pipe_fd(3, O_WRONLY) || !pipe_fd(4, O_RDONLY)) refuse();
  /* Remove all ambient descriptors before restrictions. fd0..2 and fd3/4 must
   * already have exact ownership/type/content admission by the supervisor. */
  if (linux_call(436, 5, ~0U, 0, 0, 0, 0) != 0 || !single_thread()) refuse();
  struct rlimit cpu = {30, 30}, core = {0, 0};
  if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core)) refuse();
  if (signal(SIGALRM, SIG_DFL) == SIG_ERR || alarm(60) != 0) refuse();
  /* PR_SET_NO_NEW_PRIVS = 38. Never relax a pre-existing policy. */
  if (linux_call(157, 38, 1, 0, 0, 0, 0)) refuse();
  int abi = install_landlock();
  if (abi < 3 || !install_seccomp()) refuse();
  installed = 1;
  if (!supervisory_state()) refuse();
  char receipt[768];
  int n = snprintf(receipt, sizeof(receipt),
    "{\"schema\":\"v98.guard-install.v2\",\"status\":\"INSTALLED\","
    "\"stage\":\"constructor-before-node-main\",\"policyId\":\"%s\","
    "\"pid\":%ld,\"uid\":1000,\"landlockAbi\":%d,\"parentPid\":%ld,"
    "\"parentDeathSignal\":9,\"parentDeathSignalInstalled\":true,"
    "\"noNewPrivileges\":true,\"landlockInstalled\":true,"
    "\"seccompInstalled\":true,\"seccompTsync\":true,\"singleThreadAtInstall\":true}\n",
    POLICY_ID, (long)getpid(), abi, (long)original_parent);
  /* PIPE_BUF-sized write on original supervisor-owned channel. */
  if (n <= 0 || (size_t)n >= sizeof(receipt) || write(3, receipt, (size_t)n) != n || close(3))
    refuse();
  /* Hold before Node main until the original supervisor has verified FD3 and
   * independently measured the boundary. The following bounded JSON remains
   * for the fixture's FD4 transport. Missing/EOF/wrong release fails closed. */
  char release = 0;
  if (read(4, &release, 1) != 1 || release != 'G') refuse();
  if (!supervisory_state()) refuse();
}

#if V98_PRODUCTION
/* vfork child path uses only inlined raw syscalls: no libc call, allocation,
 * shared-stack return, JS callback or unknown data. Unexpected success is fatal
 * qualification failure, never converted into an allowed result. */
__attribute__((always_inline)) static inline long raw3(long nr, long a, long b, long c) {
  long result;
  __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return result;
}
#endif

static long attempted_process(int nr) {
#if V98_PRODUCTION
  static const char marker[] = "V98_FORBIDDEN_CHILD\n";
  long value = raw3(nr, 0, 0, 0);
  if (value == 0) {
    (void)raw3(1, 2, (long)marker, sizeof(marker) - 1);
    (void)raw3(231, 91, 0, 0);
    __builtin_unreachable();
  }
  if (value < 0) { errno = (int)-value; return -1; }
  int status = 0;
  if (waitpid((pid_t)value, &status, 0) != value) refuse();
  return value;
#else
  (void)nr;
  refuse();
  return -1;
#endif
}

static napi_value fixed_probe(napi_env env, napi_callback_info info) {
  if (!supervisory_state()) refuse();
  size_t count = 1, length = 0;
  napi_value argv[1], result, value;
  char name[24];
  if (napi_get_cb_info(env, info, &count, argv, NULL, NULL) != napi_ok || count != 1 ||
      napi_get_value_string_utf8(env, argv[0], name, sizeof(name), &length) != napi_ok ||
      length >= sizeof(name) - 1) {
    napi_throw_type_error(env, "V98_PROBE", "fixed public probe required");
    return NULL;
  }
  long rc;
  errno = 0;
  if (!strcmp(name, "fork")) rc = attempted_process(57);
  else if (!strcmp(name, "vfork")) rc = attempted_process(58);
  else if (!strcmp(name, "socketInet4")) rc = linux_call(41, 2, 1, 0, 0, 0, 0);
  else if (!strcmp(name, "socketInet6")) rc = linux_call(41, 10, 1, 0, 0, 0, 0);
  else if (!strcmp(name, "socketUnix")) rc = linux_call(41, 1, 1, 0, 0, 0, 0);
  else if (!strcmp(name, "execveat")) {
    int fd = open("/usr/local/bin/node", O_RDONLY);
    if (fd < 0) { napi_throw_error(env, "V98_PROBE", "public target unavailable"); return NULL; }
    char *const args[] = {"/usr/local/bin/node", "-e", "process.stderr.write('V98_FORBIDDEN_EXEC\\n');process.exit(91)", NULL};
    char *const clean_env[] = {"LANG=C", "TZ=UTC", NULL};
    rc = linux_call(322, fd, (long)"", (long)args, (long)clean_env, 0x1000, 0);
    int saved = errno;
    if (close(fd)) refuse();
    errno = saved;
  } else {
    napi_throw_type_error(env, "V98_PROBE", "unknown fixed probe");
    return NULL;
  }
  int saved = rc < 0 ? errno : 0;
  if (rc >= 0 && (!strcmp(name, "socketInet4") || !strcmp(name, "socketInet6") || !strcmp(name, "socketUnix")))
    if (close((int)rc)) refuse();
  if (napi_create_object(env, &result) != napi_ok ||
      napi_get_boolean(env, 1, &value) != napi_ok ||
      napi_set_named_property(env, result, "attempted", value) != napi_ok ||
      napi_get_boolean(env, rc >= 0, &value) != napi_ok ||
      napi_set_named_property(env, result, "returned", value) != napi_ok ||
      napi_create_int32(env, saved, &value) != napi_ok ||
      napi_set_named_property(env, result, "errno", value) != napi_ok) refuse();
  return result;
}

static napi_value assert_supervisor(napi_env env, napi_callback_info info) {
  size_t count = 1;
  napi_value argument, result;
  if (napi_get_cb_info(env, info, &count, &argument, NULL, NULL) != napi_ok || count != 0 ||
      !supervisory_state() || napi_get_undefined(env, &result) != napi_ok) refuse();
  return result;
}

NAPI_MODULE_INIT() {
  napi_value probe, assertion;
  if (!supervisory_state() ||
      atomic_exchange_explicit(&addon_initialized, 1, memory_order_acq_rel)) refuse();
  if (napi_create_function(env, "fixedProbe", NAPI_AUTO_LENGTH, fixed_probe, NULL, &probe) != napi_ok ||
      napi_set_named_property(env, exports, "fixedProbe", probe) != napi_ok ||
      napi_create_function(env, "assertSupervisor", NAPI_AUTO_LENGTH, assert_supervisor, NULL, &assertion) != napi_ok ||
      napi_set_named_property(env, exports, "assertSupervisor", assertion) != napi_ok) refuse();
  return exports;
}
