/* SOURCE ONLY: unbuilt/unqualified Linux x86-64 freestanding entry.
 * No headers, libc, loader, constructors, environment startup or other program.
 * The reviewed build must independently prove those properties in the ELF.
 */
typedef unsigned long usize;
typedef long isize;

#if !defined(__linux__) || !defined(__x86_64__)
#error "Only the separately qualified Linux x86-64 target is supported"
#endif

static isize syscall3(isize number, isize a, isize b, isize c) {
    isize result;
    __asm__ volatile ("syscall" : "=a"(result)
                      : "a"(number), "D"(a), "S"(b), "d"(c)
                      : "rcx", "r11", "memory");
    return result;
}

__attribute__((noreturn)) static void stop(const char *message, usize length) {
    /* Only fixed codes. No caller string, assignment name or value is emitted. */
    (void)syscall3(1, 2, (isize)message, (isize)length);
    (void)syscall3(60, 111, 0, 0);
    for (;;) __asm__ volatile ("ud2");
}

static usize bounded_length(const char *value, usize cap) {
    usize n = 0;
    if (!value) return cap + 1;
    while (n <= cap && value[n]) n++;
    return n;
}

static int equal(const char *a, const char *b) {
    usize n = 0;
    while (a[n] && b[n] && a[n] == b[n]) n++;
    return a[n] == 0 && b[n] == 0;
}

static int lower_hex(const char *value, usize count) {
    usize i;
    for (i = 0; i < count; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    return value[count] == 0;
}

static int name_valid(const char *name) {
    return bounded_length(name, 28) == 28 && name[0] == 'o' &&
           name[1] == 'c' && name[2] == 'v' && name[3] == '-' &&
           lower_hex(name + 4, 24);
}

static int key_equal(const char *assignment, usize key_length, const char *key) {
    usize i = 0;
    while (key[i]) { if (i >= key_length || assignment[i] != key[i]) return 0; i++; }
    return i == key_length;
}

static int pid_equal(const char *value, isize pid) {
    usize i = 0, number = 0;
    if (pid <= 0 || pid > 2147483647 || value[0] < '1' || value[0] > '9') return 0;
    while (value[i]) {
        if (i >= 10 || value[i] < '0' || value[i] > '9') return 0;
        number = number * 10 + (usize)(value[i] - '0');
        if (number > 2147483647) return 0;
        i++;
    }
    return number == (usize)pid;
}

/* Fixed labels only: never print an argument, environment key, or value. */
#define REFUSE(label) stop("entry_refused_" label "\n", sizeof("entry_refused_" label "\n") - 1)

__attribute__((noreturn, used, visibility("hidden")))
void entry_main(usize *stack) {
    static const char exec_failure[] = "entry_exec_failed\n";
    static const char *keys[] = {"PATH", "LANG", "LC_ALL", "HOME", "SHELL", "USER", "LOGNAME", "INVOCATION_ID", "SYSTEMD_EXEC_PID"};
    static const char *fixed[] = {"/usr/bin", "C", "C", "/", "/nonexistent"};
    char *arguments[] = {"/usr/bin/python3.11", "-I", "-S", "-B", "/code/worker.py", (char *)0};
    char *environment[] = {"PATH=/usr/bin", "LANG=C", "LC_ALL=C", "HOME=/", (char *)0};
    usize argc = stack[0], i, total = 0, seen = 0;
    char **argv = (char **)(stack + 1), **env;
    isize pid;
    if (argc != 2 || argv[2] != (char *)0 ||
        !argv[0] || bounded_length(argv[0], 64) > 64 ||
        !equal(argv[0], "/code/static-entry") || !name_valid(argv[1]))
        REFUSE("args");
    pid = syscall3(39, 0, 0, 0); /* Actual PID, never an inherited claim. */
    if (pid <= 0 || pid > 2147483647) REFUSE("pid");
    env = argv + argc + 1;
    for (i = 0; i < 16 && env[i]; i++) {
        usize length = bounded_length(env[i], 511), k = 0, which;
        const char *value;
        if (length > 511 || length == 0 || total + length + 1 > 8192)
            REFUSE("env_bounds");
        total += length + 1; /* Bounds include each terminating NUL. */
        while (k < length && env[i][k] != '=') k++;
        if (k == 0 || k == length) REFUSE("env_syntax");
        for (which = 0; which < 9 && !key_equal(env[i], k, keys[which]); which++);
        if (which == 9) {
            /* Diagnostic classifications remain fixed refusals; key and value are never emitted. */
            if (key_equal(env[i], k, "MEMORY_PRESSURE_WATCH")) REFUSE("unknown_key_memory_pressure_watch");
            if (key_equal(env[i], k, "MEMORY_PRESSURE_WRITE")) REFUSE("unknown_key_memory_pressure_write");
            if (key_equal(env[i], k, "JOURNAL_STREAM")) REFUSE("unknown_key_journal_stream");
            if (key_equal(env[i], k, "NOTIFY_SOCKET")) REFUSE("unknown_key_notify_socket");
            if (key_equal(env[i], k, "WATCHDOG_USEC")) REFUSE("unknown_key_watchdog_usec");
            if (key_equal(env[i], k, "WATCHDOG_PID")) REFUSE("unknown_key_watchdog_pid");
            if (key_equal(env[i], k, "CREDENTIALS_DIRECTORY")) REFUSE("unknown_key_credentials_directory");
            if (key_equal(env[i], k, "RUNTIME_DIRECTORY")) REFUSE("unknown_key_runtime_directory");
            if (key_equal(env[i], k, "STATE_DIRECTORY")) REFUSE("unknown_key_state_directory");
            if (key_equal(env[i], k, "CACHE_DIRECTORY")) REFUSE("unknown_key_cache_directory");
            if (key_equal(env[i], k, "LOGS_DIRECTORY")) REFUSE("unknown_key_logs_directory");
            if (key_equal(env[i], k, "CONFIGURATION_DIRECTORY")) REFUSE("unknown_key_configuration_directory");
            if (key_equal(env[i], k, "LISTEN_FDS")) REFUSE("unknown_key_listen_fds");
            if (key_equal(env[i], k, "LISTEN_PID")) REFUSE("unknown_key_listen_pid");
            if (key_equal(env[i], k, "LISTEN_FDNAMES")) REFUSE("unknown_key_listen_fdnames");
            if (key_equal(env[i], k, "XDG_RUNTIME_DIR")) REFUSE("unknown_key_xdg_runtime_dir");
            if (key_equal(env[i], k, "TERM")) REFUSE("unknown_key_term");
            if (key_equal(env[i], k, "FDSTORE")) REFUSE("unknown_key_fdstore");
            if (key_equal(env[i], k, "LANGUAGE")) REFUSE("unknown_key_language");
            if (key_equal(env[i], k, "LC_CTYPE")) REFUSE("unknown_key_lc_ctype");
            if (key_equal(env[i], k, "LC_NUMERIC")) REFUSE("unknown_key_lc_numeric");
            if (key_equal(env[i], k, "LC_TIME")) REFUSE("unknown_key_lc_time");
            if (key_equal(env[i], k, "LC_COLLATE")) REFUSE("unknown_key_lc_collate");
            if (key_equal(env[i], k, "LC_MONETARY")) REFUSE("unknown_key_lc_monetary");
            if (key_equal(env[i], k, "LC_MESSAGES")) REFUSE("unknown_key_lc_messages");
            if (key_equal(env[i], k, "LC_PAPER")) REFUSE("unknown_key_lc_paper");
            if (key_equal(env[i], k, "LC_NAME")) REFUSE("unknown_key_lc_name");
            if (key_equal(env[i], k, "LC_ADDRESS")) REFUSE("unknown_key_lc_address");
            if (key_equal(env[i], k, "LC_TELEPHONE")) REFUSE("unknown_key_lc_telephone");
            if (key_equal(env[i], k, "LC_MEASUREMENT")) REFUSE("unknown_key_lc_measurement");
            if (key_equal(env[i], k, "LC_IDENTIFICATION")) REFUSE("unknown_key_lc_identification");
            if (key_equal(env[i], k, "LOG_NAMESPACE")) REFUSE("unknown_key_log_namespace");
            if (key_equal(env[i], k, "SERVICE_RESULT")) REFUSE("unknown_key_service_result");
            if (key_equal(env[i], k, "EXIT_CODE")) REFUSE("unknown_key_exit_code");
            if (key_equal(env[i], k, "EXIT_STATUS")) REFUSE("unknown_key_exit_status");
            if (key_equal(env[i], k, "MONITOR_SERVICE_RESULT")) REFUSE("unknown_key_monitor_service_result");
            if (key_equal(env[i], k, "MONITOR_EXIT_CODE")) REFUSE("unknown_key_monitor_exit_code");
            if (key_equal(env[i], k, "MONITOR_EXIT_STATUS")) REFUSE("unknown_key_monitor_exit_status");
            if (key_equal(env[i], k, "MONITOR_INVOCATION_ID")) REFUSE("unknown_key_monitor_invocation_id");
            if (key_equal(env[i], k, "MONITOR_UNIT")) REFUSE("unknown_key_monitor_unit");
            if (key_equal(env[i], k, "PIDFILE")) REFUSE("unknown_key_pidfile");
            if (key_equal(env[i], k, "REMOTE_ADDR")) REFUSE("unknown_key_remote_addr");
            if (key_equal(env[i], k, "REMOTE_PORT")) REFUSE("unknown_key_remote_port");
            if (key_equal(env[i], k, "TRIGGER_UNIT")) REFUSE("unknown_key_trigger_unit");
            if (key_equal(env[i], k, "TRIGGER_PATH")) REFUSE("unknown_key_trigger_path");
            if (key_equal(env[i], k, "TRIGGER_TIMER_REALTIME_USEC")) REFUSE("unknown_key_trigger_timer_realtime_usec");
            if (key_equal(env[i], k, "TRIGGER_TIMER_MONOTONIC_USEC")) REFUSE("unknown_key_trigger_timer_monotonic_usec");
            if (key_equal(env[i], k, "XDG_SEAT")) REFUSE("unknown_key_xdg_seat");
            if (key_equal(env[i], k, "XDG_VTNR")) REFUSE("unknown_key_xdg_vtnr");
            if (key_equal(env[i], k, "TZ")) REFUSE("unknown_key_tz");
            if (key_equal(env[i], k, "PWD")) REFUSE("unknown_key_pwd");
            if (key_equal(env[i], k, "TMPDIR")) REFUSE("unknown_key_tmpdir");
            if (key_equal(env[i], k, "SHLVL")) REFUSE("unknown_key_shlvl");
            if (key_equal(env[i], k, "container")) REFUSE("unknown_key_container");
            if (key_equal(env[i], k, "DEBIAN_FRONTEND")) REFUSE("unknown_key_debian_frontend");
            if (key_equal(env[i], k, "SYSTEMD_LOG_LEVEL")) REFUSE("unknown_key_systemd_log_level");
            if (key_equal(env[i], k, "SYSTEMD_LOG_TARGET")) REFUSE("unknown_key_systemd_log_target");
            if (key_equal(env[i], k, "SYSTEMD_COLORS")) REFUSE("unknown_key_systemd_colors");
            if (key_equal(env[i], k, "SYSTEMD_URLIFY")) REFUSE("unknown_key_systemd_urlify");
            if (key_equal(env[i], k, "SYSTEMD_LOG_TIME")) REFUSE("unknown_key_systemd_log_time");
            if (key_equal(env[i], k, "SYSTEMD_LOG_LOCATION")) REFUSE("unknown_key_systemd_log_location");
            if (key_equal(env[i], k, "CI")) REFUSE("unknown_key_ci");
            if (key_equal(env[i], k, "GITHUB_ACTIONS")) REFUSE("unknown_key_github_actions");
            if (key_equal(env[i], k, "SYSTEMD_ACTIVATION_UNIT")) REFUSE("unknown_key_systemd_activation_unit");
            if (key_equal(env[i], k, "SYSTEMD_ACTIVATION_SCOPE")) REFUSE("unknown_key_systemd_activation_scope");
            REFUSE("unknown_key");
        }
        if (seen & ((usize)1 << which)) REFUSE("duplicate_key");
        seen |= (usize)1 << which;
        value = env[i] + k + 1;
        if ((which < 5 && !equal(value, fixed[which])) ||
            ((which == 5 || which == 6) && !equal(value, argv[1])) ||
            (which == 7 && (bounded_length(value, 32) != 32 || !lower_hex(value, 32))) ||
            (which == 8 && !pid_equal(value, pid))) {
            switch (which) {
            case 0: REFUSE("value_path");
            case 1: REFUSE("value_lang");
            case 2: REFUSE("value_lc_all");
            case 3: REFUSE("value_home");
            case 4: REFUSE("value_shell");
            case 5: REFUSE("value_user");
            case 6: REFUSE("value_logname");
            case 7: REFUSE("value_invocation_id");
            case 8: REFUSE("value_exec_pid");
            default: REFUSE("value_unknown");
            }
        }
    }
    if (env[i]) REFUSE("env_count");
    if ((seen & 127) != 127) REFUSE("missing_required");
    (void)syscall3(59, (isize)arguments[0], (isize)arguments, (isize)environment);
    stop(exec_failure, sizeof(exec_failure) - 1);
}

/* Linux amd64 initial stack, no libc/crt invocation. Stack is aligned for call;
 * initial stack address is passed separately before the alignment operation.
 */
__asm__(".global _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "xor %rbp,%rbp\n"
        "mov %rsp,%rdi\n"
        "and $-16,%rsp\n"
        "call entry_main\n"
        "ud2\n"
        ".size _start,.-_start\n");
