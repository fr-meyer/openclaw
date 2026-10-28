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

__attribute__((noreturn, used, visibility("hidden")))
void entry_main(usize *stack) {
    static const char refusal[] = "entry_refused\n";
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
        stop(refusal, sizeof(refusal) - 1);
    pid = syscall3(39, 0, 0, 0); /* Actual PID, never an inherited claim. */
    if (pid <= 0 || pid > 2147483647) stop(refusal, sizeof(refusal) - 1);
    env = argv + argc + 1;
    for (i = 0; i < 16 && env[i]; i++) {
        usize length = bounded_length(env[i], 511), k = 0, which;
        const char *value;
        if (length > 511 || length == 0 || total + length + 1 > 8192)
            stop(refusal, sizeof(refusal) - 1);
        total += length + 1; /* Bounds include each terminating NUL. */
        while (k < length && env[i][k] != '=') k++;
        if (k == 0 || k == length) stop(refusal, sizeof(refusal) - 1);
        for (which = 0; which < 9 && !key_equal(env[i], k, keys[which]); which++);
        if (which == 9 || (seen & ((usize)1 << which)))
            stop(refusal, sizeof(refusal) - 1);
        seen |= (usize)1 << which;
        value = env[i] + k + 1;
        if ((which < 5 && !equal(value, fixed[which])) ||
            ((which == 5 || which == 6) && !equal(value, argv[1])) ||
            (which == 7 && (bounded_length(value, 32) != 32 || !lower_hex(value, 32))) ||
            (which == 8 && !pid_equal(value, pid)))
            stop(refusal, sizeof(refusal) - 1);
    }
    if (env[i] || (seen & 127) != 127) stop(refusal, sizeof(refusal) - 1);
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
