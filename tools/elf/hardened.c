// A freestanding program built with the mitigations checksec reads on (see
// build.cmd): position-independent, stack canaries on every function,
// control-flow protection (CET on x86-64, BTI and PAC on AArch64), and
// linked with full RELRO. It brings its own canary routine: there is no C
// library.

unsigned long __stack_chk_guard = 0x2b5f3a1c9d4e7f60UL;

__attribute__((noreturn)) void __stack_chk_fail(void) {
    for (;;) {
    }
}

static int fill(char *buf, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        buf[i] = (char)i;
        total += buf[i];
    }
    return total;
}

int compute(int n) {
    char buf[64];
    return fill(buf, n < 64 ? n : 64);
}

int (*volatile hook)(int) = compute;

void _start(void) {
    volatile int r = hook(10);
    (void)r;
    for (;;) {
    }
}
