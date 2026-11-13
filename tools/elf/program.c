/* A freestanding program for Hexcavator's ELF test inputs: code, read-only
   data, initialized and zeroed data, thread-locals, a local and a global
   of each kind. Built with no libc, so every target links the same way. */

static const char message[] = "hello from rbat";
int counter = 3;
static int hidden_state;
char buffer[4096];
_Thread_local int per_thread = 7;

static int helper(int x) { return x * 3 + hidden_state; }

__attribute__((noinline)) int compute(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += helper(i) + message[i % 15];
    return total;
}

__attribute__((weak)) int optional_hook(void) { return 0; }

void _start(void) {
    buffer[0] = (char)compute(counter);
    hidden_state = optional_hook() + per_thread;
    for (;;) {}
}
