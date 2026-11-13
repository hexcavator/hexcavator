// The program: calls what lib.a's used.o has, and has a function nothing
// calls (removed with --gc-sections or -dead_strip).
int used_helper(int);
int shared_table[16] = {1, 2, 3};

int unused_here(int x) { return x * 3; }

int compute(int n) { return used_helper(n) + shared_table[n & 15]; }

void _start(void) {
    volatile int r = compute(5);
    (void)r;
    for (;;) {
    }
}
