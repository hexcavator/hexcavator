/* Functions with frames of different shapes, for compact unwind (see
   build.cmd): a leaf, one with a frame, one with a large stack, one that
   saves registers. */
int leaf(int x) { return x + 1; }

int framed(int x) {
    volatile int a[4] = {x, x, x, x};
    return a[0] + a[3];
}

int big(int x) {
    volatile char buffer[8192];
    buffer[x & 8191] = 1;
    return buffer[0];
}

extern int other(int);
int saves(int x) {
    int a = other(x), b = other(a), c = other(b);
    return a + b + c + other(c);
}
