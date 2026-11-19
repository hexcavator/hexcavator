// Near-identical functions: instantiations of one template that differ
// only in the sizes of what they work on (total<T>), or in what they call
// (apply<F>); and one whose instantiations differ in what they do
// (pick<T>, by if constexpr), which aren't.

typedef unsigned long size_t;

template <typename T> __attribute__((noinline)) long total(const T* p, int n) {
    long sum = 0;
    for (int i = 0; i < n; i++) {
        sum += p[i] * 3 + (sum >> 2);
        if (sum > 100000) sum -= p[i];
    }
    return sum;
}

__attribute__((noinline)) int twice(int x) { return x * 2 + 1; }
__attribute__((noinline)) int thrice(int x) { return x * 3 - 1; }

template <int (*F)(int)> __attribute__((noinline)) int apply(const int* p, int n) {
    int out = 0;
    for (int i = 0; i < n; i++) {
        out ^= F(p[i]) + i;
        if (out < 0) out = -out;
    }
    return out;
}

template <typename T> __attribute__((noinline)) long pick(const T* p, int n) {
    if constexpr (sizeof(T) == 1) {
        long s = 0;
        for (int i = 0; i < n; i++) s += p[i];
        return s;
    } else {
        long m = 1;
        for (int i = 0; i < n; i += 2) m = m * p[i] + 7;
        return m;
    }
}

char c8[16];
short s16[16];
int i32[16];
long i64[16];

extern "C" void _start() {
    volatile long r = total(c8, 16) + total(s16, 16) + total(i32, 16) + total(i64, 16)
        + apply<twice>(i32, 16) + apply<thrice>(i32, 16)
        + pick(c8, 16) + pick(i32, 16);
    (void)r;
    for (;;) {}
}
