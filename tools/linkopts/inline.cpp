// Inlining: mix (a function of a dozen operations, two parameters) inlined
// into each of 12 callers, which calling one copy would make smaller; and
// get (a field's load), inlined as often, which a call would make larger.

struct Point {
    int x, y;
    __attribute__((always_inline)) inline int get() const { return x; }
};

__attribute__((always_inline)) inline int mix(int a, int b) {
    int h = a * 0x45d9f3b + b;
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 13;
    h += a ^ (b << 3);
    h *= 0x27d4eb2d;
    h ^= h >> 15;
    return h + (a > b ? a - b : b - a);
}

volatile int sink;
Point pts[12];

#define CALLER(n) \
    __attribute__((noinline)) void caller##n(int v) { sink = mix(v, n) + pts[n].get(); }
CALLER(0) CALLER(1) CALLER(2) CALLER(3) CALLER(4) CALLER(5)
CALLER(6) CALLER(7) CALLER(8) CALLER(9) CALLER(10) CALLER(11)

extern "C" void _start() {
    caller0(1); caller1(2); caller2(3); caller3(4); caller4(5); caller5(6);
    caller6(7); caller7(8); caller8(9); caller9(10); caller10(11); caller11(12);
    for (;;) {}
}
