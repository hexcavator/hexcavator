// SPDX-License-Identifier: Apache-2.0
//
// C++ exception handling frames for frames.c: a snapshot taken in a catch
// block (run by the C++ runtime's handler, above the thrower's frames),
// and one in a try block whose frame has objects to destroy.

#include <stdexcept>

struct Guard {
    volatile int* p;
    explicit Guard(volatile int* p) : p(p) { ++*p; }
    ~Guard() { --*p; }
};

static volatile int live;

__declspec(noinline) static void thrower(int a) {
    Guard g(&live);
    if (a >= 0) throw a + 1;
}

__declspec(noinline) static int guarded(void (*f)(void), int a) {
    Guard g(&live);
    Guard h(&live);
    f();
    return a + live;
}

extern "C" int cpp_scenarios(void (*f)(void)) {
    int r = 0;
    try {
        thrower(r);
    } catch (int x) {
        f();
        r = x;
    }
    try {
        r += guarded(f, r);
    } catch (...) {
        r = -1;
    }
    return r;
}
