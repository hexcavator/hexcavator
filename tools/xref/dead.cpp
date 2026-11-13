// Compiled without /Gy: its functions share one section, so the linker
// keeps dead_entry (which nothing calls) because main calls
// live_in_dead_object, and with it Ghost's constructor, vtable, and
// virtual functions (see build.cmd).
#include "shapes.h"

Ghost::Ghost() {}
double Ghost::area() const { return 0.5; }
const char* Ghost::name() const { return "ghost"; }

NOINLINE int dead_helper(int x) { return x ^ 0x5A5A; }

NOINLINE int dead_entry(int x) {
    Ghost g;
    return dead_helper(x) + static_cast<int>(g.area());
}

int live_in_dead_object(int x) { return x + 5; }
