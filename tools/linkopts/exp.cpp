// libexp: exported functions, some calling others (through the PLT unless
// linked -Bsymbolic-functions or built -fvisibility=hidden), and template
// instantiations and inline functions exported with them.
#include "exp.h"

int exp_helper(int x) { return x * 7 + 1; }

int exp_used(int x) {
    Box<int> b{exp_helper(x)};
    Box<long> l{x};
    Box<short> s{static_cast<short>(x)};
    return b.get() + b.twice() + static_cast<int>(l.twice() + l.get()) + s.twice();
}

int exp_unused(int x) {
    Box<char> c{static_cast<char>(x)};
    Box<unsigned> u{static_cast<unsigned>(x)};
    return exp_helper(x) + exp_used(x) + c.twice() + static_cast<int>(u.twice() + u.get());
}

// Not API: exported only because visibility is the default.
int exp_internal_a(int x) { return exp_helper(x) - 3; }
int exp_internal_b(int x) { return exp_internal_a(x) * exp_helper(x + 1); }
