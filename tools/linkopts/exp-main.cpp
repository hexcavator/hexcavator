// An importer of libexp: it imports exp_used only.
#include "exp.h"

extern "C" void _start() {
    volatile int r = exp_used(3);
    (void)r;
    for (;;) {}
}
