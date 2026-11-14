// The source lines test program for ELF (see build-elf.cmd): lines.cpp's
// functions, freestanding (no C library), with lines.h's inline sites (one
// nested in another).
#include "lines.h"

__declspec(noinline) int first(int x) { return square(x) + 1; }

__declspec(noinline) int second(int x) { return square(x + 1) * 3; }

__declspec(noinline) int third(int a, int b) { return sum_of_squares(a, b) - 7; }

int sink;

extern "C" void _start() {
    sink = first(sink) + second(sink) + third(sink, sink + 2) + twice(sink);
    for (;;) {
    }
}
