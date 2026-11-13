// The header of the source lines test program (see build.cmd).
#pragma once

// Inlined everywhere it's called.
__forceinline int square(int x) { return x * x; }

// Inlined, and inlines square: a nested inline site.
__forceinline int sum_of_squares(int a, int b) { return square(a) + square(b); }

// Defined in the header, never inlined: its code is the header's.
template <typename T>
__declspec(noinline) T twice(T x) {
    return x + x;
}
