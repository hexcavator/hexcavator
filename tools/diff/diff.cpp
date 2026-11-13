// Two builds to compare (testdata\diff\diff-v1.exe and diff-v2.exe, with
// their PDBs): built from this file without and with V2 defined.
//
//                       v1                  v2
//   functions
//     kept_same         the same            the same
//     transform         small               larger (more steps)
//     removed_fn        here                gone
//     added_fn          -                   here
//   data
//     g_same            the same            the same
//     g_lookup          32 ints             96 ints, other values
//     g_removed_table   256 bytes           gone
//     g_added_table     -                   512 bytes
//     g_message         a short string      a longer one
//
// Each function is kept out of line and called, and each datum is read,
// so the linker keeps them all.

#include <cstdio>

#define NOINLINE __declspec(noinline)

// ---------------------------------------------------------------- data

extern "C" const int g_same[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

#ifndef V2
extern "C" const int g_lookup[32] = {
    0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225,
    256, 289, 324, 361, 400, 441, 484, 529, 576, 625, 676, 729, 784, 841, 900, 961,
};
extern "C" const unsigned char g_removed_table[256] = {1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233};
extern "C" const char g_message[] = "v1";
#else
extern "C" const int g_lookup[96] = {
    0, 1, 8, 27, 64, 125, 216, 343, 512, 729, 1000, 1331, 1728, 2197, 2744, 3375,
    4096, 4913, 5832, 6859, 8000, 9261, 10648, 12167, 13824, 15625, 17576, 19683,
    21952, 24389, 27000, 29791, 32768, 35937, 39304, 42875, 46656, 50653, 54872,
    59319, 64000, 68921, 74088, 79507, 85184, 91125, 97336, 103823, 110592,
};
extern "C" const unsigned char g_added_table[512] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47};
extern "C" const char g_message[] = "version two, with a longer message than before";
#endif

// ----------------------------------------------------------- functions

NOINLINE int kept_same(int x) {
    return x * 3 + g_same[x & 15];
}

#ifndef V2
NOINLINE int transform(int x) {
    return x + g_lookup[x & 31];
}

NOINLINE int removed_fn(int x) {
    int sum = 0;
    for (int i = 0; i < x; ++i) {
        sum += g_removed_table[(x + i) & 255] * i;
    }
    return sum;
}
#else
NOINLINE int transform(int x) {
    // More steps: the function grows.
    int y = x + g_lookup[x % 96];
    for (int i = 0; i < (x & 7); ++i) {
        y = y * 31 + g_lookup[(y + i) % 96];
        y ^= y >> 7;
    }
    return y - g_lookup[(y & 0x7fffffff) % 96];
}

NOINLINE int added_fn(int x) {
    int product = 1;
    for (int i = 0; i < (x & 15); ++i) {
        product = product * g_added_table[(x * i) & 511] + i;
    }
    return product;
}
#endif

int main(int argc, char**) {
    int r = kept_same(argc) + transform(argc);
#ifndef V2
    r += removed_fn(argc);
#else
    r += added_fn(argc);
#endif
    std::printf("%s %d\n", g_message, r);
    return 0;
}
