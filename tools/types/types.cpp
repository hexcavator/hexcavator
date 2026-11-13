// The type layout test program (see build.cmd): one structure for each
// kind of part and hole. With V2, Padded's members are reordered (no
// holes but the tail) and Grows gains a member, for comparing builds.
#include <stdio.h>

// (MSVC's spellings; clang's for the DWARF builds, which have no
// annotations: see build-dwarf.cmd.)
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#define FORCEINLINE __forceinline
#define ANNOTATE(...) __annotation(__VA_ARGS__)
#else
#define NOINLINE __attribute__((noinline))
#define FORCEINLINE inline __attribute__((always_inline))
#define ANNOTATE(...) ((void)0)
#endif

#ifndef V2
struct Padded {  // a@0, 3 padding, b@4, c@8, 3 tail: 12 bytes, 6 wasted
    char a;
    int b;
    char c;
};
#else
struct Padded {  // b@0, a@4, c@5, 2 tail: 8 bytes, 2 wasted
    int b;
    char a;
    char c;
};
#endif

struct Bits {  // a:3 and b:5 in one unsigned (24 bits unused), c@4
    unsigned a : 3;
    unsigned b : 5;
    int c;
};

struct Base {  // vfptr@0, x@8, 4 tail: 16 bytes
    NOINLINE virtual ~Base() {}
    int x = 1;
};

struct Derived : Base {  // Base@0 (16), y@16, 7 tail: 24 bytes
    char y = 2;
};

struct Empty {};

struct WithEmpty : Empty {  // the empty base takes nothing: z@0, 4 bytes
    int z = 3;
};

struct VBase {
    int v = 4;
};

struct Diamond : virtual VBase {  // vbptr@0, d@8, 4 padding, VBase@16, 4 tail
    int d = 5;
};

union Either {  // c and d at 0: 8 bytes, none wasted
    char c;
    double d;
};

struct Grows {
    int first;
#ifdef V2
    int second;
#endif
};

// Annotations (the __annotation intrinsic): strings attached to code in
// the PDB, for hexc annotations.
FORCEINLINE int annotated_inline(int x) {
    ANNOTATE(L"Hexcavator", L"in an inlined copy");
    return x + 1;
}

NOINLINE int use(Padded* p, Bits* b, Derived* d, WithEmpty* w, Diamond* m, Either* e, Grows* g) {
    ANNOTATE(L"Hexcavator", L"layout test", L"third string");
    return annotated_inline(p->a) + p->a + p->b + p->c + b->a + b->b + b->c + d->x + d->y + w->z + m->v + m->d + e->c +
           g->first;
}

// Globals for hexc data: each kind of value, initialized (in .data, the
// string pointer relocated), and one with a vtable (in .bss until its
// constructor runs).
enum Color { Red = 1, Green = 2, Blue = 4 };

struct Sample {
    Padded padded{'a', 42, 'c'};
    Bits bits{5, 17, -3};
    Color color = Green;
    double ratio = 1.5;
    const char* text = "hello";
    char name[8] = "abc";
    int numbers[3] = {1, -2, 3};
    bool flag = true;
    Either either{'e'};
};

Sample g_sample;
Derived g_derived;

int main() {
    g_sample.flag = g_sample.numbers[1] < 0;
    printf("%s %d %d\n", g_sample.text, g_sample.padded.b + g_sample.bits.c + g_sample.color, g_derived.x);
    Padded p{};
    Bits b{};
    Derived d;
    WithEmpty w;
    Diamond m;
    Either e{};
    Grows g{};
    printf("%d\n", use(&p, &b, &d, &w, &m, &e, &g));
    return 0;
}
