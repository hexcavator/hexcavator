// Inputs for Hexcavator's object and library size tests (see build.cmd).
#include <stdint.h>

int counter;                       // .bss
int table[16] = {1, 2, 3};         // .data
static const char text[] = "a literal in .rdata";

template <typename T> T twice(T v) { return v + v; }   // COMDATs

struct Shape {
    virtual ~Shape() {}
    virtual int area() const = 0;
};
struct Square : Shape {
    int side;
    explicit Square(int s) : side(s) {}
    int area() const override { return side * side; }
};

int use_statics(int n) {
    static int calls;              // a function's static
    calls += n;
    return calls + text[n & 7];
}

extern "C" __declspec(dllexport) int exported(int n) {
    Square s(n);
    const Shape& shape = s;
    return twice(shape.area()) + twice(static_cast<int64_t>(n)) > 0 ? use_statics(n) : table[n & 15] + counter;
}
