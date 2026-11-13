// The cross-reference test program: calls, tail calls, a table of function
// pointers, virtual functions reached through their classes' constructors,
// a static initializer, and an export (see build.cmd).
#include <stdio.h>

#include "shapes.h"

Shape::~Shape() {}
const char* Shape::name() const { return "shape"; }

Square::Square(double s) : side(s) {}
Square::~Square() { puts("~Square"); }
double Square::area() const { return side * side; }
const char* Square::name() const { return "square"; }

Circle::Circle(double r) : radius(r) {}
double Circle::area() const { return 3.14159 * radius * radius; }

// Reached only from the table.
NOINLINE int op_add(int x) { return x + 17; }
NOINLINE int op_sub(int x) { return x - 23; }
static int (*const ops[])(int) = {op_add, op_sub};

#ifdef RENAMED
// The renamed build (build.cmd): the same function under another name.
#define inner inner_renamed
#endif
NOINLINE int inner(int x) { return x * 3 + 1; }
NOINLINE int outer(int x) { return inner(x) + inner(x + 1); }

// A static initializer: the CRT calls it before main.
static Circle unit_circle(1.0);

extern "C" __declspec(dllexport) NOINLINE int exported_twice(int x) { return x * 2; }

NOINLINE Shape* make_shape(int n) { return new Square(n); }

// Initialized at compile time: no constructor runs (and, with no virtual
// destructor, no destructor either), so only the object refers to Tag's
// vtable.
struct Named {
    virtual const char* label() const = 0;
};
struct Tag final : Named {
    constexpr Tag() {}
    NOINLINE const char* label() const override;
};
const char* Tag::label() const { return "tag"; }
static constinit Tag tag;
static const Named* const named[] = {&tag};
static volatile int which = 0;

int main(int argc, char**) {
    Shape* s = make_shape(argc);
    printf("%s %f %f %s\n", s->name(), s->area(), unit_circle.area(), named[which]->label());
    delete s;
    return outer(argc) + ops[argc & 1](argc) + live_in_dead_object(argc);
}
