// The classes of the cross-reference test program (see build.cmd).
#pragma once

#define NOINLINE __declspec(noinline)

struct Shape {
    NOINLINE virtual ~Shape();
    virtual double area() const = 0;
    NOINLINE virtual const char* name() const;
};

// Constructed by main.
struct Square : Shape {
    double side;
    NOINLINE explicit Square(double s);
    NOINLINE ~Square() override;
    NOINLINE double area() const override;
    NOINLINE const char* name() const override;
};

// Constructed only by a static initializer.
struct Circle : Shape {
    double radius;
    NOINLINE explicit Circle(double r);
    NOINLINE double area() const override;
};

// Constructed only by code nothing calls (dead.cpp).
struct Ghost : Shape {
    NOINLINE Ghost();
    NOINLINE double area() const override;
    NOINLINE const char* name() const override;
};

int live_in_dead_object(int x);
