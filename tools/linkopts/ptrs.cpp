// Pointer-heavy data in a shared library: a table of string pointers
// (each a relative relocation), and a class's vtable.

const char* const color_names[] = {
    "red", "orange", "yellow", "green", "blue", "indigo", "violet", "black",
};

struct Shape {
    virtual ~Shape();
    virtual int area() const;
    virtual int perimeter() const;
    virtual int corners() const;
    virtual const char* name() const;
    int w = 2, h = 3;
};
Shape::~Shape() {}
int Shape::area() const { return w * h; }
int Shape::perimeter() const { return 2 * (w + h); }
int Shape::corners() const { return 4; }
const char* Shape::name() const { return color_names[w & 7]; }

__attribute__((visibility("default"))) int describe(int i) {
    Shape s;
    Shape* p = &s;
    return p->area() + p->perimeter() + p->corners() + color_names[i & 7][0];
}
