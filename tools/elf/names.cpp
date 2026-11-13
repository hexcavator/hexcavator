// C++ names for Hexcavator's ELF symbol tests: namespaces, templates, a class
// with a constructor and members, an operator, and a lambda.

namespace geometry {
template <typename T> struct Point {
    T x, y;
    Point(T a, T b) : x(a), y(b) {}
    T dot(const Point& o) const { return x * o.x + y * o.y; }
};
template <typename T> Point<T> operator+(const Point<T>& a, const Point<T>& b) {
    return Point<T>(a.x + b.x, a.y + b.y);
}
} // namespace geometry

int table[64] = {1};

int use_points(int n) {
    geometry::Point<int> p(n, 2), q(3, n);
    geometry::Point<long> r(n, 4);
    auto twice = [](int v) { return v * 2; };
    return twice((p + q).dot(q)) + static_cast<int>(r.dot(r)) + table[n & 63];
}
