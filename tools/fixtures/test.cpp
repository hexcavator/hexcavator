#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <stdexcept>
namespace ns {
enum class Color : uint8_t { Red = 1, Green = 2, Blue = 4 };
enum Plain { A, B = 10, C };
struct Bits { unsigned a : 3; unsigned b : 5; int c : 7; uint64_t d : 40; };
union U { int i; float f; char bytes[4]; };
struct Base { virtual ~Base() {} virtual int f(int x) { return x + 1; } int base_member = 3; };
struct Base2 { virtual void g() {} double d = 1.5; };
struct Derived : Base, Base2 { int f(int x) override { return x * 2; } static int s_count; const char* name = "d"; };
int Derived::s_count = 7;
struct VBase { int v = 1; };
struct VD1 : virtual VBase { int a1 = 2; };
struct VD2 : virtual VBase { int a2 = 3; };
struct Diamond : VD1, VD2 { int dd = 4; };
template <typename T, int N> struct Arr { T data[N]; T sum() const { T s{}; for (int i = 0; i < N; ++i) s += data[i]; return s; } };
__declspec(noinline) int compute(int a, int b, Color c) {
    volatile int local = a * b;
    if (c == Color::Red) throw std::runtime_error("red");
    return local + (int)c;
}
inline int inl(int x) { return x * 3 + 1; }
}
thread_local int tls_value = 42;
static int file_static = 5;
int global_array[16];
int main(int argc, char** argv) {
    ns::Derived d; ns::Base* b = &d; ns::Diamond dia;
    ns::Arr<double, 4> arr{{1, 2, 3, 4}};
    ns::Bits bits{}; bits.a = 3; bits.d = 12345;
    ns::U u; u.f = 1.0f;
    std::vector<std::string> v{"a", "b"};
    std::map<int, std::string> m{{1, "one"}};
    auto up = std::make_unique<ns::Derived>();
    int r = 0;
    try { r = ns::compute(argc, 3, ns::Color::Green); } catch (const std::exception& e) { std::puts(e.what()); }
    for (int i = 0; i < 16; ++i) global_array[i] = ns::inl(i);
    std::printf("%d %d %f %u %d %zu %d %d %d\n", b->f(r), dia.v, arr.sum(), bits.a, u.i, v.size(), tls_value, file_static, ns::Derived::s_count);
    return (int)m.size() + up->base_member;
}
