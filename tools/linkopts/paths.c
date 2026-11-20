// Build paths: __FILE__ as a build without -fmacro-prefix-map leaves it (an
// absolute path, here as #line sets it), in what checks report.

void report(const char* file, int line);
#define CHECK(x) do { if (!(x)) report(__FILE__, __LINE__); } while (0)

#line 1 "/home/user/project/src/parse.c"
__attribute__((noinline)) int parse(int x) { CHECK(x > 0); return x * 2; }
#line 1 "/home/user/project/src/lex.c"
__attribute__((noinline)) int lex(int x) { CHECK(x != 3); return x + 1; }
#line 1 "/home/user/project/include/util.h"
__attribute__((noinline)) int util(int x) { CHECK(x < 100); return x - 1; }
#line 1 "/home/user/project/src/emit.c"
__attribute__((noinline)) int emit(int x) { CHECK(x); return x ^ 5; }
#line 1 "/home/user/project/src/main.c"
volatile int sink;
const char* volatile reported;
__attribute__((noinline)) void report(const char* file, int line) {
    reported = file;
    sink = line;
}
int say_a(void);
int say_b(void);
void _start(void) {
    sink = parse(sink) + lex(sink) + util(sink) + emit(sink) + say_a() + say_b();
    for (;;) {}
}
