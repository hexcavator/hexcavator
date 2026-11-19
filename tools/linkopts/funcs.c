/* Identical functions (add_a, add_b, add_c), functions nothing calls
   (unused1, unused2), and data nothing reads (table2): what ICF folds and
   --gc-sections collects, linked with and without each. */
volatile int sink;

__attribute__((noinline)) int add_a(int x, int y) {
  int r = 0;
  for (int i = 0; i < x; i++) {
    r += y * i + (r >> 3);
    sink = r;
  }
  return r * 7 + 3;
}

__attribute__((noinline)) int add_b(int x, int y) {
  int r = 0;
  for (int i = 0; i < x; i++) {
    r += y * i + (r >> 3);
    sink = r;
  }
  return r * 7 + 3;
}

__attribute__((noinline)) int add_c(int x, int y) {
  int r = 0;
  for (int i = 0; i < x; i++) {
    r += y * i + (r >> 3);
    sink = r;
  }
  return r * 7 + 3;
}

__attribute__((noinline)) int unused1(int x) {
  int r = 1;
  for (int i = 0; i < x; i++) {
    r = r * 31 + i;
    sink = r;
    sink = r ^ 5;
    sink = r + 9;
  }
  return r;
}

__attribute__((noinline)) int unused2(int x) {
  int r = 2;
  for (int i = 0; i < x; i++) {
    r = r * 37 + i;
    sink = r;
    sink = r ^ 6;
    sink = r + 19;
  }
  return r;
}

static const char table1[200] = "a table of text that takes space, read";
const char table2[200] = "another table of text, never read, that takes space too";

void _start(void) {
  int a = add_a(sink, 2);
  int b = add_b(sink, 3);
  int c = add_c(sink, 4);
  sink = a + b + c;
  sink = table1[sink & 63];
  for (;;) {
  }
}
