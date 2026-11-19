volatile int sink;
int use_a(int);
int use_b(int);
int use_c(int);
int use_other(int);
void _start(void) {
  int a = use_a(sink);
  int b = use_b(sink);
  int c = use_c(sink);
  int d = use_other(sink);
  sink = a + b + c + d;
  for (;;) {
  }
}
