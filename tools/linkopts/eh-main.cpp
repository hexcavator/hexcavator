volatile int sink;
struct Guard {
  int *p;
  ~Guard();
};
Guard::~Guard() { sink = 0; }
void may_throw(int) {}
int use1(int);
int use2(int);
extern "C" void _start() {
  int a = use1(sink);
  int b = use2(sink);
  sink = a + b;
  for (;;) {
  }
}
