// Compiled twice (N=1, N=2): work<N> has a cleanup (an LSDA), which lld's
// ICF never folds; plain<N> has none, and folds; use<N> calls each.
struct Guard {
  int *p;
  ~Guard();
};
void may_throw(int);
extern volatile int sink;

template <int M> __attribute__((noinline)) int work(int x) {
  Guard g{(int *)&sink};
  int r = 0;
  for (int i = 0; i < x; i++) {
    may_throw(i);
    r += i * 3;
    sink = r;
  }
  return r;
}

template <int M> __attribute__((noinline)) int plain(int x) {
  int r = 0;
  for (int i = 0; i < x; i++) {
    r += i * 5 + (r >> 2);
    sink = r;
  }
  return r;
}

#define USE_(n) use##n
#define USE(n) USE_(n)
int USE(N)(int x) { return work<N>(x) + plain<N>(x); }
