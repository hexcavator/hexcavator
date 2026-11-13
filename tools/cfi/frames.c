// Functions with varied frames, for call frame information tests: alloca,
// many saved registers, floating-point saves, recursion, cleanups.
void sink(void *, long);
// Defined nowhere (the link ignores it): it may throw, so cleanups stay.
void elsewhere(long);
double fsink(double);

long saves(long a, long b, long c, long d, long e, long f) {
  long x = a * b, y = c * d, z = e * f, w = a + f;
  sink(&x, y);
  sink(&y, z);
  sink(&z, w);
  return x + y + z + w + a + b + c + d + e + f;
}

long dynamic(long n) {
  char *p = __builtin_alloca(n);
  sink(p, n);
  return p[0];
}

double floats(double a, double b, double c) {
  double x = fsink(a) * b, y = fsink(b) * c, z = fsink(c) * a;
  return fsink(x + y) + z;
}

long recurse(long n) { return n < 2 ? n : recurse(n - 1) + recurse(n - 2); }

static void cleanup(long *p) { sink(p, 0); }

long cleans(long n) {
  long guard __attribute__((cleanup(cleanup))) = n;
  sink(&guard, n);
  elsewhere(n);
  return guard;
}

long big(long n) {
  char buf[70000];
  sink(buf, n);
  return buf[n & 1023];
}

void _start(void) { saves(1, 2, 3, 4, 5, 6); dynamic(9); floats(1, 2, 3); recurse(5); cleans(3); big(4); }
void sink(void *p, long n) { *(volatile char *)p = (char)n; }
double fsink(double d) { return d * 2; }
