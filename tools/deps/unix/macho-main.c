/* The Mach-O dependency test's program (see build-unix.cmd): liba by
   @rpath (its own run path, @executable_path/lib), what liba re-exports,
   a symbol liba had when the program was linked and no longer has, a weak
   library that isn't there, and libSystem (in the dyld shared cache). */
int a_fn(int);
int re_fn(void);
int gone_fn(void);
int weak_fn(void) __attribute__((weak_import));
int main(void) { return a_fn(1) + re_fn() + gone_fn() + (weak_fn ? weak_fn() : 0); }
