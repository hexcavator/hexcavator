/* The ELF dependency test's program (see build-unix.cmd): its libraries by
   rpath ($ORIGIN/lib), puts at a version, and a library only another
   architecture's copy of which is there. */
int puts(const char *);
int a_fn(int);
int wrong_fn(void);
void _start(void) { puts("x"); a_fn(1); wrong_fn(); for (;;) {} }
