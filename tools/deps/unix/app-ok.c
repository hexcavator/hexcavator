/* The ELF dependency test's second program: every library found, so its
   symbols are checked: puts at its version, vers_fn at one the system's
   libc doesn't have (it was linked against a newer one), and liba's
   nowhere, which nothing defines. */
int puts(const char *);
int vers_fn(void);
int a_fn(int);
void _start(void) { puts("x"); vers_fn(); a_fn(1); for (;;) {} }
