/* The system's libc, as the test's root has it: puts and vers_fn at
   GLIBC_2.2.5 (a newer one, linked against, has vers_fn at GLIBC_2.99). */
int puts(const char *s) { (void)s; return 0; }
int vers_fn(void) { return 0; }
