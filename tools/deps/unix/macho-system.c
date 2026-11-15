/* A stand-in for libSystem, to link against (not shipped: the system's is
   in the shared cache). Its binder, by its own name (no underscore). */
int stub_binder(void) __asm__("dyld_stub_binder");
int stub_binder(void) { return 0; }
