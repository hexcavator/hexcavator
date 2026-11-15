/* The initialization test program for ELF (see build-unix.cmd): code that
   runs before main in each of the ways the loader runs it. Freestanding;
   built as a program and (with LIB defined) as a shared library. */
/* (Volatile: else the compiler runs the constructors itself, at compile
   time, and leaves only their result.) */
static volatile int order[16];
static volatile int count;
static void record(int what) { order[count++ & 15] = what; }

#ifndef LIB
/* A program's preinit array: first of all. */
static void preinit(void) { record(1); }
__attribute__((section(".preinit_array"), used)) static void (*preinit_ptr)(void) = preinit;
#endif

/* DT_INIT (the linker's -init). */
void init_function(void) { record(2); }

/* The older constructors' list. */
static void old_constructor(void) { record(3); }
__attribute__((section(".ctors"), used)) static void (*old_constructor_ptr)(void) = old_constructor;

/* Constructors (.init_array), the one with a priority first, and what the
   other calls. */
__attribute__((constructor(101))) static void first(void) { record(4); }
__attribute__((noinline)) static void prepare(void) { record(6); }
__attribute__((constructor)) static void second(void) {
    record(5);
    prepare();
}

#ifdef LIB
int recorded(int i) { return order[i & 15]; }
#else
int main(void) { return order[0]; }
void _start(void) {
    main();
    for (;;) {
    }
}
#endif
