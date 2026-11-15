/* The initialization test program for Mach-O (see build-unix.cmd): its
   constructors (__mod_init_func), then its entry point, main. */
/* (Volatile: else the compiler runs the constructors itself, at compile
   time, and leaves only their result.) */
static volatile int order[16];
static volatile int count;
static void record(int what) { order[count++ & 15] = what; }

__attribute__((noinline)) static void prepare(void) { record(3); }
__attribute__((constructor(101))) static void first(void) { record(1); }
__attribute__((constructor)) static void second(void) {
    record(2);
    prepare();
}

int main(void) { return order[0]; }
