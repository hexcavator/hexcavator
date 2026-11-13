/* Anonymous data that only code refers to, for the symbols source's
   disassembly: string literals (one shared by two functions), a lookup
   table, and a jump table. Freestanding, like program.c. */

const char *volatile sink;
volatile int isink;

__attribute__((noinline)) void greet(void) { sink = "hello, world"; }
__attribute__((noinline)) void shared_first(void) { sink = "shared literal"; }
__attribute__((noinline)) void shared_second(void) { sink = "shared literal"; }

/* A lookup table (clang's switch.table). */
__attribute__((noinline)) int lookup(unsigned i) {
    switch (i) {
    case 0: return 11;
    case 1: return 23;
    case 2: return 37;
    case 3: return 41;
    case 4: return 59;
    case 5: return 61;
    case 6: return 67;
    default: return 0;
    }
}

/* A jump table. */
__attribute__((noinline)) void jumps(unsigned i) {
    switch (i) {
    case 0: sink = "zero"; break;
    case 1: isink = 2; break;
    case 2: greet(); break;
    case 3: isink = 7; break;
    case 4: shared_first(); break;
    case 5: isink = 9; break;
    case 6: shared_second(); break;
    }
}

void _start(void) {
    greet();
    shared_first();
    shared_second();
    isink = lookup((unsigned)isink);
    jumps((unsigned)isink);
    for (;;) {}
}
