// The entry point of msvc-strs-*.exe (no C runtime).
volatile int sink;
int say_a(void);
int say_b(void);
int start(void) { return say_a() + say_b() + sink; }
