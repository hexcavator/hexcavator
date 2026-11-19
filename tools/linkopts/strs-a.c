// A string literal, which the linker merges with strs-b.c's; and a named
// array, which it mustn't.
extern volatile int sink;
const char banner_a[] = "Hexcavator digs into binaries";
int say_a(void) {
    const char* s = "the same literal in two objects, unmerged";
    int i = sink;
    return s[i & 7] + banner_a[i & 3];
}
