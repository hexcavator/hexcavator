// strs-a.c's literal again (merged: lld merges identical strings), and its
// array's text, in an array of its own (not merged: named data).
extern volatile int sink;
const char banner_b[] = "Hexcavator digs into binaries";
int say_b(void) {
    const char* s = "the same literal in two objects, unmerged";
    int i = sink;
    return s[i & 5] + banner_b[i & 1];
}
