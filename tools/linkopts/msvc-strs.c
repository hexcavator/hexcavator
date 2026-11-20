// The same string literals in two objects (MSVC_STRS_B: the second), which
// the linker merges if they're pooled (/GF) and can't if they aren't (/GF-).
extern volatile int sink;
#ifdef MSVC_STRS_B
int say_b(void) {
#else
int say_a(void) {
#endif
    const char* s = "the same literal in two objects, pooled or not";
    const char* t = "and another, as long, in both of them as well";
    int i = sink;
    return s[i & 7] + t[i & 3];
}
