// noexc.cpp's callees: helper(), which can't throw (but isn't noexcept),
// and thrower(), which throws.
extern volatile int sink;
int helper(int x) { return x * 7 + sink; }
int thrower(int x) {
    if (x > 100) {
        throw x;
    }
    return x;
}
