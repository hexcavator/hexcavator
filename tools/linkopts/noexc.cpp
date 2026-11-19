// Exception cleanups: needless() keeps a Guard (a destructor to run if
// what it calls throws) and calls only helper(), which can't throw but
// isn't declared noexcept, so its cleanup is there for nothing; needed()
// keeps one and calls thrower(), which throws, so its cleanup is needed.
struct Guard {
    volatile int* p;
    ~Guard() { *p = 0; }
};
int helper(int);
int thrower(int);
extern volatile int sink;

__attribute__((noinline)) int needless(int x) {
    Guard g{&sink};
    return helper(x) + helper(x + 1);
}

__attribute__((noinline)) int needed(int x) {
    Guard g{&sink};
    return thrower(x) + 1;
}
