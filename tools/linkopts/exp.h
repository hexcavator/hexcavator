// The API of libexp (exp.cpp): what exp-main.cpp imports, and what it
// doesn't. EXP_API marks it visible when built with -fvisibility=hidden.
#define EXP_API __attribute__((visibility("default")))

EXP_API int exp_used(int x);
EXP_API int exp_unused(int x);
EXP_API int exp_helper(int x);

// A template, instantiated in the library (vague linkage: a weak
// definition each object makes its own copy of).
template <typename T> struct Box {
    T value;
    T get() const { return value; }  // inline
    T twice() const;                 // out of line
};
template <typename T> T Box<T>::twice() const { return value + value; }
