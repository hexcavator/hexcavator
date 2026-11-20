/* The entry point of noexc, and stand-ins for the C++ runtime's exception
   functions (nothing here throws: nothing calls them for real). */
volatile int sink;
int _Z8needlessi(int);
int _Z6neededi(int);
void _Unwind_Resume(void* e) { (void)e; for (;;) {} }
int __gxx_personality_v0(void) { return 0; }
void* __cxa_allocate_exception(unsigned long n) { (void)n; return (void*)&sink; }
void __cxa_throw(void* e, void* t, void (*d)(void*)) { (void)e; (void)t; (void)d; for (;;) {} }
int _ZTIi;
void _start(void) {
    sink = _Z8needlessi(sink) + _Z6neededi(sink);
    for (;;) {}
}
