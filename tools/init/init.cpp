// The initialization test program (see build.cmd): code that runs before
// main in each of the ways the loader and MSVC's CRT run it. Built as a
// program and (with DLL defined) as a DLL.
#include <windows.h>

static int order[16];
static int count;
static void record(int what) { order[count++ & 15] = what; }

// A TLS callback: the loader's, before the entry point.
static void NTAPI tls_callback(void*, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH) {
        record(1);
    }
}
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_ptr")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback_ptr = tls_callback;
#pragma const_seg()

// A C initializer (.CRT$XIU: the CRT's _initterm_e).
static int __cdecl c_initializer() {
    record(2);
    return 0;
}
#pragma comment(linker, "/INCLUDE:c_initializer_ptr")
#pragma section(".CRT$XIU", long, read)
extern "C" __declspec(allocate(".CRT$XIU")) int(__cdecl* const c_initializer_ptr)() = c_initializer;

// A global object's constructor (.CRT$XCU: the CRT's _initterm), and what
// it calls.
struct Widget {
    Widget();
    static __declspec(noinline) void prepare();
};
__declspec(noinline) void Widget::prepare() { record(4); }
__declspec(noinline) Widget::Widget() {
    record(3);
    prepare();
}
Widget widget;

#ifdef DLL
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        record(5);
    }
    return TRUE;
}
extern "C" __declspec(dllexport) int recorded(int i) { return order[i & 15]; }
#else
int main() {
    record(5);
    return order[0] * 10000 + order[1] * 1000 + order[2] * 100 + order[3] * 10 + order[4];
}
#endif
