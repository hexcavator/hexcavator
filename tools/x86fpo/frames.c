// SPDX-License-Identifier: Apache-2.0
//
// Stacks for testing the x86 unwinder (FPO and FrameData records): a
// 32-bit program whose functions take each frame shape MSVC makes, and
// that writes snapshots of its own stack (registers, stack bytes, loaded
// modules), with the true return addresses its functions recorded.
//
//   frames.exe sync  FILE        one snapshot per scenario, with truth
//   frames.exe async FILE N      N snapshots of a worker thread running
//                                the scenarios, suspended at random points
//
// Built by build.cmd (MSVC, /O2: frame pointers omitted; and /Oy-).

#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOINLINE __declspec(noinline)

void asm_fpo(void (*f)(void));
int cpp_scenarios(void (*f)(void));

// --- Ground truth: each instrumented function records where its return
// address is (and what it is, and how many argument bytes its `ret` pops).

typedef struct {
    DWORD loc, ra, pops;
} Truth;

static Truth truth[128];
static volatile LONG depth;
static volatile int sink;

#define ENTER(n)                                               \
    do {                                                       \
        truth[depth].loc = (DWORD)_AddressOfReturnAddress();   \
        truth[depth].ra = (DWORD)_ReturnAddress();             \
        truth[depth].pops = (n);                               \
        depth++;                                               \
    } while (0)
#define LEAVE() (depth--)

// --- Snapshots.

static HANDLE out;
static int async_mode;

static void put(const void* p, DWORD n) {
    DWORD w;
    WriteFile(out, p, n, &w, NULL);
}

static void put32(DWORD v) { put(&v, 4); }

static void put_modules(void) {
    HMODULE mods[256];
    DWORD need = 0;
    K32EnumProcessModules(GetCurrentProcess(), mods, sizeof mods, &need);
    DWORD n = need / sizeof(HMODULE);
    if (n > 256) n = 256;
    put32(n);
    for (DWORD i = 0; i < n; i++) {
        MODULEINFO mi;
        WCHAR path[MAX_PATH];
        K32GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof mi);
        DWORD len = GetModuleFileNameW(mods[i], path, MAX_PATH);
        put32((DWORD)mi.lpBaseOfDll);
        put32(mi.SizeOfImage);
        put32(len);
        put(path, len * 2);
    }
}

static void put_snapshot(const CONTEXT* c, DWORD stack_base, const void* stack,
                         DWORD stack_len, const Truth* t, DWORD truths, const char* name) {
    put("X86S", 4);
    DWORD name_len = (DWORD)strlen(name);
    put32(name_len);
    put(name, name_len);
    DWORD regs[10] = {c->Eip, c->Esp, c->Ebp, c->Eax, c->Ebx,
                      c->Ecx, c->Edx, c->Esi, c->Edi, c->EFlags};
    put(regs, sizeof regs);
    put32(stack_base);
    put32(stack_len);
    put(stack, stack_len);
    put_modules();
    put32(truths);
    put(t, truths * sizeof(Truth));
}

static const char* scenario = "";

// The innermost function of each synchronous scenario.
NOINLINE static void snap(void) {
    if (async_mode) {
        sink++;
        return;
    }
    // (Not RtlCaptureContext: on x86 it follows EBP to its caller, which
    // FPO code doesn't keep.)
    CONTEXT c = {0};
    DWORD eip_, esp_, ebp_, ebx_, esi_, edi_, flags_;
    __asm {
        call here
    here:
        pop eax
        mov eip_, eax
        mov esp_, esp
        mov ebp_, ebp
        mov ebx_, ebx
        mov esi_, esi
        mov edi_, edi
        pushfd
        pop eax
        mov flags_, eax
    }
    c.Eip = eip_;
    c.Esp = esp_;
    c.Ebp = ebp_;
    c.Ebx = ebx_;
    c.Esi = esi_;
    c.Edi = edi_;
    c.EFlags = flags_;
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    DWORD base = (DWORD)tib->StackBase;
    put_snapshot(&c, base, (void*)c.Esp, base - c.Esp, truth, depth, scenario);
}

// --- Scenarios.

// FPO functions with locals and saved registers.
NOINLINE static int fpo3(int a, int b) {
    ENTER(0);
    volatile int locals[7];
    for (int i = 0; i < 7; i++) locals[i] = a * i + b;
    snap();
    int r = locals[a & 3] + locals[b & 3];
    LEAVE();
    return r;
}

NOINLINE static int fpo2(int a) {
    ENTER(0);
    int x = a * 3, y = a ^ 0x55, z = a + 7, w = a - 9;
    int r = fpo3(x + y, z * w);
    r += x * y + z * w;
    LEAVE();
    return r;
}

NOINLINE static int fpo1(int a) {
    ENTER(0);
    volatile char big[300];
    big[a & 255] = (char)a;
    int r = fpo2(a + big[a & 7]);
    LEAVE();
    return r;
}

// A frame pointer from alloca.
NOINLINE static int with_alloca(int n) {
    ENTER(0);
    volatile char* p = (volatile char*)_alloca(n);
    p[0] = 1;
    p[n - 1] = 2;
    snap();
    int r = p[0] + p[n - 1];
    LEAVE();
    return r;
}

// A realigned stack (an over-aligned local).
NOINLINE static int aligned(int a) {
    ENTER(0);
    __declspec(align(64)) volatile int buf[16];
    buf[a & 15] = a;
    snap();
    int r = buf[a & 15];
    LEAVE();
    return r;
}

// More than a page of locals: __chkstk.
NOINLINE static int big_frame(int a) {
    ENTER(0);
    volatile char buf[12000];
    buf[a] = 1;
    buf[11999] = (char)a;
    snap();
    int r = buf[a] + buf[11999];
    LEAVE();
    return r;
}

// Callee-popped arguments.
NOINLINE static int __stdcall std2(int a, int b, int c) {
    ENTER(12);
    volatile int v = a + b + c;
    snap();
    int r = v;
    LEAVE();
    return r;
}

NOINLINE static int __stdcall std1(int a, int b) {
    ENTER(8);
    int r = std2(a, b, a ^ b) + 1;
    LEAVE();
    return r;
}

NOINLINE static int __fastcall fast1(int a, int b, int c, int d) {
    ENTER(8);
    volatile int v = a * b + c * d;
    snap();
    int r = v;
    LEAVE();
    return r;
}

// SEH: a __try in the frame.
NOINLINE static int seh_frame(int a) {
    ENTER(0);
    int r = 0;
    __try {
        volatile int v = a;
        snap();
        r = v;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r = -1;
    }
    LEAVE();
    return r;
}

// An exception filter, run by the exception dispatcher (through ntdll and
// RaiseException in kernelbase).
static volatile LONG filter_depth;

NOINLINE static int filter(void) {
    // (Its frame is under the dispatcher's, so the truth below it stands.)
    LONG d = depth;
    ENTER(0);
    snap();
    depth = d;
    return EXCEPTION_EXECUTE_HANDLER;
}

NOINLINE static int raises(int a) {
    ENTER(0);
    int r = 0;
    __try {
        RaiseException(0xE0000001, 0, 0, NULL);
    } __except (filter()) {
        r = a;
    }
    LEAVE();
    return r;
}

// A CRT callback (qsort, statically linked or in ucrtbase).
static int sorted_once;

static int __cdecl compare(const void* a, const void* b) {
    if (!sorted_once) {
        sorted_once = 1;
        ENTER(0);
        snap();
        LEAVE();
    }
    return *(const int*)a - *(const int*)b;
}

NOINLINE static int sorts(int a) {
    ENTER(0);
    int v[32];
    for (int i = 0; i < 32; i++) v[i] = (a * 7919 + i * 104729) % 1000;
    sorted_once = 0;
    qsort(v, 32, sizeof v[0], compare);
    int r = v[0];
    LEAVE();
    return r;
}

// A system callback (kernelbase).
static int enumerated_once;

static BOOL CALLBACK code_page(LPWSTR name) {
    if (!enumerated_once) {
        enumerated_once = 1;
        ENTER(4);
        snap();
        LEAVE();
    }
    return TRUE;
}

NOINLINE static int enumerates(int a) {
    ENTER(0);
    enumerated_once = 0;
    EnumSystemCodePagesW(code_page, CP_INSTALLED);
    LEAVE();
    return a;
}

// Recursion with frames of varying size.
NOINLINE static int recurse(int n) {
    ENTER(0);
    volatile int pad[5];
    pad[n % 5] = n;
    int r;
    if (n == 0) {
        snap();
        r = 0;
    } else if (n % 3 == 0) {
        r = with_alloca(16 + n * 8) + recurse(n - 1);
    } else {
        r = recurse(n - 1) + pad[n % 5];
    }
    LEAVE();
    return r;
}

static void asm_callback(void) {
    ENTER(0);
    snap();
    LEAVE();
}

static void cpp_callback(void) {
    ENTER(0);
    snap();
    LEAVE();
}

struct {
    const char* name;
    int (*run)(int);
} scenarios[] = {
    {"fpo", fpo1},
    {"alloca", with_alloca},
    {"aligned", aligned},
    {"chkstk", big_frame},
    {"seh", seh_frame},
    {"filter", raises},
    {"qsort", sorts},
    {"enum", enumerates},
    {"recurse", recurse},
};

static int run_all(int a) {
    int r = 0;
    for (int i = 0; i < sizeof scenarios / sizeof scenarios[0]; i++) {
        scenario = scenarios[i].name;
        r += scenarios[i].run(a + 9);
    }
    scenario = "stdcall";
    r += std1(a, 3);
    scenario = "fastcall";
    r += fast1(a, 2, 3, 4);
    scenario = "asm";
    asm_fpo(asm_callback);
    scenario = "cpp";
    r += cpp_scenarios(cpp_callback);
    return r;
}

// --- Asynchronous sampling.

static volatile DWORD worker_stack_base;

static DWORD WINAPI worker(void* p) {
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    worker_stack_base = (DWORD)tib->StackBase;
    for (int a = 0;; a++) sink += run_all(a & 63);
}

static int sample(int n) {
    async_mode = 1;
    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    while (!worker_stack_base) Sleep(1);
    // (No allocation while the worker is suspended: it may hold the heap
    // lock.)
    static BYTE copy[1 << 20];
    unsigned seed = 12345;
    for (int i = 0; i < n; i++) {
        seed = seed * 1103515245 + 12345;
        for (volatile unsigned spin = (seed >> 8) & 0x3FFF; spin; spin--) {
        }
        SuspendThread(t);
        CONTEXT c;
        c.ContextFlags = CONTEXT_FULL;
        GetThreadContext(t, &c);
        DWORD len = worker_stack_base - c.Esp;
        if (len > sizeof copy) len = sizeof copy;
        memcpy(copy, (void*)c.Esp, len);
        ResumeThread(t);
        put_snapshot(&c, worker_stack_base, copy, len, NULL, 0, "async");
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: frames sync FILE | frames async FILE N\n");
        return 2;
    }
    out = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (out == INVALID_HANDLE_VALUE) return 1;
    if (strcmp(argv[1], "async") == 0) {
        sample(argc > 3 ? atoi(argv[3]) : 1000);
    } else {
        ENTER(0);
        sink += run_all(1);
        LEAVE();
    }
    CloseHandle(out);
    return 0;
}
