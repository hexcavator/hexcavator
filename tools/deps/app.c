/* The dependency test's application (see build.cmd): the system's kernel32
   (a planted one beside it notwithstanding), its helper by name and by
   ordinal, an API set, Common Controls 6 (by its manifest), and a DLL it
   delay-loads that isn't shipped. */
__declspec(dllimport) int __stdcall Sleep(int);
__declspec(dllimport) int helper_add(int, int);
__declspec(dllimport) int helper_ordinal(void);
__declspec(dllimport) int ApiFunc(void);
__declspec(dllimport) int TaskDialogIndirect(void);
__declspec(dllimport) int MissingFn(void);
/* (The delay-load helper the linker's thunks call: never run, so a stub,
   rather than delayimp.lib and the C runtime it needs.) */
void *__delayLoadHelper2(const void *descriptor, void **slot) {
    (void)descriptor;
    (void)slot;
    return 0;
}
int mainCRTStartup(void) {
    return Sleep(0) + helper_add(1, 2) + helper_ordinal() + ApiFunc() + TaskDialogIndirect() + MissingFn();
}
