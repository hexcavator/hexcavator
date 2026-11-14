/* The application's helper DLL (see build.cmd): imports what its system no
   longer exports, a forwarder that leads nowhere, and a DLL not shipped. */
__declspec(dllimport) int __stdcall Sleep(int);
__declspec(dllimport) int NoSuchFunction(void);
__declspec(dllimport) int FwdTarget(void);
__declspec(dllimport) int FwdMissing(void);
__declspec(dllimport) int GoneFn(void);
int helper_add(int a, int b) { return a + b + Sleep(0) + NoSuchFunction() + FwdTarget() + FwdMissing() + GoneFn(); }
int helper_ordinal(void) { return 5; }
int __stdcall _DllMainCRTStartup(void *module, unsigned long reason, void *reserved) {
    (void)module; (void)reason; (void)reserved;
    return 1;
}
