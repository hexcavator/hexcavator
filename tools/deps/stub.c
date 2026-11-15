/* The DLLs of the dependency test (see build.cmd): each export is a stub,
   built under the name its .def file gives. */
int stub(void) { return 0; }
int __stdcall _DllMainCRTStartup(void *module, unsigned long reason, void *reserved) {
    (void)module; (void)reason; (void)reserved;
    return 1;
}
