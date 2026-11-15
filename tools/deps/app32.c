/* A 32-bit application: its kernel32 is SysWOW64's. (Sleep is declared
   __cdecl to match the stand-in's undecorated export: it never runs.) */
__declspec(dllimport) int __cdecl Sleep(int);
int mainCRTStartup(void) { return Sleep(0); }
