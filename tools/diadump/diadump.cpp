// diadump: prints a PDB's contents via the DIA SDK in a simple line format,
// as a reference for hexcavator-pdb's tests.
//
// Build (from a VS developer prompt):
//   cl /nologo /EHsc /O2 /I "%VSINSTALLDIR%DIA SDK\include" diadump.cpp ^
//      /link "%VSINSTALLDIR%DIA SDK\lib\amd64\diaguids.lib" ole32.lib oleaut32.lib
// and put msdia140.dll (from "DIA SDK\bin\amd64") next to diadump.exe.
//
// Output lines:
//   MODULE <name>
//   PUBLIC <sec>:<off> <name>
//   FUNC <rva> <length> <name>
//   DATA <rva> <name>
//   UDT <size> <name>
//   LINE <rva> <length> <line> <file>

#include <windows.h>
#include <dia2.h>
#include <cstdio>
#include <string>

static std::string narrow(const wchar_t *w) {
  if (!w) return std::string();
  int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
  std::string s(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
  return s;
}

static std::string name_of(IDiaSymbol *sym) {
  BSTR b = nullptr;
  std::string s;
  if (sym->get_name(&b) == S_OK) { s = narrow(b); SysFreeString(b); }
  return s;
}

template <typename F> static void each(IDiaSymbol *scope, enum SymTagEnum tag, F f) {
  IDiaEnumSymbols *e = nullptr;
  if (scope->findChildren(tag, nullptr, nsNone, &e) != S_OK || !e) return;
  IDiaSymbol *s = nullptr;
  ULONG got = 0;
  while (e->Next(1, &s, &got) == S_OK && got == 1) { f(s); s->Release(); }
  e->Release();
}

int wmain(int argc, wchar_t **argv) {
  if (argc < 2) { fwprintf(stderr, L"usage: diadump <file.pdb>\n"); return 2; }
  CoInitialize(nullptr);
  typedef HRESULT(WINAPI * GetClassObjectFn)(REFCLSID, REFIID, LPVOID *);
  HMODULE dll = LoadLibraryW(L"msdia140.dll");
  GetClassObjectFn get = dll ? (GetClassObjectFn)GetProcAddress(dll, "DllGetClassObject") : nullptr;
  IClassFactory *factory = nullptr;
  IDiaDataSource *source = nullptr;
  if (!get || FAILED(get(__uuidof(DiaSource), IID_IClassFactory, (void **)&factory)) ||
      FAILED(factory->CreateInstance(nullptr, __uuidof(IDiaDataSource), (void **)&source))) {
    fwprintf(stderr, L"cannot load msdia140.dll\n");
    return 1;
  }
  IDiaSession *session = nullptr;
  IDiaSymbol *global = nullptr;
  if (FAILED(source->loadDataFromPdb(argv[1])) || FAILED(source->openSession(&session)) ||
      FAILED(session->get_globalScope(&global))) {
    fwprintf(stderr, L"cannot open %s\n", argv[1]);
    return 1;
  }

  each(global, SymTagCompiland, [&](IDiaSymbol *c) {
    printf("MODULE %s\n", name_of(c).c_str());
    // Lines: for each source file of the compiland.
    IDiaEnumSourceFiles *files = nullptr;
    if (session->findFile(c, nullptr, nsNone, &files) == S_OK && files) {
      IDiaSourceFile *file = nullptr;
      ULONG got = 0;
      while (files->Next(1, &file, &got) == S_OK && got == 1) {
        BSTR fname = nullptr;
        file->get_fileName(&fname);
        std::string fn = narrow(fname);
        SysFreeString(fname);
        IDiaEnumLineNumbers *lines = nullptr;
        if (session->findLines(c, file, &lines) == S_OK && lines) {
          IDiaLineNumber *ln = nullptr;
          ULONG gl = 0;
          while (lines->Next(1, &ln, &gl) == S_OK && gl == 1) {
            DWORD rva = 0, len = 0, line = 0;
            ln->get_relativeVirtualAddress(&rva);
            ln->get_length(&len);
            ln->get_lineNumber(&line);
            printf("LINE %X %X %u %s\n", rva, len, line, fn.c_str());
            ln->Release();
          }
          lines->Release();
        }
        file->Release();
      }
      files->Release();
    }
    each(c, SymTagFunction, [&](IDiaSymbol *f) {
      DWORD rva = 0;
      ULONGLONG len = 0;
      f->get_relativeVirtualAddress(&rva);
      f->get_length(&len);
      printf("FUNC %X %llX %s\n", rva, len, name_of(f).c_str());
    });
  });

  each(global, SymTagPublicSymbol, [&](IDiaSymbol *p) {
    DWORD sec = 0, off = 0;
    p->get_addressSection(&sec);
    p->get_addressOffset(&off);
    printf("PUBLIC %X:%X %s\n", sec, off, name_of(p).c_str());
  });
  each(global, SymTagData, [&](IDiaSymbol *d) {
    DWORD rva = 0;
    if (d->get_relativeVirtualAddress(&rva) == S_OK) printf("DATA %X %s\n", rva, name_of(d).c_str());
  });
  each(global, SymTagUDT, [&](IDiaSymbol *u) {
    ULONGLONG size = 0;
    u->get_length(&size);
    printf("UDT %llX %s\n", size, name_of(u).c_str());
  });
  return 0;
}
