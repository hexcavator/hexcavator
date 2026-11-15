// diasymbolize: what the DIA SDK says is at each RVA of an image (its
// function, the functions inlined there, and their source lines), as the
// reference for `hexc symbolize`'s PDB lookups.
//
// Build with build.cmd (it puts msdia140.dll next to diasymbolize.exe).
//
// usage: diasymbolize <file.pdb> < rvas
//
// Reads RVAs (hexadecimal, one per line) on standard input and writes, for
// each, a line of JSON, innermost frame first:
//   {"rva":"0x1043","frames":[{"name":"square","file":"...","line":5,"inlined":true},...]}

#include <windows.h>
#include <dia2.h>
#include <cstdio>
#include <cstdlib>
#include <string>

static std::string narrow(const wchar_t *w) {
  if (!w) return std::string();
  int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
  std::string s(n > 0 ? n - 1 : 0, '\0');
  if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
  return s;
}

static std::string json(const std::string &s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') { out += '\\'; out += (char)c; }
    else if (c < 0x20) { char b[8]; sprintf_s(b, "\\u%04x", c); out += b; }
    else out += (char)c;
  }
  return out + "\"";
}

static std::string name_of(IDiaSymbol *sym) {
  BSTR b = nullptr;
  std::string s;
  if (sym->get_name(&b) == S_OK) { s = narrow(b); SysFreeString(b); }
  return s;
}

// The first line of `lines`: its file and line number.
static bool first_line(IDiaEnumLineNumbers *lines, std::string &file, DWORD &line) {
  if (!lines) return false;
  IDiaLineNumber *l = nullptr;
  ULONG got = 0;
  bool ok = false;
  if (lines->Next(1, &l, &got) == S_OK && got == 1) {
    l->get_lineNumber(&line);
    IDiaSourceFile *f = nullptr;
    if (l->get_sourceFile(&f) == S_OK && f) {
      BSTR b = nullptr;
      if (f->get_fileName(&b) == S_OK) { file = narrow(b); SysFreeString(b); }
      f->Release();
    }
    l->Release();
    ok = true;
  }
  lines->Release();
  return ok;
}

static std::string frame(const std::string &name, const std::string &file, DWORD line, bool inlined) {
  return "{\"name\":" + json(name) + ",\"file\":" + json(file) + ",\"line\":" + std::to_string(line) +
         ",\"inlined\":" + (inlined ? "true" : "false") + "}";
}

int wmain(int argc, wchar_t **argv) {
  if (argc < 2) { fwprintf(stderr, L"usage: diasymbolize <file.pdb> < rvas\n"); return 2; }
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
  if (FAILED(source->loadDataFromPdb(argv[1])) || FAILED(source->openSession(&session))) {
    fwprintf(stderr, L"cannot open %s\n", argv[1]);
    return 1;
  }
  char buf[64];
  while (fgets(buf, sizeof buf, stdin)) {
    DWORD rva = (DWORD)strtoull(buf, nullptr, 16);
    std::string frames;
    IDiaSymbol *fn = nullptr;
    if (session->findSymbolByRVA(rva, SymTagFunction, &fn) == S_OK && fn) {
      // The inline frames, innermost first.
      IDiaEnumSymbols *inl = nullptr;
      if (session->findInlineFramesByRVA(fn, rva, &inl) == S_OK && inl) {
        IDiaSymbol *s = nullptr;
        ULONG got = 0;
        while (inl->Next(1, &s, &got) == S_OK && got == 1) {
          std::string file;
          DWORD line = 0;
          IDiaEnumLineNumbers *lines = nullptr;
          if (s->findInlineeLinesByRVA(rva, 1, &lines) == S_OK) first_line(lines, file, line);
          if (!frames.empty()) frames += ",";
          frames += frame(name_of(s), file, line, true);
          s->Release();
        }
        inl->Release();
      }
      std::string file;
      DWORD line = 0;
      IDiaEnumLineNumbers *lines = nullptr;
      if (session->findLinesByRVA(rva, 1, &lines) == S_OK) first_line(lines, file, line);
      if (!frames.empty()) frames += ",";
      frames += frame(name_of(fn), file, line, false);
      fn->Release();
    }
    printf("{\"rva\":\"0x%lx\",\"frames\":[%s]}\n", rva, frames.c_str());
    fflush(stdout);
  }
  return 0;
}
