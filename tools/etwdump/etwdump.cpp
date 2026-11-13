// etwdump: the oracle for Hexcavator's ETL reader.
//
// It reads a trace through Windows' own API (OpenTrace/ProcessTrace, with
// raw timestamps) and prints one line per event, which tests compare with
// what hexcavator-etl reads. With -schema it prints, for each distinct event
// kind, what TDH knows about its layout. With -props it prints each event's
// top-level properties as TDH extracts them (name and raw bytes), for
// comparison with hexcavator-etw's decoders.
//
// Usage:
//   etwdump [-schema | -props] [-provider GUID] trace.etl
//
// Output lines:
//   H <logfile header fields>             once, before the events
//   E <fields>                            one per event
//   S <provider> <id/opcode/version> ...  with -schema, one per event kind
//   P <index> name=hex ...                with -props, after its E line
//   T events=<n> buffers=<n>              once, at the end
//
// Events are printed in the order ProcessTrace delivers them. Payloads are
// hashed (FNV-1a 64) rather than printed, which keeps the output small and
// free of the trace's contents.

#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

namespace {

enum class Mode { Events, Schema, Props };
Mode g_mode = Mode::Events;
bool g_filter = false;
GUID g_provider = {};
uint64_t g_events = 0;
uint64_t g_buffers = 0;
std::set<std::tuple<std::string, uint16_t, uint8_t, uint8_t>> g_seen;

uint64_t fnv(const void* data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ull;
    auto p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

std::string guid(const GUID& g) {
    char s[40];
    snprintf(s, sizeof s, "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", g.Data1, g.Data2,
             g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5],
             g.Data4[6], g.Data4[7]);
    return s;
}

std::string narrow(const wchar_t* w) {
    if (!w) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, '\0');
    if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    for (auto& c : s)
        if (c == ' ') c = '_';
    return s;
}

const wchar_t* at(const TRACE_EVENT_INFO* info, ULONG offset) {
    return offset ? reinterpret_cast<const wchar_t*>(reinterpret_cast<const BYTE*>(info) + offset)
                  : nullptr;
}

TRACE_EVENT_INFO* event_info(EVENT_RECORD* e, std::vector<BYTE>& buf) {
    ULONG size = 0;
    ULONG status = TdhGetEventInformation(e, 0, nullptr, nullptr, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER) return nullptr;
    buf.resize(size);
    auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buf.data());
    if (TdhGetEventInformation(e, 0, nullptr, info, &size) != ERROR_SUCCESS) return nullptr;
    return info;
}

void print_schema(EVENT_RECORD* e) {
    auto& d = e->EventHeader.EventDescriptor;
    auto key = std::make_tuple(guid(e->EventHeader.ProviderId), d.Id, d.Opcode, d.Version);
    if (!g_seen.insert(key).second) return;
    std::vector<BYTE> buf;
    auto info = event_info(e, buf);
    printf("S %s id=%u op=%u v=%u", guid(e->EventHeader.ProviderId).c_str(), d.Id, d.Opcode,
           d.Version);
    if (!info) {
        printf(" none\n");
        return;
    }
    printf(" src=%d provider=%s task=%s opcode=%s event=%s", info->DecodingSource,
           narrow(at(info, info->ProviderNameOffset)).c_str(),
           narrow(at(info, info->TaskNameOffset)).c_str(),
           narrow(at(info, info->OpcodeNameOffset)).c_str(),
           narrow(at(info, info->EventNameOffset)).c_str());
    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        auto& p = info->EventPropertyInfoArray[i];
        printf(" %s", narrow(at(info, p.NameOffset)).c_str());
        if (p.Flags & PropertyStruct) {
            printf(":struct");
        } else {
            printf(":%u:%u", p.nonStructType.InType, p.nonStructType.OutType);
        }
        if (p.Flags & PropertyParamCount)
            printf(":count@%u", p.countPropertyIndex);
        else if (p.count != 1)
            printf(":count=%u", p.count);
        if (p.Flags & PropertyParamLength)
            printf(":len@%u", p.lengthPropertyIndex);
        else if (p.length)
            printf(":len=%u", p.length);
    }
    printf("\n");
}

void print_props(EVENT_RECORD* e) {
    std::vector<BYTE> buf;
    auto info = event_info(e, buf);
    printf("P %llu", static_cast<unsigned long long>(g_events));
    if (!info) {
        printf(" none\n");
        return;
    }
    std::vector<BYTE> value;
    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        auto& p = info->EventPropertyInfoArray[i];
        PROPERTY_DATA_DESCRIPTOR desc = {};
        desc.PropertyName = reinterpret_cast<ULONGLONG>(at(info, p.NameOffset));
        desc.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        if (TdhGetPropertySize(e, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS) {
            printf(" %s=?", narrow(at(info, p.NameOffset)).c_str());
            continue;
        }
        value.resize(size ? size : 1);
        if (TdhGetProperty(e, 0, nullptr, 1, &desc, size, value.data()) != ERROR_SUCCESS) {
            printf(" %s=?", narrow(at(info, p.NameOffset)).c_str());
            continue;
        }
        printf(" %s=", narrow(at(info, p.NameOffset)).c_str());
        for (ULONG j = 0; j < size; ++j) printf("%02x", value[j]);
    }
    printf("\n");
}

void WINAPI on_event(EVENT_RECORD* e) {
    auto& h = e->EventHeader;
    if (g_filter && !IsEqualGUID(h.ProviderId, g_provider)) {
        ++g_events;
        return;
    }
    if (g_mode == Mode::Schema) {
        ++g_events;
        print_schema(e);
        return;
    }
    auto& d = h.EventDescriptor;
    printf("E %lld %s id=%u v=%u ch=%u lvl=%u op=%u task=%u kw=%llx f=%x p=%x pid=%lu tid=%lu "
           "cpu=%u lg=%u pt=%llx act=%s len=%u h=%016llx",
           h.TimeStamp.QuadPart, guid(h.ProviderId).c_str(), d.Id, d.Version, d.Channel, d.Level,
           d.Opcode, d.Task, d.Keyword, h.Flags, h.EventProperty, h.ProcessId, h.ThreadId,
           e->BufferContext.ProcessorIndex, e->BufferContext.LoggerId, h.ProcessorTime,
           guid(h.ActivityId).c_str(), e->UserDataLength, fnv(e->UserData, e->UserDataLength));
    for (USHORT i = 0; i < e->ExtendedDataCount; ++i) {
        auto& x = e->ExtendedData[i];
        printf(" x=%u:%u:%016llx", x.ExtType, x.DataSize,
               fnv(reinterpret_cast<const void*>(x.DataPtr), x.DataSize));
    }
    printf("\n");
    if (g_mode == Mode::Props) print_props(e);
    ++g_events;
}

ULONG WINAPI on_buffer(EVENT_TRACE_LOGFILEW*) {
    ++g_buffers;
    return TRUE;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const wchar_t* path = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (!wcscmp(argv[i], L"-schema")) {
            g_mode = Mode::Schema;
        } else if (!wcscmp(argv[i], L"-props")) {
            g_mode = Mode::Props;
        } else if (!wcscmp(argv[i], L"-provider") && i + 1 < argc) {
            std::wstring s = argv[++i];
            if (s.front() != L'{') s = L"{" + s + L"}";
            if (FAILED(CLSIDFromString(s.c_str(), &g_provider))) {
                fprintf(stderr, "bad GUID\n");
                return 2;
            }
            g_filter = true;
        } else {
            path = argv[i];
        }
    }
    if (!path) {
        fprintf(stderr, "usage: etwdump [-schema | -props] [-provider GUID] trace.etl\n");
        return 2;
    }
    static char out[1 << 20];
    setvbuf(stdout, out, _IOFBF, sizeof out);

    EVENT_TRACE_LOGFILEW log = {};
    log.LogFileName = const_cast<wchar_t*>(path);
    log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback = on_event;
    log.BufferCallback = on_buffer;
    TRACEHANDLE handle = OpenTraceW(&log);
    if (handle == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr, "OpenTrace failed: %lu\n", GetLastError());
        return 1;
    }
    auto& lh = log.LogfileHeader;
    printf("H buffersize=%lu version=%08lx provider=%lu cpus=%lu end=%lld res=%lu maxsize=%lu "
           "mode=%08lx written=%lu ptr=%lu lost=%lu mhz=%lu boot=%lld freq=%lld start=%lld "
           "clock=%lu buflost=%lu\n",
           lh.BufferSize, lh.Version, lh.ProviderVersion, lh.NumberOfProcessors,
           lh.EndTime.QuadPart, lh.TimerResolution, lh.MaximumFileSize, lh.LogFileMode,
           lh.BuffersWritten, lh.PointerSize, lh.EventsLost, lh.CpuSpeedInMHz,
           lh.BootTime.QuadPart, lh.PerfFreq.QuadPart, lh.StartTime.QuadPart, lh.ReservedFlags,
           lh.BuffersLost);
    ULONG status = ProcessTrace(&handle, 1, nullptr, nullptr);
    CloseTrace(handle);
    printf("T events=%llu buffers=%llu status=%lu\n", static_cast<unsigned long long>(g_events),
           static_cast<unsigned long long>(g_buffers), status);
    return status == ERROR_SUCCESS ? 0 : 1;
}
