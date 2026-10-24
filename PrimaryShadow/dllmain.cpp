#include <windows.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>

namespace
{
    std::atomic_bool g_started{ false };
    HMODULE g_hModule = nullptr;

    const std::vector<int> kCSystemCtorPattern = {
        0x48, 0x83, 0xC1, 0x08, 0xFF, 0x15, -1, -1, -1, -1,
        0x48, 0x8B, 0xC3, 0xC6, 0x43, 0x30, 0x01,
        0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
    };
    constexpr int kCSystemCtorOffset = -19;

    constexpr size_t kPatchLength = 6; // 40 53 48 83 EC XX
    constexpr size_t kCaveSize = 0x100;

    constexpr uintptr_t kVolumeRendererEnabledOffset = 0x38;

    constexpr size_t kMaxSingletons = 8192; // 加大容量
    void* g_singletons[kMaxSingletons] = {};
    std::atomic<size_t> g_singletonCount{ 0 };

    std::atomic<void*> g_volumeRenderer{ nullptr };
    uintptr_t g_manualVolumeRendererAddr = 0;

    uintptr_t g_cSystemCtorAddr = 0;
    uintptr_t g_cSystemCtorCave = 0;

    std::wstring g_iniPath;
    std::wstring g_logPath;
    FILETIME g_iniWriteTime{};
    FILE* g_logFile = nullptr;

    void Log(const char* fmt, ...)
    {
        char body[1024] = {};
        va_list args;
        va_start(args, fmt);
        vsnprintf_s(body, _countof(body), _TRUNCATE, fmt, args);
        va_end(args);

        SYSTEMTIME now{};
        GetLocalTime(&now);

        char line[1280] = {};
        sprintf_s(
            line, _countof(line),
            "[PrimaryShadow %02u:%02u:%02u] %s\r\n",
            (unsigned)now.wHour, (unsigned)now.wMinute, (unsigned)now.wSecond,
            body);

        OutputDebugStringA(line);

        if (g_logFile)
        {
            fputs(line, g_logFile);
            fflush(g_logFile);
        }
    }

    uintptr_t ScanPattern(const char* moduleName, const std::vector<int>& pattern)
    {
        if (pattern.empty()) return 0;
        HMODULE module = GetModuleHandleA(moduleName);
        if (!module) return 0;

        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) return 0;

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + (uintptr_t)dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

        const auto* sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            const auto& section = sections[i];
            if (std::memcmp(section.Name, ".text", 5) != 0) continue;

            const size_t textSize = (size_t)section.Misc.VirtualSize;
            if (textSize < pattern.size()) return 0;

            const uint8_t* text = reinterpret_cast<const uint8_t*>(moduleBase + section.VirtualAddress);
            const uint8_t* textEnd = text + textSize - pattern.size() + 1;
            const uint8_t firstByte = (uint8_t)pattern[0];

            for (const uint8_t* q = text; q < textEnd;)
            {
                q = (const uint8_t*)std::memchr(q, firstByte, (size_t)(textEnd - q));
                if (!q) break;

                bool found = true;
                for (size_t j = 1; j < pattern.size(); ++j)
                {
                    if (pattern[j] != -1 && q[j] != (uint8_t)pattern[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found) return reinterpret_cast<uintptr_t>(q);
                ++q;
            }
            return 0;
        }
        return 0;
    }

    uintptr_t AllocNear(uintptr_t target, size_t size)
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        const uintptr_t granularity = si.dwAllocationGranularity;
        const uintptr_t searchRange = 0x10000000ULL;
        const uintptr_t lowerBound = target > searchRange ? target - searchRange : granularity;
        const uintptr_t upperBound = target + searchRange;

        uintptr_t addr = target & ~(granularity - 1);
        while (addr > lowerBound)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
            uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
            if (mbi.State == MEM_FREE)
            {
                uintptr_t regionEnd = regionBase + mbi.RegionSize;
                uintptr_t allocAddr = (regionEnd - size) & ~(granularity - 1);
                while (allocAddr >= regionBase && allocAddr >= lowerBound)
                {
                    void* memory = VirtualAlloc((void*)allocAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (memory) return (uintptr_t)memory;
                    if (allocAddr < granularity) break;
                    allocAddr -= granularity;
                }
            }
            if (regionBase >= granularity && regionBase - granularity > lowerBound)
                addr = regionBase - granularity;
            else break;
        }

        addr = (target & ~(granularity - 1)) + granularity;
        while (addr < upperBound)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
            uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
            uintptr_t regionEnd = regionBase + mbi.RegionSize;
            if (mbi.State == MEM_FREE)
            {
                uintptr_t allocAddr = regionBase < addr ? addr : regionBase;
                allocAddr = (allocAddr + granularity - 1) & ~(granularity - 1);
                while (allocAddr + size <= regionEnd && allocAddr < upperBound)
                {
                    void* memory = VirtualAlloc((void*)allocAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (memory) return (uintptr_t)memory;
                    allocAddr += granularity;
                }
            }
            if (regionEnd < upperBound && regionEnd > addr) addr = regionEnd;
            else break;
        }
        return 0;
    }

    extern "C" void RecordSingleton(void* thisPtr)
    {
        const size_t idx = g_singletonCount.fetch_add(1, std::memory_order_acq_rel);
        if (idx < kMaxSingletons)
        {
            g_singletons[idx] = thisPtr;
        }
    }

    bool TryReadU64(uintptr_t addr, uint64_t& out)
    {
        __try { out = *reinterpret_cast<uint64_t*>(addr); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    bool IsReadableString(uintptr_t addr)
    {
        __try
        {
            const char* p = (const char*)addr;
            char c = p[0];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_')) return false;
            for (int i = 1; i < 128; i++)
            {
                char ch = p[i];
                if (ch == 0) return true;
                if (ch < 0x20 || ch > 0x7E) return false;
            }
            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    void* GetDtiSafe(void* inst)
    {
        __try
        {
            void** vtable = *reinterpret_cast<void***>(inst);
            if (!vtable || !vtable[4]) return nullptr;
            using GetDtiFn = void* (*)(void*);
            auto fn = reinterpret_cast<GetDtiFn>(vtable[4]);
            return fn(inst);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }

    bool TryWriteBool(uintptr_t addr, bool value)
    {
        __try { *reinterpret_cast<bool*>(addr) = value; return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    // 暴破所有可能的指针，并放宽读取条件
    const char* ReadDtiNameSafe(void* dti)
    {
        const uintptr_t base = (uintptr_t)dti;
        const uintptr_t candidates[] = { 0x20, 0x28, 0x08, 0x10, 0x18 };
        for (size_t i = 0; i < 5; i++)
        {
            uint64_t namePtr = 0;
            if (!TryReadU64(base + candidates[i], namePtr)) continue;
            if (namePtr < 0x10000) continue;

            // 首先尝试严格匹配
            if (IsReadableString((uintptr_t)namePtr))
                return (const char*)namePtr;

            // 如果失败，看看是不是解析到了相邻的单例地址
            if (namePtr > 0x140000000 && namePtr < 0x150000000)
            {
                // 可能是字符串直接是内联在 DTI 结构里的？或者忽略格式
                __try {
                    const char* p = (const char*)namePtr;
                    // 强制看看前两个字符是不是英文字母
                    if ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
                        return p;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
        return nullptr;
    }

    bool InstallCSystemCtorHook()
    {
        HMODULE module = GetModuleHandleA("MonsterHunterWorld.exe");
        if (!module) return false;

        const uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", kCSystemCtorPattern);
        if (!scanAddr) return false;

        const uintptr_t ctorAddr = scanAddr + kCSystemCtorOffset;
        const uint8_t* entry = (const uint8_t*)ctorAddr;
        if (entry[0] != 0x40 || entry[1] != 0x53 || entry[2] != 0x48 || entry[3] != 0x83 || entry[4] != 0xEC)
            return false;

        const uint8_t stackSub = entry[5];
        const uintptr_t returnAddr = ctorAddr + kPatchLength;
        const uintptr_t caveAddr = AllocNear(ctorAddr, kCaveSize);
        if (!caveAddr) return false;

        uint8_t code[0x80] = {};
        size_t p = 0;

        code[p++] = 0x40; code[p++] = 0x53;
        code[p++] = 0x48; code[p++] = 0x83; code[p++] = 0xEC; code[p++] = stackSub;

        code[p++] = 0x50; code[p++] = 0x51; code[p++] = 0x52;
        code[p++] = 0x41; code[p++] = 0x50; code[p++] = 0x41; code[p++] = 0x51;
        code[p++] = 0x41; code[p++] = 0x52; code[p++] = 0x41; code[p++] = 0x53;

        code[p++] = 0x48; code[p++] = 0xB8;
        const uint64_t fnAddr = (uint64_t)&RecordSingleton;
        std::memcpy(&code[p], &fnAddr, 8); p += 8;

        code[p++] = 0xFF; code[p++] = 0xD0;

        code[p++] = 0x41; code[p++] = 0x5B; code[p++] = 0x41; code[p++] = 0x5A;
        code[p++] = 0x41; code[p++] = 0x59; code[p++] = 0x41; code[p++] = 0x58;
        code[p++] = 0x5A; code[p++] = 0x59; code[p++] = 0x58;

        const size_t jmp_pos = p;
        code[p++] = 0xE9;
        const size_t jmp_disp_pos = p;
        p += 4;

        int64_t backDisp = (int64_t)returnAddr - (int64_t)(caveAddr + jmp_pos + 5);
        int32_t backDisp32 = (int32_t)backDisp;
        std::memcpy(&code[jmp_disp_pos], &backDisp32, 4);

        std::memcpy((void*)caveAddr, code, p);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)caveAddr, p);

        int64_t patchDisp = (int64_t)caveAddr - (int64_t)(ctorAddr + 5);
        int32_t patchDisp32 = (int32_t)patchDisp;

        uint8_t jmpPatch[kPatchLength] = { 0xE9, 0, 0, 0, 0, 0x90 };
        std::memcpy(&jmpPatch[1], &patchDisp32, 4);

        DWORD oldProtect = 0;
        if (!VirtualProtect((void*)ctorAddr, kPatchLength, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;

        std::memcpy((void*)ctorAddr, jmpPatch, kPatchLength);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)ctorAddr, kPatchLength);
        VirtualProtect((void*)ctorAddr, kPatchLength, oldProtect, &oldProtect);

        g_cSystemCtorAddr = ctorAddr;
        g_cSystemCtorCave = caveAddr;
        return true;
    }

    void DumpSingletons()
    {
        const size_t count = g_singletonCount.load(std::memory_order_acquire);
        const size_t limit = count < 10 ? count : 10; // 只打印前 10 个，防止日志太长
        Log("dumping %zu singletons (showing up to %zu)", count, limit);
        for (size_t i = 0; i < limit; i++)
        {
            void* inst = g_singletons[i];
            if (!inst) continue;
            void* dti = GetDtiSafe(inst);
            const char* name = dti ? ReadDtiNameSafe(dti) : nullptr;
            Log("  [%zu] inst=0x%p dti=0x%p name=%s", i, inst, dti, name ? name : "?");
        }
    }

    bool TryFindVolumeRenderer()
    {
        const size_t count = g_singletonCount.load(std::memory_order_acquire);
        for (size_t i = 0; i < count; i++)
        {
            void* inst = g_singletons[i];
            if (!inst) continue;
            void* dti = GetDtiSafe(inst);
            if (!dti) continue;
            const char* name = ReadDtiNameSafe(dti);
            if (name && std::strcmp(name, "sVolumeRenderer") == 0)
            {
                g_volumeRenderer.store(inst, std::memory_order_release);
                Log("found sVolumeRenderer at 0x%p (index %zu)", inst, i);
                return true;
            }
        }
        return false;
    }

    struct Settings { int volumeRendering = -1; uintptr_t volumeRendererAddress = 0; };
    bool TryParseInt(const wchar_t* s, int& out) {
        if (!s || !s[0]) return false;
        wchar_t* end = nullptr;
        long v = wcstol(s, &end, 10);
        if (end == s) return false;
        while (*end == L' ' || *end == L'\t') ++end;
        if (*end != 0) return false;
        out = (int)v;
        return true;
    }
    int ReadInt(const wchar_t* section, const wchar_t* key, int def, const wchar_t* file) {
        wchar_t buf[64] = {};
        GetPrivateProfileStringW(section, key, L"", buf, _countof(buf), file);
        if (buf[0] == 0) return def;
        int v = 0;
        return TryParseInt(buf, v) ? v : def;
    }
    uintptr_t ReadUIntPtr(const wchar_t* section, const wchar_t* key, uintptr_t def, const wchar_t* file) {
        wchar_t buf[64] = {};
        GetPrivateProfileStringW(section, key, L"", buf, _countof(buf), file);
        if (buf[0] == 0) return def;
        wchar_t* end = nullptr;
        unsigned long long v = wcstoull(buf, &end, 0);
        return end == buf ? def : (uintptr_t)v;
    }
    Settings LoadSettings(const std::wstring& path) {
        Settings s;
        s.volumeRendering = ReadInt(L"Settings", L"VolumeRendering", -1, path.c_str());
        s.volumeRendererAddress = ReadUIntPtr(L"Settings", L"VolumeRendererAddress", 0, path.c_str());
        return s;
    }
    FILETIME GetFileWriteTime(const std::wstring& path) {
        FILETIME ft{};
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
            ft = data.ftLastWriteTime;
        return ft;
    }
    void ApplyVolumeRendering(const Settings& s) {
        void* vr = g_volumeRenderer.load(std::memory_order_acquire);
        if (!vr && s.volumeRendererAddress) {
            vr = (void*)s.volumeRendererAddress;
            g_volumeRenderer.store(vr, std::memory_order_release);
        }
        if (!vr) return;
        if (s.volumeRendering < 0) return;
        const bool enabled = (s.volumeRendering != 0);
        const uintptr_t addr = (uintptr_t)vr + kVolumeRendererEnabledOffset;
        if (!TryWriteBool(addr, enabled)) {
            g_volumeRenderer.store(nullptr, std::memory_order_release);
        }
    }
    void CreateDefaultIni(const std::filesystem::path& path) {
        std::error_code ec;
        if (std::filesystem::exists(path, ec)) return;
        FILE* f = nullptr;
        _wfopen_s(&f, path.c_str(), L"w");
        if (!f) return;
        fputs("; Primary Shadow Tweak (Volume Rendering)\r\n\r\n[Settings]\r\n; -1 = 不修改, 0 = 强制关闭, 1 = 强制开启\r\nVolumeRendering=-1\r\n\r\n; 如果自动找不到，手填对象地址(0x开头)\r\nVolumeRendererAddress=0\r\n", f);
        fclose(f);
    }

    void Worker(HMODULE module)
    {
        wchar_t buf[MAX_PATH] = {};
        GetModuleFileNameW(module, buf, MAX_PATH);
        std::filesystem::path dllPath(buf);
        std::filesystem::path dir = dllPath.parent_path();
        std::wstring stem = dllPath.stem().wstring();
        g_iniPath = (dir / (stem + L".ini")).wstring();
        g_logPath = (dir / (stem + L".log")).wstring();

        _wfopen_s(&g_logFile, g_logPath.c_str(), L"w");
        Log("PrimaryShadow (Volume) loaded from %ls", dllPath.c_str());

        CreateDefaultIni(g_iniPath);
        Settings settings = LoadSettings(g_iniPath);
        g_iniWriteTime = GetFileWriteTime(g_iniPath);

        // 【关键改动】废弃 Sleep(300)，死死卡在这里等游戏模块加载完，并立刻注入
        Log("Trying to install cSystem::Ctor hook immediately...");
        while (!g_started.load()) {
            __try {
                if (InstallCSystemCtorHook()) {
                    Log("cSystem::Ctor hooked early!");
                    break;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            Sleep(10);
        }

        if (!g_started.load()) {
            // 等游戏进入主菜单或场景再开始找
            Sleep(8000);
            Log("recorded %zu singletons so far", g_singletonCount.load(std::memory_order_acquire));

            bool found = false;
            for (int i = 0; i < 30 && !found; ++i) {
                if (TryFindVolumeRenderer()) found = true;
                else Sleep(2000);
            }

            if (!found) {
                Log("sVolumeRenderer not found, dumping for diagnosis");
                DumpSingletons();
                Log("patch inactive; hook stays installed");
            }
        }

        while (g_started.load())
        {
            Sleep(10);
            if (!g_volumeRenderer.load(std::memory_order_acquire)) {
                // 如果没找到，每5秒尝试一次
                static DWORD lastRetry = 0;
                DWORD now = GetTickCount();
                if (now - lastRetry >= 5000) {
                    lastRetry = now;
                    TryFindVolumeRenderer();
                }
                continue;
            }

            ApplyVolumeRendering(settings);

            static int tick = 0;
            if (++tick >= 100) {
                tick = 0;
                FILETIME ft = GetFileWriteTime(g_iniPath);
                if (CompareFileTime(&ft, &g_iniWriteTime) != 0) {
                    g_iniWriteTime = ft;
                    Settings updated = LoadSettings(g_iniPath);
                    if (updated.volumeRendering != settings.volumeRendering || updated.volumeRendererAddress != settings.volumeRendererAddress) {
                        settings = updated;
                        if (settings.volumeRendererAddress) g_volumeRenderer.store((void*)settings.volumeRendererAddress, std::memory_order_release);
                        Log("reloaded: VolumeRendering=%d", settings.volumeRendering);
                    }
                }
            }
        }

        if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
    }
}

__declspec(dllexport) bool Load()
{
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return true;

    HMODULE module = g_hModule;
    if (!module) {
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)&Load, &module);
    }

    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        Worker((HMODULE)param);
        return 0;
    }, module, 0, nullptr);

    if (!thread) {
        g_started.store(false, std::memory_order_release);
        return false;
    }

    CloseHandle(thread);
    return true;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        g_hModule = module;
        Load();
    }
    return TRUE;
}
