#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdio>
#include <ctime>

namespace
{
    std::atomic_bool g_started{ false };
    HANDLE g_consoleOutput = INVALID_HANDLE_VALUE;

    // 特征码
    const std::vector<int> kQueryPattern = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF9, 0x48, 0x85, 0xD2, 0x75, 0x0D, 
        0x32, 0xC0, 0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3, 0x48, 0x8D, 0x0D, -1, -1, -1, -1, 
        0xFF, 0x15, -1, -1, -1, -1, 0x48, 0x83, 0x38, 0x00, 0x74, 0x3B, 0x48, 0x8B, 0x07, 0x48, 0x8B, 0xCF, 0xFF, 0x50, 0x60, 0x83, 0xF8, 0x02, 0x75, 0x2D, 
        0x48, 0x8D, 0x0D, -1, -1, -1, -1, 0x40, 0xB7, 0x01, 0xFF, 0x15, -1, -1, -1, -1, 0x48, 0x8B, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x18, 0x8B, 0xC0, 0x48, 0x89, 0x03
    };

    const std::vector<int> kDatePattern = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x33, 0xC0, 0x48, 0x8D, 0x0D, -1, -1, -1, -1, 0x48, 0x89, 0x02, 
        0x48, 0x8B, 0xDA, 0x48, 0x89, 0x42, 0x08, 0x48, 0x89, 0x42, 0x10, 0x48, 0x89, 0x42, 0x18, 0x88, 0x42, 0x20, 
        0xFF, 0x15, -1, -1, -1, -1, 0x48, 0x8B, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x18, 0x48, 0x8B, 0x0D, -1, -1, -1, -1, 
        0x8B, 0xC0, 0x48, 0x8B, 0x89, 0x60, 0x02, 0x00, 0x00, 0x48, 0x85, 0xC9, 0x74, 0x15, 0x48, 0x8B, 0x49, 0x10, 
        0x48, 0x85, 0xC9, 0x74, 0x0C, 0x0F, 0xB6, 0x89, 0xF0, 0xBF, 0x00, 0x00, 0x80, 0xE1, 0x01, 0xEB, 0x02, 0x32, 0xC9, 
        0x88, 0x4B, 0x20, 0x48, 0x8D, 0x4B, 0x18, 0x48, 0x89, 0x43, 0x18, 0xE8, -1, -1, -1, -1, 0x8B, 0x48, 0x14, 0x81, 0xC1, 
        0x6C, 0x07, 0x00, 0x00, 0x89, 0x0B
    };

    constexpr unsigned state_slot = 0x60;
    constexpr std::uint32_t flag_offsets[3] = { 0x260, 0x10, 0xBFF0 };

    // 全局指针
    std::atomic<uintptr_t> g_flag_global{ 0 };
    uintptr_t g_query_tramp = 0;
    uintptr_t g_date_tramp = 0;

    // 原函数指针
    typedef char(__fastcall* QueryFn)(void* session, uint64_t* out);
    typedef uintptr_t(__fastcall* DateFn)(uintptr_t self, uintptr_t out);
    QueryFn g_query_orig = nullptr;
    DateFn g_date_orig = nullptr;

    // 缓存逻辑变量
    std::atomic<bool> g_active{ true };
    std::atomic<std::uint32_t> g_reuse_for_ms{ 1000 }; // 缓存 1 秒
    std::atomic<std::uint64_t> g_kept{ 0 };

    std::uint32_t ms32() noexcept {
        LARGE_INTEGER freq, now;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&now);
        return static_cast<std::uint32_t>(static_cast<std::uint64_t>(now.QuadPart) * 1000ULL / static_cast<std::uint64_t>(freq.QuadPart));
    }

    bool fresh(std::uint32_t& value) noexcept {
        const auto k = g_kept.load(std::memory_order_relaxed);
        if (!k) return false;
        const auto age = ms32() - static_cast<std::uint32_t>(k);
        if (age >= g_reuse_for_ms.load(std::memory_order_relaxed)) return false;
        value = static_cast<std::uint32_t>(k >> 32) + age / 1000;
        return true;
    }

    void keep(std::uint32_t value) noexcept {
        g_kept.store(std::uint64_t(value) << 32 | ms32(), std::memory_order_relaxed);
    }

    bool read_flag(std::uint8_t& flag) noexcept {
        const auto global = g_flag_global.load(std::memory_order_relaxed);
        if (!global) return false;
        __try {
            auto p = *reinterpret_cast<volatile const std::uintptr_t*>(global);
            if (!p) return false;
            flag = 0;
            p = *reinterpret_cast<volatile const std::uintptr_t*>(p + flag_offsets[0]);
            if (p) p = *reinterpret_cast<volatile const std::uintptr_t*>(p + flag_offsets[1]);
            if (p) flag = *reinterpret_cast<volatile const std::uint8_t*>(p + flag_offsets[2]) & 1;
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    char __fastcall query_detour(void* session, std::uint64_t* out) {
        const auto next = g_query_orig;
        std::uint32_t value{};
        const bool on = g_active.load(std::memory_order_relaxed);
        if (!out || !on || !fresh(value)) {
            const char r = next(session, out);
            if (on && out && r == 1) {
                keep(static_cast<std::uint32_t>(*out));
            }
            return r;
        }
        using State = std::uint32_t(__fastcall*)(void*);
        const auto state = (*reinterpret_cast<State* const*>(session))[state_slot / sizeof(void*)](session);
        if (state != 2) {
            return next(session, out);
        }
        *out = value;
        return 1;
    }

    uintptr_t __fastcall date_detour(uintptr_t self, uintptr_t out) {
        const auto next = g_date_orig;
        std::uint32_t value{};
        std::uint8_t flag{};
        const bool on = g_active.load(std::memory_order_relaxed);
        if (!on || !fresh(value) || !read_flag(flag)) {
            const auto r = next(self, out);
            if (on) {
                keep(*reinterpret_cast<const std::uint32_t*>(out + 0x18));
            }
            return r;
        }
        std::tm parts{};
        const __time64_t time = value;
        if (_gmtime64_s(&parts, &time) != 0) return next(self, out);
        auto* d = reinterpret_cast<std::uint32_t*>(out);
        d[0] = static_cast<std::uint32_t>(parts.tm_year + 1900);
        d[1] = static_cast<std::uint32_t>(parts.tm_mon + 1);
        d[2] = static_cast<std::uint32_t>(parts.tm_mday);
        d[3] = static_cast<std::uint32_t>(parts.tm_hour);
        d[4] = static_cast<std::uint32_t>(parts.tm_min);
        d[5] = static_cast<std::uint32_t>(parts.tm_sec);
        *reinterpret_cast<std::uint64_t*>(out + 0x18) = value;
        *reinterpret_cast<std::uint8_t*>(out + 0x20) = flag;
        return out;
    }

    // --- 基础工具 ---
    void InitConsole()
    {
        if (!GetConsoleWindow()) { AllocConsole(); }
        SetConsoleTitleW(L"MHW ServerTime");
        g_consoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_consoleOutput == nullptr || g_consoleOutput == INVALID_HANDLE_VALUE) {
            g_consoleOutput = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (g_consoleOutput != INVALID_HANDLE_VALUE) { SetStdHandle(STD_OUTPUT_HANDLE, g_consoleOutput); }
        }
    }

    void ConsolePrint(const wchar_t* message)
    {
        if (!message || g_consoleOutput == INVALID_HANDLE_VALUE) return;
        SYSTEMTIME now{}; GetLocalTime(&now);
        wchar_t line[768]{};
        const int length = swprintf_s(line, _countof(line), L"[ %02u:%02u:%02u ] %s\r\n", (unsigned)now.wHour, (unsigned)now.wMinute, (unsigned)now.wSecond, message);
        if (length > 0) { DWORD written = 0; WriteConsoleW(g_consoleOutput, line, (DWORD)length, &written, nullptr); }
    }

    uintptr_t ScanPattern(const char* moduleName, const std::vector<int>& pattern)
    {
        if (pattern.empty()) return 0;
        HMODULE module = GetModuleHandleA(moduleName);
        if (!module) return 0;

        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) return 0;

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + static_cast<uintptr_t>(dosHeader->e_lfanew));
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

        const auto* sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            const auto& section = sections[i];
            if (std::memcmp(section.Name, ".text", 5) != 0) continue;

            const size_t textSize = static_cast<size_t>(section.Misc.VirtualSize);
            if (textSize < pattern.size()) return 0;

            const uint8_t* text = reinterpret_cast<const uint8_t*>(moduleBase + section.VirtualAddress);
            const uint8_t* textEnd = text + textSize - pattern.size() + 1;
            const uint8_t firstByte = static_cast<uint8_t>(pattern[0]);

            for (const uint8_t* q = text; q < textEnd; )
            {
                q = static_cast<const uint8_t*>(std::memchr(q, firstByte, static_cast<size_t>(textEnd - q)));
                if (!q) break;

                bool found = true;
                for (size_t j = 1; j < pattern.size(); ++j)
                {
                    if (pattern[j] != -1 && q[j] != static_cast<uint8_t>(pattern[j]))
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
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        const uintptr_t granularity = si.dwAllocationGranularity; 
        const uintptr_t maxDistance = 0x7FFF0000ULL;
        const uintptr_t lowerBound = target > maxDistance ? target - maxDistance : granularity;
        const uintptr_t upperBound = target + maxDistance;

        uintptr_t addr = target & ~(granularity - 1);
        while (addr > lowerBound)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) break;
            uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            
            if (mbi.State == MEM_FREE)
            {
                uintptr_t regionEnd = regionBase + mbi.RegionSize;
                uintptr_t allocAddr = (regionEnd - size) & ~(granularity - 1);
                while (allocAddr >= regionBase && allocAddr >= lowerBound)
                {
                    void* memory = VirtualAlloc(reinterpret_cast<void*>(allocAddr), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (memory) return reinterpret_cast<uintptr_t>(memory);
                    if (allocAddr < granularity) break;
                    allocAddr -= granularity;
                }
            }
            if (regionBase >= granularity && regionBase - granularity > lowerBound) addr = regionBase - granularity;
            else break;
        }
        return 0;
    }

    uintptr_t get_rip_target(uintptr_t match, unsigned at, unsigned len, unsigned disp_at) {
        int32_t disp = 0;
        memcpy(&disp, (void*)(match + at + disp_at), 4);
        return match + at + len + disp;
    }

    bool SetupHooks()
    {
        uintptr_t query_site = ScanPattern("MonsterHunterWorld.exe", kQueryPattern);
        uintptr_t date_site = ScanPattern("MonsterHunterWorld.exe", kDatePattern);
        
        if (!query_site || !date_site) {
            ConsolePrint(L"[ServerTime] Failed: Patterns not found.");
            return false;
        }
        
        // 验证 Steam 接口
        uintptr_t context = get_rip_target(date_site, 0x0C, 7, 3);
        uintptr_t import = get_rip_target(date_site, 0x28, 6, 2);
        if (get_rip_target(query_site, 0x22, 7, 3) != context || get_rip_target(query_site, 0x29, 6, 2) != import) {
            ConsolePrint(L"[ServerTime] Failed: Query pattern mismatch.");
            return false;
        }
        if (get_rip_target(query_site, 0x43, 7, 3) != context || get_rip_target(query_site, 0x4D, 6, 2) != import) {
            ConsolePrint(L"[ServerTime] Failed: Query pattern mismatch (2).");
            return false;
        }
        
        g_flag_global.store(get_rip_target(date_site, 0x37, 7, 3));

        // 处理 Query
        uintptr_t query_cave = AllocNear(query_site, 0x100);
        g_query_tramp = AllocNear(query_site, 0x100);
        if (!query_cave || !g_query_tramp) return false;

        uint8_t q_tramp[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uintptr_t q_ret = query_site + 5;
        memcpy(&q_tramp[7], &q_ret, 8);
        memcpy((void*)g_query_tramp, q_tramp, sizeof(q_tramp));
        g_query_orig = (QueryFn)g_query_tramp;

        uint8_t q_cave[] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uint64_t q_hook = (uint64_t)&query_detour;
        memcpy(&q_cave[2], &q_hook, 8);
        memcpy((void*)query_cave, q_cave, sizeof(q_cave));

        DWORD oldProtect;
        uint8_t jmp_patch[] = { 0xE9, 0,0,0,0 };
        
        int32_t q_rel = (int32_t)(query_cave - (query_site + 5));
        memcpy(&jmp_patch[1], &q_rel, 4);
        VirtualProtect((void*)query_site, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((void*)query_site, jmp_patch, 5);
        FlushInstructionCache(GetCurrentProcess(), (void*)query_site, 5);
        VirtualProtect((void*)query_site, 5, oldProtect, &oldProtect);

        // 处理 Date
        uintptr_t date_cave = AllocNear(date_site, 0x100);
        g_date_tramp = AllocNear(date_site, 0x100);
        if (!date_cave || !g_date_tramp) return false;

        uint8_t d_tramp[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uintptr_t d_ret = date_site + 5;
        memcpy(&d_tramp[7], &d_ret, 8);
        memcpy((void*)g_date_tramp, d_tramp, sizeof(d_tramp));
        g_date_orig = (DateFn)g_date_tramp;

        uint8_t d_cave[] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uint64_t d_hook = (uint64_t)&date_detour;
        memcpy(&d_cave[2], &d_hook, 8);
        memcpy((void*)date_cave, d_cave, sizeof(d_cave));

        int32_t d_rel = (int32_t)(date_cave - (date_site + 5));
        memcpy(&jmp_patch[1], &d_rel, 4);
        VirtualProtect((void*)date_site, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((void*)date_site, jmp_patch, 5);
        FlushInstructionCache(GetCurrentProcess(), (void*)date_site, 5);
        VirtualProtect((void*)date_site, 5, oldProtect, &oldProtect);

        ConsolePrint(L"[ServerTime] Hooks installed successfully.");
        return true;
    }

    void ThreadLoop()
    {
        InitConsole();
        ConsolePrint(L"[ServerTime] DLL Loaded. Waiting 10 seconds...");
        Sleep(10000);

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (SetupHooks()) return;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            Sleep(kRetryInterval);
        }

        ConsolePrint(L"[ServerTime] Failed after 30 attempts.");
        g_started.store(false, std::memory_order_release);
    }
} // namespace

__declspec(dllexport) bool Load()
{
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return true;

    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        ThreadLoop();
        return 0;
    }, nullptr, 0, nullptr);

    if (!thread) {
        g_started.store(false, std::memory_order_release);
        return false;
    }
    CloseHandle(thread);
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        Load();
    }
    return TRUE;
}
