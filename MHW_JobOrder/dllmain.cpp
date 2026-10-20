#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdio>

namespace
{
    std::atomic_bool g_started{ false };
    HANDLE g_consoleOutput = INVALID_HANDLE_VALUE;

    const std::vector<int> kExecuteJobPattern = {
        0x40, 0x53, 0x55, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x49, 0x8B, 0xE8, 0x44, 0x8B, 0xFA, 0x48, 0x8B, 0xD9, 
        0x4D, 0x85, 0xC0, 0x74, 0x09, 0x44, 0x89, 0x89, 0xB0, 0x00, 0x00, 0x00, 0xEB, 0x07, 0x44, 0x8B, 0x89, 0xB0, 
        0x00, 0x00, 0x00
    };

    const std::vector<int> kCameraPattern = {
        0x46, 0x8B, 0x8C, 0xB6, 0xB0, 0xDE, 0x3D, 0x00, 0x4E, 0x8B, 0x04, 0xC6, 0x48, 0x8B, 0x0D, -1, -1, -1, -1, 
        0xE8, -1, -1, -1, -1, 0x45, 0x8B, 0xC7, 0x48, 0x8B, 0xD3, 0x48, 0x8B, 0xCD, 0xE8
    };
    constexpr uintptr_t kCallOffset = 19; 

    uintptr_t g_cameraReturn = 0;
    uintptr_t g_trampoline = 0;
    struct Entry { uint64_t q[4]; };
    Entry g_backup[8192];

    typedef void(__fastcall* ExecuteJobFn)(uintptr_t smain, int mode, uintptr_t jobs, uint32_t count, uintptr_t extra);
    ExecuteJobFn OriginalExecuteJob = nullptr;

    void __fastcall HookedExecuteJob(uintptr_t smain, int mode, uintptr_t jobs, uint32_t count, uintptr_t extra)
    {
        uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
        bool is_camera = (caller == g_cameraReturn);
        bool modified = false;
        uintptr_t list = jobs;
        uint32_t n = count;

        if (!list) {
            list = smain + 0xF0;
            __try { n = *reinterpret_cast<uint32_t*>(smain + 0xB0); } 
            __except (EXCEPTION_EXECUTE_HANDLER) { n = 0; }
        }

        if (is_camera && n > 1 && n <= 8192) {
            __try {
                memcpy(g_backup, reinterpret_cast<void*>(list), n * sizeof(Entry));
                Entry* target = reinterpret_cast<Entry*>(list);
                for (uint32_t i = 0; i < n; ++i) target[i] = g_backup[n - 1 - i];
                modified = true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        OriginalExecuteJob(smain, mode, jobs, count, extra);

        if (modified) {
            __try { memcpy(reinterpret_cast<void*>(list), g_backup, n * sizeof(Entry)); } 
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    void InitConsole()
    {
        if (!GetConsoleWindow()) { AllocConsole(); }
        SetConsoleTitleW(L"MHW JobOrder");
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

    bool SetupJobOrderHook()
    {
        uintptr_t executeSite = ScanPattern("MonsterHunterWorld.exe", kExecuteJobPattern);
        if (!executeSite) {
            ConsolePrint(L"[JobOrder] Failed: executeJob pattern not found.");
            return false;
        }

        uintptr_t cameraSite = ScanPattern("MonsterHunterWorld.exe", kCameraPattern);
        if (!cameraSite) {
            ConsolePrint(L"[JobOrder] Failed: camera pattern not found.");
            return false;
        }

        g_cameraReturn = cameraSite + kCallOffset + 5; 

        // 1. 申请跳板 (执行被覆盖的指令并跳回) 和 中转站 (跳向我们的函数)
        g_trampoline = AllocNear(executeSite, 0x100);
        uintptr_t cave = AllocNear(executeSite, 0x100);
        
        if (!g_trampoline || !cave) {
            ConsolePrint(L"[JobOrder] Failed: Memory allocation failed.");
            return false;
        }

        // 构建跳板：push rbx; push rbp; push r15; mov rax, executeSite+5; jmp rax
        uint8_t trampCode[] = {
            0x40, 0x53,                   // push rbx
            0x55,                         // push rbp
            0x41, 0x57,                   // push r15
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, imm64
            0xFF, 0xE0                    // jmp rax
        };
        uintptr_t returnAddress = executeSite + 5;
        memcpy(&trampCode[9], &returnAddress, 8);
        memcpy(reinterpret_cast<void*>(g_trampoline), trampCode, sizeof(trampCode));
        OriginalExecuteJob = reinterpret_cast<ExecuteJobFn>(g_trampoline);

        // 构建中转站：mov rax, HookedExecuteJob; jmp rax
        uint8_t stubCode[] = {
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 0xE0
        };
        uint64_t hookFunc = reinterpret_cast<uint64_t>(&HookedExecuteJob);
        memcpy(&stubCode[2], &hookFunc, 8);
        memcpy(reinterpret_cast<void*>(cave), stubCode, sizeof(stubCode));

        // 在函数头部写入 jmp 到 cave
        uint8_t jmpPatch[] = { 0xE9, 0, 0, 0, 0 };
        int32_t rel = static_cast<int32_t>(cave - (executeSite + 5));
        memcpy(&jmpPatch[1], &rel, 4);

        DWORD oldProtect;
        if (!VirtualProtect((void*)executeSite, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        memcpy(reinterpret_cast<void*>(executeSite), jmpPatch, 5);
        FlushInstructionCache(GetCurrentProcess(), (void*)executeSite, 5);
        VirtualProtect((void*)executeSite, 5, oldProtect, &oldProtect);

        wchar_t msg[128];
        swprintf_s(msg, L"[JobOrder] Hooked executeJob at: 0x%p, camera return: 0x%p", (void*)executeSite, (void*)g_cameraReturn);
        ConsolePrint(msg);
        return true;
    }

    void ThreadLoop()
    {
        InitConsole();
        ConsolePrint(L"[JobOrder] DLL Loaded. Waiting 10 seconds...");
        Sleep(10000);

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (SetupJobOrderHook()) return;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            Sleep(kRetryInterval);
        }

        ConsolePrint(L"[JobOrder] Failed after 30 attempts.");
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
