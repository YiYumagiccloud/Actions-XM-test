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

    const std::vector<int> kCameraPattern = {
        0x46, 0x8B, 0x8C, 0xB6, 0xB0, 0xDE, 0x3D, 0x00, 0x4E, 0x8B, 0x04, 0xC6, 0x48, 0x8B, 0x0D, -1, -1, -1, -1, 
        0xE8, -1, -1, -1, -1, 0x45, 0x8B, 0xC7, 0x48, 0x8B, 0xD3, 0x48, 0x8B, 0xCD, 0xE8
    };
    constexpr uintptr_t kCallOffset = 19; 

    typedef void(__fastcall* ExecuteJobFn)(uintptr_t smain, int mode, uintptr_t jobs, uint32_t count, uintptr_t extra);
    ExecuteJobFn OriginalExecuteJob = nullptr;

    struct Entry { uint64_t q[4]; };
    Entry g_backup[8192];

    void __fastcall HookedExecuteJob(uintptr_t smain, int mode, uintptr_t jobs, uint32_t count, uintptr_t extra)
    {
        uintptr_t list = jobs;
        uint32_t n = count;
        
        if (!list) {
            list = smain + 0xF0;
            __try { n = *reinterpret_cast<uint32_t*>(smain + 0xB0); } 
            __except (EXCEPTION_EXECUTE_HANDLER) { n = 0; }
        }

        bool modified = false;
        if (n > 1 && n <= 8192) {
            __try {
                memcpy(g_backup, reinterpret_cast<void*>(list), n * sizeof(Entry));
                Entry* target = reinterpret_cast<Entry*>(list);
                for (uint32_t i = 0; i < n; ++i) target[i] = g_backup[n - 1 - i];
                modified = true;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        // 调用原始函数
        OriginalExecuteJob(smain, mode, jobs, count, extra);

        // 恢复列表
        if (modified) {
            __try { memcpy(reinterpret_cast<void*>(list), g_backup, n * sizeof(Entry)); } 
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    void InitConsole() { /* 略 */ }
    void ConsolePrint(const wchar_t* message) { /* 略 */ }
    uintptr_t ScanPattern(const char* moduleName, const std::vector<int>& pattern) { /* 略 */ }
    uintptr_t AllocNear(uintptr_t target, size_t size) { /* 略 */ }

    bool SetupJobOrderHook()
    {
        uintptr_t site = ScanPattern("MonsterHunterWorld.exe", kCameraPattern);
        if (!site) return false;

        uintptr_t callSite = site + kCallOffset;
        if (*(uint8_t*)callSite != 0xE8) return false;

        int32_t rel = *(int32_t*)(callSite + 1);
        OriginalExecuteJob = reinterpret_cast<ExecuteJobFn>(callSite + 5 + rel);

        uintptr_t cave = AllocNear(callSite, 0x100);
        if (!cave) return false;

        uint8_t trampoline[] = {
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, imm64
            0xFF, 0xE0                          // jmp rax
        };
        memcpy(&trampoline[2], &HookedExecuteJob, 8);
        memcpy(reinterpret_cast<void*>(cave), trampoline, sizeof(trampoline));

        DWORD oldProtect;
        if (!VirtualProtect((void*)callSite, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;

        int32_t newRel = static_cast<int32_t>(cave - (callSite + 5));
        *(int32_t*)(callSite + 1) = newRel;
        
        FlushInstructionCache(GetCurrentProcess(), (void*)callSite, 5);
        VirtualProtect((void*)callSite, 5, oldProtect, &oldProtect);

        wchar_t msg[128];
        swprintf_s(msg, L"[JobOrder] Hooked camera draw call at: 0x%p", (void*)callSite);
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
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        Load();
    }
    return TRUE;
}
