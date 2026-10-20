#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>
#include <cstdio>

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace
{
    std::atomic_bool g_started{ false };
    HANDLE g_consoleOutput = INVALID_HANDLE_VALUE;
    HANDLE g_hTimer = NULL;
    bool g_timerFailed = false;
    double g_qpcFreq = 0.0;

    // 特征码：sMain 的时间限制器函数
    const std::vector<int> kTimingPattern = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x41, 
        0x56, 0x48, 0x83, 0xEC, 0x60, 0x80, 0xB9, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD9, 0x8B, 
        0x81, 0xD0, 0x00, 0x00, 0x00, 0x89, 0x81, 0xCC, 0x00, 0x00, 0x00
    };

    void InitConsole()
    {
        if (!GetConsoleWindow()) { AllocConsole(); }
        SetConsoleTitleW(L"MHW SleepLimiter");
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

    // 核心 C++ 逻辑：读取游戏时间，计算剩余时间，进行睡眠
    void SleepLogic(uintptr_t smain) noexcept {
        if (!smain || g_timerFailed) return;

        if (!g_hTimer) {
            g_hTimer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
            if (!g_hTimer) { g_timerFailed = true; return; }
            LARGE_INTEGER freq;
            QueryPerformanceFrequency(&freq);
            g_qpcFreq = (double)freq.QuadPart;
        }

        float scale, max_fps;
        uint8_t mode;
        uint64_t scaled, reference;
        int64_t last;

        __try {
            scale = *reinterpret_cast<volatile float*>(smain + 0x58);
            max_fps = *reinterpret_cast<volatile float*>(smain + 0x5C);
            mode = *reinterpret_cast<volatile uint8_t*>(smain + 0x60);
            scaled = *reinterpret_cast<volatile uint64_t*>(smain + 0x70);
            reference = *reinterpret_cast<volatile uint64_t*>(smain + 0x78);
            last = *reinterpret_cast<volatile int64_t*>(smain + 0x80);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return;
        }

        if (mode || !(scale >= 1.0f && scale <= 1000.0f) || !(max_fps >= 10.0f && max_fps <= 1000.0f)) return;

        LARGE_INTEGER now_qpc;
        QueryPerformanceCounter(&now_qpc);
        int64_t now = now_qpc.QuadPart;

        if (last == 0 || last > now) last = now;
        const auto sum = scaled + static_cast<uint32_t>(static_cast<int32_t>(double(static_cast<int32_t>(now - last)) * scale));
        const auto elapsed = static_cast<int32_t>(static_cast<uint32_t>(sum) - static_cast<uint32_t>(reference));
        double seconds = (double(scale) / max_fps - double(elapsed) / g_qpcFreq) / scale;

        if (!std::isfinite(seconds)) return;

        const double margin = 1000.0 * 1e-6; // 预留 1ms 给游戏自己自旋
        const double sleep_sec = seconds - margin;
        if (sleep_sec < 100e-6) return; // 小于 100us 就不调用定时器了

        const double max_sleep = sleep_sec < 0.1 ? sleep_sec : 0.1;
        LARGE_INTEGER due;
        due.QuadPart = -static_cast<LONGLONG>(max_sleep * 1e7); 
        
        if (SetWaitableTimer(g_hTimer, &due, 0, nullptr, nullptr, FALSE)) {
            WaitForSingleObject(g_hTimer, 200);
        }
    }

    bool SetupSleepLimiterHook()
    {
        uintptr_t timingAddr = ScanPattern("MonsterHunterWorld.exe", kTimingPattern);
        if (!timingAddr) {
            ConsolePrint(L"[SleepLimiter] Failed: Pattern not found.");
            return false;
        }

        uintptr_t cave = AllocNear(timingAddr, 0x100);
        if (!cave) {
            ConsolePrint(L"[SleepLimiter] Failed: AllocNear failed.");
            return false;
        }

        uint8_t* p = reinterpret_cast<uint8_t*>(cave);

        // 保存易失性寄存器 (rcx 存参数，必须是第一个 push)
        *p++ = 0x51;                         // push rcx
        *p++ = 0x52;                         // push rdx
        *p++ = 0x41; *p++ = 0x50;            // push r8
        *p++ = 0x41; *p++ = 0x51;            // push r9
        *p++ = 0x50;                         // push rax
        *p++ = 0x41; *p++ = 0x52;            // push r10
        *p++ = 0x41; *p++ = 0x53;            // push r11
        
        // Shadow space & 调用 SleepLogic
        *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20; // sub rsp, 0x20
        *p++ = 0x48; *p++ = 0xB8;            // mov rax, SleepLogic
        *(uint64_t*)p = reinterpret_cast<uint64_t>(&SleepLogic); p += 8;
        *p++ = 0xFF; *p++ = 0xD0;            // call rax
        *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x20; // add rsp, 0x20

        // 恢复易失性寄存器
        *p++ = 0x41; *p++ = 0x5B;            // pop r11
        *p++ = 0x41; *p++ = 0x5A;            // pop r10
        *p++ = 0x58;                         // pop rax
        *p++ = 0x41; *p++ = 0x59;            // pop r9
        *p++ = 0x41; *p++ = 0x58;            // pop r8
        *p++ = 0x5A;                         // pop rdx
        *p++ = 0x59;                         // pop rcx

        // 执行被覆盖的 5 字节原指令：mov [rsp+10h], rbx
        *p++ = 0x48; *p++ = 0x89; *p++ = 0x5C; *p++ = 0x24; *p++ = 0x10;

        // 跳回原函数
        *p++ = 0x48; *p++ = 0xB8;            // mov rax, ret
        *(uint64_t*)p = timingAddr + 5; p += 8;
        *p++ = 0xFF; *p++ = 0xE0;            // jmp rax

        // 将原地址前 5 字节替换为 Jmp 到 Code Cave
        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(timingAddr), 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }

        *(uint8_t*)timingAddr = 0xE9;
        *(int32_t*)(timingAddr + 1) = static_cast<int32_t>(cave - timingAddr - 5);

        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(timingAddr), 5);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(cave), p - reinterpret_cast<uint8_t*>(cave));

        VirtualProtect(reinterpret_cast<void*>(timingAddr), 5, oldProtect, &oldProtect);

        wchar_t msg[128];
        swprintf_s(msg, L"[SleepLimiter] Hook installed at: 0x%p", reinterpret_cast<void*>(timingAddr));
        ConsolePrint(msg);
        return true;
    }

    void ThreadLoop()
    {
        InitConsole();
        ConsolePrint(L"[SleepLimiter] DLL Loaded. Waiting 10 seconds for game initialization...");
        Sleep(10000);

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (SetupSleepLimiterHook()) return;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            Sleep(kRetryInterval);
        }

        ConsolePrint(L"[SleepLimiter] Failed after 30 attempts.");
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
