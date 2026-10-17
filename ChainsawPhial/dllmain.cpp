#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

namespace
{
    std::atomic_bool g_started{ false };
    HANDLE g_consoleOutput = INVALID_HANDLE_VALUE;

    constexpr size_t kPatchLength = 6;
    constexpr size_t kCaveSize = 0x1000;

    const std::vector<int> kPattern = {
        0x89, 0x8B, 0x74, 0x23, 0x00, 0x00, 0x72
    };

    // 初始化控制台，不创建任何日志文件。
    void InitConsole()
    {
        if (!GetConsoleWindow())
        {
            if (!AllocConsole())
            {
                // 如果无法新建控制台，尝试附加到父进程控制台。
                AttachConsole(ATTACH_PARENT_PROCESS);
            }
        }

        SetConsoleTitleW(L"Chainsaw Phial MOD");

        g_consoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);

        if (g_consoleOutput == nullptr ||
            g_consoleOutput == INVALID_HANDLE_VALUE)
        {
            g_consoleOutput = CreateFileW(
                L"CONOUT$",
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr);

            if (g_consoleOutput != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(
                    STD_OUTPUT_HANDLE,
                    g_consoleOutput);
            }
        }
    }

    // 输出一条控制台消息，不写入文件。
    void ConsolePrint(const wchar_t* message)
    {
        if (!message)
            return;

        SYSTEMTIME now{};
        GetLocalTime(&now);

        wchar_t line[768]{};

        const int length = swprintf_s(
            line,
            _countof(line),
            L"[ %02u:%02u:%02u ] %s",
            static_cast<unsigned>(now.wHour),
            static_cast<unsigned>(now.wMinute),
            static_cast<unsigned>(now.wSecond),
            message);

        if (length <= 0)
            return;

        if (g_consoleOutput != nullptr &&
            g_consoleOutput != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;

            if (WriteConsoleW(
                    g_consoleOutput,
                    line,
                    static_cast<DWORD>(length),
                    &written,
                    nullptr))
            {
                return;
            }
        }

        OutputDebugStringW(line);
    }

    uintptr_t ScanPattern(
        const char* moduleName,
        const std::vector<int>& pattern)
    {
        if (pattern.empty())
            return 0;

        HMODULE module = GetModuleHandleA(moduleName);

        if (!module)
            return 0;

        const uintptr_t moduleBase =
            reinterpret_cast<uintptr_t>(module);

        const auto* dosHeader =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
            dosHeader->e_lfanew <= 0)
        {
            return 0;
        }

        const auto* ntHeaders =
            reinterpret_cast<const IMAGE_NT_HEADERS*>(
                moduleBase + static_cast<uintptr_t>(
                    dosHeader->e_lfanew));

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return 0;

        const auto* sections = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0;
             i < ntHeaders->FileHeader.NumberOfSections;
             ++i)
        {
            const auto& section = sections[i];

            if (std::memcmp(section.Name, ".text", 5) != 0)
                continue;

            const size_t textSize =
                static_cast<size_t>(section.Misc.VirtualSize);

            if (textSize < pattern.size())
                return 0;

            const auto* text =
                reinterpret_cast<const uint8_t*>(
                    moduleBase + section.VirtualAddress);

            for (size_t offset = 0;
                 offset <= textSize - pattern.size();
                 ++offset)
            {
                bool found = true;

                for (size_t j = 0; j < pattern.size(); ++j)
                {
                    if (pattern[j] != -1 &&
                        (pattern[j] < 0 ||
                         pattern[j] > 0xFF ||
                         text[offset + j] !=
                             static_cast<uint8_t>(pattern[j])))
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    return reinterpret_cast<uintptr_t>(
                        text + offset);
                }
            }

            return 0;
        }

        return 0;
    }

    // 保留已验证有效的内存分配方式。
    uintptr_t AllocNear(uintptr_t target, size_t size)
    {
        const uintptr_t start =
            target & ~static_cast<uintptr_t>(0xFFFF);

        const uintptr_t searchRange =
            static_cast<uintptr_t>(0x7FFF0000ULL);

        const uintptr_t lowerBound =
            start > searchRange ? start - searchRange : 0;

        uintptr_t addr = start;

        while (addr > lowerBound)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (VirtualQuery(
                    reinterpret_cast<LPCVOID>(addr),
                    &mbi,
                    sizeof(mbi)) != 0)
            {
                if (mbi.State == MEM_FREE)
                {
                    void* memory = VirtualAlloc(
                        reinterpret_cast<void*>(addr),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);

                    if (memory)
                        return reinterpret_cast<uintptr_t>(memory);
                }
            }

            if (addr < 0x10000)
                break;

            addr -= 0x10000;
        }

        // 保留原版回退逻辑。
        void* memory = VirtualAlloc(
            nullptr,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        return reinterpret_cast<uintptr_t>(memory);
    }

    bool FitsRel32(int64_t displacement)
    {
        return displacement >=
                   (std::numeric_limits<int32_t>::min)() &&
               displacement <=
                   (std::numeric_limits<int32_t>::max)();
    }

    bool SetupHook()
    {
        const uintptr_t scanAddr =
            ScanPattern("MonsterHunterWorld.exe", kPattern);

        if (!scanAddr)
            return false;

        const uintptr_t returnAddr =
            scanAddr + kPatchLength;

        const uintptr_t caveAddr =
            AllocNear(scanAddr, kCaveSize);

        if (!caveAddr)
            return false;

        // 保留原版汇编和 CE 脚本的执行逻辑。
        uint8_t code[] = {
            // movss xmm1, [rbx+2470]
            0xF3, 0x0F, 0x10, 0x8B, 0x70, 0x24, 0x00, 0x00,

            // xorps xmm2, xmm2
            0x0F, 0x57, 0xD2,

            // comiss xmm1, xmm2
            0x0F, 0x2F, 0xCA,

            // ja skip_consume
            0x77, 0x06,

            // mov [rbx+2374], ecx
            0x89, 0x8B, 0x74, 0x23, 0x00, 0x00,

            // comiss xmm0, [rbx+2470]
            0x0F, 0x2F, 0x83, 0x70, 0x24, 0x00, 0x00,

            // jmp return
            0xE9, 0x00, 0x00, 0x00, 0x00
        };

        static_assert(sizeof(code) == 34,
                      "Unexpected Code Cave size");

        const int64_t returnJump =
            static_cast<int64_t>(returnAddr) -
            static_cast<int64_t>(caveAddr + sizeof(code));

        if (!FitsRel32(returnJump))
        {
            VirtualFree(
                reinterpret_cast<void*>(caveAddr),
                0,
                MEM_RELEASE);

            return false;
        }

        const int32_t returnDisplacement =
            static_cast<int32_t>(returnJump);

        std::memcpy(
            &code[sizeof(code) - sizeof(returnDisplacement)],
            &returnDisplacement,
            sizeof(returnDisplacement));

        const int64_t patchJump =
            static_cast<int64_t>(caveAddr) -
            static_cast<int64_t>(scanAddr + 5);

        if (!FitsRel32(patchJump))
        {
            VirtualFree(
                reinterpret_cast<void*>(caveAddr),
                0,
                MEM_RELEASE);

            return false;
        }

        const int32_t patchDisplacement =
            static_cast<int32_t>(patchJump);

        std::memcpy(
            reinterpret_cast<void*>(caveAddr),
            code,
            sizeof(code));

        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(caveAddr),
            sizeof(code));

        uint8_t jmpPatch[kPatchLength] = {
            0xE9, 0x00, 0x00, 0x00, 0x00, 0x90
        };

        std::memcpy(
            &jmpPatch[1],
            &patchDisplacement,
            sizeof(patchDisplacement));

        DWORD oldProtect = 0;

        if (!VirtualProtect(
                reinterpret_cast<void*>(scanAddr),
                kPatchLength,
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            VirtualFree(
                reinterpret_cast<void*>(caveAddr),
                0,
                MEM_RELEASE);

            return false;
        }

        std::memcpy(
            reinterpret_cast<void*>(scanAddr),
            jmpPatch,
            sizeof(jmpPatch));

        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(scanAddr),
            kPatchLength);

        DWORD ignoredProtect = 0;

        VirtualProtect(
            reinterpret_cast<void*>(scanAddr),
            kPatchLength,
            oldProtect,
            &ignoredProtect);

        return true;
    }

    // 取消一解、二解时的电锯时间重置。
    bool SetupResetTimePatch()
    {
        constexpr size_t kResetTimePatchLength = 6;

        const std::vector<int> pattern = {
            0x89, 0x83, 0x70, 0x24, 0x00, 0x00
        };

        const uintptr_t scanAddr =
            ScanPattern("MonsterHunterWorld.exe", pattern);

        if (!scanAddr)
            return false;

        DWORD oldProtect = 0;

        if (!VirtualProtect(
                reinterpret_cast<void*>(scanAddr),
                kResetTimePatchLength,
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            return false;
        }

        const uint8_t nops[kResetTimePatchLength] = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90
        };

        std::memcpy(
            reinterpret_cast<void*>(scanAddr),
            nops,
            sizeof(nops));

        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(scanAddr),
            kResetTimePatchLength);

        DWORD ignoredProtect = 0;

        const bool restored = VirtualProtect(
            reinterpret_cast<void*>(scanAddr),
            kResetTimePatchLength,
            oldProtect,
            &ignoredProtect) != FALSE;

        return restored;
    }

    void ThreadLoop()
    {
        InitConsole();

        ConsolePrint(
            L"[Chainsaw Phial] DLL loaded; worker thread started.\r\n");

        ConsolePrint(
            L"[Chainsaw Phial] Waiting 10 seconds for game initialization...\r\n");

        Sleep(10000);

        ConsolePrint(
            L"[Chainsaw Phial] Scanning for AOB and installing hook...\r\n");

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (SetupHook())
                {
                    ConsolePrint(
                        L"[Chainsaw Phial] Hook installed; memory patch applied successfully.\r\n");

                    if (SetupResetTimePatch())
                    {
                        ConsolePrint(
                            L"[Chainsaw Phial] Reset time patch applied successfully.\r\n");
                    }
                    else
                    {
                        ConsolePrint(
                            L"[Chainsaw Phial] Reset time patch installation failed.\r\n");
                    }

                    return;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Silent retry; no file logging.
            }

            if (i + 1 < kMaxAttempts)
                Sleep(kRetryInterval);
        }

        ConsolePrint(
            L"[Chainsaw Phial] Hook installation failed after 30 attempts.\r\n");

        g_started.store(false, std::memory_order_release);
    }
} // namespace

// Stracker's Loader 导出入口。
__declspec(dllexport) bool Load()
{
    bool expected = false;

    if (!g_started.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel))
    {
        return true;
    }

    HANDLE thread = CreateThread(
        nullptr,
        0,
        [](LPVOID) -> DWORD
        {
            ThreadLoop();
            return 0;
        },
        nullptr,
        0,
        nullptr);

    if (!thread)
    {
        g_started.store(
            false,
            std::memory_order_release);

        return false;
    }

    CloseHandle(thread);
    return true;
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD reason,
    LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        // 保留上一个成功版本的启动行为。
        Load();
    }

    return TRUE;
}
