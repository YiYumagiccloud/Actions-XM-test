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


    // 精确特征码：前面一句 mov eax,[rsi+E20] + 你要 NOP 的那句
    const std::vector<int> kResetTimePattern = {
        0x8B, 0x86, 0x20, 0x0E, 0x00, 0x00, 
        0x89, 0x83, 0x70, 0x24, 0x00, 0x00
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

    // 优化后的内存分配方式
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

            // 步子迈小一点，4KB 一找，更容易在碎片中抓到空隙
            // 原本是 0x10000，现在改成 0x1000
            addr -= 0x1000; 
        }

        // 【关键修改】去掉了 VirtualAlloc(nullptr) 的远端回退！
        // 如果附近 2GB 找不到，直接返回 0，让外层重试，避免分配无用的极远端内存。
        return 0;
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
        {
            ConsolePrint(L"[Chainsaw Phial] SetupHook failed: Pattern not found.\r\n");
            return false;
        }

        const uintptr_t returnAddr =
            scanAddr + kPatchLength;

        const uintptr_t caveAddr =
            AllocNear(scanAddr, kCaveSize);

        if (!caveAddr)
        {
            ConsolePrint(L"[Chainsaw Phial] SetupHook failed: AllocNear returned 0.\r\n");
            return false;
        }

        // 保留原版汇编和 CE 脚本的执行逻辑。
        uint8_t code[] = {
            0xF3, 0x0F, 0x10, 0x8B, 0x70, 0x24, 0x00, 0x00,
            0x0F, 0x57, 0xD2,
            0x0F, 0x2F, 0xCA,
            0x77, 0x06,
            0x89, 0x8B, 0x74, 0x23, 0x00, 0x00,
            0x0F, 0x2F, 0x83, 0x70, 0x24, 0x00, 0x00,
            0xE9, 0x00, 0x00, 0x00, 0x00
        };

        const int64_t returnJump =
            static_cast<int64_t>(returnAddr) -
            static_cast<int64_t>(caveAddr + sizeof(code));

        if (!FitsRel32(returnJump))
        {
            wchar_t msg[128];
            swprintf_s(msg, L"[Chainsaw Phial] SetupHook failed: returnJump out of range (cave 0x%p).\r\n", reinterpret_cast<void*>(caveAddr));
            ConsolePrint(msg);

            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
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
            wchar_t msg[128];
            swprintf_s(msg, L"[Chainsaw Phial] SetupHook failed: patchJump out of range (cave 0x%p).\r\n", reinterpret_cast<void*>(caveAddr));
            ConsolePrint(msg);

            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
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
            ConsolePrint(L"[Chainsaw Phial] SetupHook failed: VirtualProtect failed.\r\n");
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
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

    // 2. 取消一解二解重置电锯时间
    bool SetupResetTimePatch()
    {
        // 找到唯一的特征码地址（对应图中的 +288）
        const uintptr_t baseAddr =
            ScanPattern("MonsterHunterWorld.exe", kResetTimePattern);

        if (!baseAddr)
            return false;

        // 因为特征码前面有 6 个字节，所以目标指令（+289）在 baseAddr + 6 的位置
        const uintptr_t scanAddr = baseAddr + 6;

        DWORD oldProtect = 0;

        if (!VirtualProtect(
                reinterpret_cast<void*>(scanAddr),
                6,
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            return false;
        }

        // 用 6 个 NOP 覆盖 89 83 70 24 00 00
        const uint8_t nops[6] = {
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90
        };

        std::memcpy(
            reinterpret_cast<void*>(scanAddr),
            nops,
            sizeof(nops));

        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(scanAddr),
            sizeof(nops));

        DWORD ignoredProtect = 0;

        VirtualProtect(
            reinterpret_cast<void*>(scanAddr),
            6,
            oldProtect,
            &ignoredProtect);

        // 打印修改的地址，方便你在 CE 里核对
        wchar_t debugMsg[128];
        swprintf_s(debugMsg, L"[Chainsaw Phial] Reset timer patched at: 0x%p\r\n", reinterpret_cast<void*>(scanAddr));
        ConsolePrint(debugMsg);

        return true;
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
            L"[Chainsaw Phial] Scanning for AOB and installing hooks...\r\n");

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        bool hookDone = false;
        bool resetDone = false;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (!resetDone)
                {
                    if (SetupResetTimePatch())
                    {
                        resetDone = true;

                        ConsolePrint(
                            L"[Chainsaw Phial] Reset timer patch applied successfully.\r\n");
                    }
                }

                if (!hookDone)
                {
                    if (SetupHook())
                    {
                        hookDone = true;

                        ConsolePrint(
                            L"[Chainsaw Phial] Hook installed; memory patch applied successfully.\r\n");
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Silent retry; no file logging.
            }

            if (hookDone && resetDone)
                return;

            if (i + 1 < kMaxAttempts)
                Sleep(kRetryInterval);
        }

        if (!hookDone)
        {
            ConsolePrint(
                L"[Chainsaw Phial] Hook installation failed after 30 attempts.\r\n");
        }

        if (!resetDone)
        {
            ConsolePrint(
                L"[Chainsaw Phial] Reset timer patch failed after 30 attempts.\r\n");
        }

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
