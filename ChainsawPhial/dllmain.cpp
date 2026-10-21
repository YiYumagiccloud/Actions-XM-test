#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

namespace
{
    std::atomic_bool g_started{ false };
    HMODULE g_hModule = nullptr;
    HANDLE g_logFile = INVALID_HANDLE_VALUE;
    std::mutex g_logMutex;

    constexpr size_t kPatchLength = 6;
    // 【优化】我们只需要写 34 字节的汇编，64 字节的洞就足够了，极大提升找洞成功率
    constexpr size_t kCaveSize = 0x40; 

    const std::vector<int> kPattern = {
        0x89, 0x8B, 0x74, 0x23, 0x00, 0x00, 0x72
    };

    // 取消一解二解重置电锯时间
    const std::vector<int> kResetTimePattern = {
        0x8B, 0x86, 0x20, 0x0E, 0x00, 0x00, 
        0x89, 0x83, 0x70, 0x24, 0x00, 0x00
    };

    // 初始化日志文件路径，每次启动直接覆盖旧文件（不追加）
    void InitLogFile()
    {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(g_hModule, path, MAX_PATH);
        std::wstring logPath(path);
        
        size_t pos = logPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
        {
            logPath = logPath.substr(0, pos + 1) + L"ChainsawPhial.log";
        }

        g_logFile = CreateFileW(
            logPath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ, // 允许玩家在游戏运行时用记事本查看
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    }

    // 写入日志文件
    void Log(const wchar_t* message)
    {
        if (!message || g_logFile == INVALID_HANDLE_VALUE)
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

        // 转换为 UTF-8 编码写入，防止乱码
        int utf8Length = WideCharToMultiByte(CP_UTF8, 0, line, length, nullptr, 0, nullptr, nullptr);
        if (utf8Length > 0)
        {
            std::vector<char> utf8Line(utf8Length);
            WideCharToMultiByte(CP_UTF8, 0, line, length, utf8Line.data(), utf8Length, nullptr, nullptr);

            std::lock_guard<std::mutex> lock(g_logMutex);
            DWORD written = 0;
            WriteFile(g_logFile, utf8Line.data(), utf8Length, &written, nullptr);
        }
    }

    // 采用极速的 memchr 扫描特征码
    uintptr_t ScanPattern(
        const char* moduleName,
        const std::vector<int>& pattern)
    {
        if (pattern.empty()) return 0;

        HMODULE module = GetModuleHandleA(moduleName);
        if (!module) return 0;

        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0)
            return 0;

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            moduleBase + static_cast<uintptr_t>(dosHeader->e_lfanew));

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return 0;

        const auto* sections = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            const auto& section = sections[i];
            if (std::memcmp(section.Name, ".text", 5) != 0)
                continue;

            const size_t textSize = static_cast<size_t>(section.Misc.VirtualSize);
            if (textSize < pattern.size())
                return 0;

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

                if (found)
                {
                    return reinterpret_cast<uintptr_t>(q);
                }
                ++q;
            }
            return 0;
        }
        return 0;
    }

    // 终极保底版：双向 VirtualAlloc + 极限 .text 挖洞
    uintptr_t AllocNear(uintptr_t target, size_t size)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        const uintptr_t granularity = si.dwAllocationGranularity;

        const uintptr_t maxDistance = 0x7FFF0000ULL;
        const uintptr_t lowerBound = target > maxDistance ? target - maxDistance : granularity;
        const uintptr_t upperBound = target + maxDistance;

        // 1. VirtualAlloc 向下搜索
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
            if (regionBase >= granularity && regionBase - granularity > lowerBound)
                addr = regionBase - granularity;
            else break;
        }

        // 2. VirtualAlloc 向上搜索
        addr = (target & ~(granularity - 1)) + granularity;
        while (addr < upperBound)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) break;
            uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t regionEnd = regionBase + mbi.RegionSize;

            if (mbi.State == MEM_FREE)
            {
                uintptr_t allocAddr = regionBase;
                if (allocAddr < addr) allocAddr = addr;
                allocAddr = (allocAddr + granularity - 1) & ~(granularity - 1);

                while (allocAddr + size <= regionEnd && allocAddr < upperBound)
                {
                    void* memory = VirtualAlloc(reinterpret_cast<void*>(allocAddr), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (memory) return reinterpret_cast<uintptr_t>(memory);
                    allocAddr += granularity;
                }
            }
            if (regionEnd < upperBound && regionEnd > addr)
                addr = regionEnd;
            else break;
        }

        // 3. 终极保底：直接在游戏 .text 段寻找连续的填充字节
        HMODULE module = GetModuleHandleA("MonsterHunterWorld.exe");
        if (!module) return 0;

        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + dosHeader->e_lfanew);
        const auto* sections = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            if (std::memcmp(sections[i].Name, ".text", 5) != 0) continue;

            const uintptr_t textBase = moduleBase + sections[i].VirtualAddress;
            const size_t textSize = sections[i].Misc.VirtualSize;
            const uint8_t* text = reinterpret_cast<const uint8_t*>(textBase);

            // 遍历寻找填充区（0xCC, 0x00, 0x90）
            for (size_t offset = 0; offset <= textSize - size; offset += 4) 
            {
                const uint8_t firstByte = text[offset];
                if (firstByte != 0xCC && firstByte != 0x00 && firstByte != 0x90) continue;

                bool isPadding = true;
                for (size_t j = 1; j < size; ++j)
                {
                    if (text[offset + j] != firstByte)
                    {
                        isPadding = false;
                        break;
                    }
                }

                if (isPadding)
                {
                    uintptr_t candidate = textBase + offset;
                    int64_t dist = static_cast<int64_t>(candidate) - static_cast<int64_t>(target);
                    if (dist >= INT32_MIN && dist <= INT32_MAX)
                    {
                        DWORD oldProtect;
                        if (VirtualProtect(reinterpret_cast<void*>(candidate), size, PAGE_EXECUTE_READWRITE, &oldProtect))
                        {
                            std::memset(reinterpret_cast<void*>(candidate), 0x90, size);
                            
                            wchar_t msg[128];
                            swprintf_s(msg, L"[Chainsaw Phial] Found Code Cave in .text at: 0x%p\r\n", reinterpret_cast<void*>(candidate));
                            Log(msg);
                            
                            return candidate;
                        }
                    }
                }
            }
        }
        return 0;
    }

    bool FitsRel32(int64_t displacement)
    {
        return displacement >= (std::numeric_limits<int32_t>::min)() &&
               displacement <= (std::numeric_limits<int32_t>::max)();
    }

    bool SetupHook()
    {
        const uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", kPattern);
        if (!scanAddr) return false;

        const uintptr_t returnAddr = scanAddr + kPatchLength;
        const uintptr_t caveAddr = AllocNear(scanAddr, kCaveSize);

        if (!caveAddr) return false;

        uint8_t code[] = {
            0xF3, 0x0F, 0x10, 0x8B, 0x70, 0x24, 0x00, 0x00,
            0x0F, 0x57, 0xD2,
            0x0F, 0x2F, 0xCA,
            0x77, 0x06,
            0x89, 0x8B, 0x74, 0x23, 0x00, 0x00,
            0x0F, 0x2F, 0x83, 0x70, 0x24, 0x00, 0x00,
            0xE9, 0x00, 0x00, 0x00, 0x00
        };

        static_assert(sizeof(code) == 34, "Unexpected Code Cave size");

        const int64_t returnJump = static_cast<int64_t>(returnAddr) - static_cast<int64_t>(caveAddr + sizeof(code));
        if (!FitsRel32(returnJump))
        {
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }

        const int32_t returnDisplacement = static_cast<int32_t>(returnJump);
        std::memcpy(&code[sizeof(code) - sizeof(returnDisplacement)], &returnDisplacement, sizeof(returnDisplacement));

        const int64_t patchJump = static_cast<int64_t>(caveAddr) - static_cast<int64_t>(scanAddr + 5);
        if (!FitsRel32(patchJump))
        {
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }

        const int32_t patchDisplacement = static_cast<int32_t>(patchJump);

        std::memcpy(reinterpret_cast<void*>(caveAddr), code, sizeof(code));
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(caveAddr), sizeof(code));

        uint8_t jmpPatch[kPatchLength] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90 };
        std::memcpy(&jmpPatch[1], &patchDisplacement, sizeof(patchDisplacement));

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(scanAddr), kPatchLength, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }

        std::memcpy(reinterpret_cast<void*>(scanAddr), jmpPatch, sizeof(jmpPatch));
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(scanAddr), kPatchLength);

        DWORD ignoredProtect = 0;
        VirtualProtect(reinterpret_cast<void*>(scanAddr), kPatchLength, oldProtect, &ignoredProtect);

        return true;
    }

    // 取消一解二解重置电锯时间
    bool SetupResetTimePatch()
    {
        const uintptr_t baseAddr = ScanPattern("MonsterHunterWorld.exe", kResetTimePattern);
        if (!baseAddr) return false;

        const uintptr_t scanAddr = baseAddr + 6;

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(scanAddr), 6, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        const uint8_t nops[6] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
        std::memcpy(reinterpret_cast<void*>(scanAddr), nops, sizeof(nops));
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(scanAddr), sizeof(nops));

        DWORD ignoredProtect = 0;
        VirtualProtect(reinterpret_cast<void*>(scanAddr), 6, oldProtect, &ignoredProtect);

        wchar_t debugMsg[128];
        swprintf_s(debugMsg, L"[Chainsaw Phial] Reset timer patched at: 0x%p\r\n", reinterpret_cast<void*>(scanAddr));
        Log(debugMsg);

        return true;
    }

    void ThreadLoop()
    {
        InitLogFile();

        Log(L"[Chainsaw Phial] DLL loaded; worker thread started.\r\n");
        Log(L"[Chainsaw Phial] Waiting 10 seconds for game initialization...\r\n");

        Sleep(10000);

        Log(L"[Chainsaw Phial] Scanning for AOB and installing hooks...\r\n");

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        bool hookDone = false;
        bool resetDone = false;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (!hookDone)
                {
                    if (SetupHook())
                    {
                        hookDone = true;
                        Log(L"[Chainsaw Phial] Hook installed; memory patch applied successfully.\r\n");
                    }
                }

                if (hookDone && !resetDone)
                {
                    if (SetupResetTimePatch())
                    {
                        resetDone = true;
                        Log(L"[Chainsaw Phial] Reset timer patch applied successfully.\r\n");
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Silent retry
            }

            if (hookDone && resetDone)
                return;

            if (i + 1 < kMaxAttempts)
                Sleep(kRetryInterval);
        }

        if (!hookDone)
        {
            Log(L"[Chainsaw Phial] Hook installation failed after 30 attempts. Falling back to vanilla behavior (NO patches applied).\r\n");
        }
        else if (!resetDone)
        {
            Log(L"[Chainsaw Phial] Reset timer patch failed after 30 attempts.\r\n");
        }

        g_started.store(false, std::memory_order_release);
    }
} // namespace

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
        g_started.store(false, std::memory_order_release);
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
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        Load();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        if (g_logFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_logFile);
            g_logFile = INVALID_HANDLE_VALUE;
        }
    }

    return TRUE;
}
