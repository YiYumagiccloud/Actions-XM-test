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

    // ==========================================
    // 核心数据：特效绘制内存回读修复
    // ==========================================

    const std::vector<int> kPattern = {
        0x33, 0xC9, 0x48, 0x8B, 0x05, -1, -1, -1, -1, 0x44, 0x89, 0x44, 0x24, 0x40, 0x2B, 0x98, 0x48, 0x01, 0x00, 0x00,
        0x45, 0x85, 0xC0, 0x74, 0x52, 0x45, 0x8B, 0xCC, 0x48, 0x8D, 0x45, 0x04, 0x41, 0xC1, 0xE1, 0x04, 0x41, 0x83, 0xE6, 0x0F,
        0x45, 0x8B, 0xD5, 0x45, 0x0F, 0xB7, 0xD8, 0x41, 0xC1, 0xE2, 0x04, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x83, 0x60, 0xFC,
        0xF0, 0x09, 0x50, 0xFC, 0x83, 0x20, 0xF0, 0x44, 0x09, 0x30, 0x83, 0x60, 0xFC, 0x0F, 0x44, 0x09, 0x48, 0xFC, 0x83, 0x20,
        0x0F, 0x44, 0x09, 0x10, 0x66, 0x89, 0x48, 0x04, 0xFF, 0xC1, 0x66, 0x44, 0x89, 0x58, 0x06, 0x89, 0x58, 0x08, 0x48, 0x8D,
        0x40, 0x10, 0x41, 0x3B, 0xC8, 0x72, 0xCE
    };

    // 从特征码起点开始，偏移 51 字节处开始修改，修改 56 字节
    constexpr uintptr_t kPatchOffset = 51;
    constexpr size_t kPatchLength = 56;

    // 原始字节（防呆校验）
    const uint8_t kExpected[56] = {
        0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x83, 0x60, 0xFC, 0xF0, 0x09, 0x50, 0xFC, 0x83, 0x20, 0xF0,
        0x44, 0x09, 0x30, 0x83, 0x60, 0xFC, 0x0F, 0x44, 0x09, 0x48, 0xFC, 0x83, 0x20, 0x0F, 0x44, 0x09,
        0x10, 0x66, 0x89, 0x48, 0x04, 0xFF, 0xC1, 0x66, 0x44, 0x89, 0x58, 0x06, 0x89, 0x58, 0x08, 0x48,
        0x8D, 0x40, 0x10, 0x41, 0x3B, 0xC8, 0x72, 0xCE
    };

    // 替换字节（直接写入，消除显存回读）
    const uint8_t kReplacement[56] = {
        0x41, 0x09, 0xD1, 0x45, 0x09, 0xF2, 0x44, 0x89, 0x48, 0xFC, 0x44, 0x89, 0x10, 0x66, 0x89, 0x48,
        0x04, 0xFF, 0xC1, 0x66, 0x44, 0x89, 0x58, 0x06, 0x89, 0x58, 0x08, 0x48, 0x8D, 0x40, 0x10, 0x41,
        0x3B, 0xC8, 0x72, 0xE2, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x84, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0F, 0x1F, 0x40, 0x00
    };

    // 控制台日志
    void InitConsole()
    {
        if (!GetConsoleWindow()) { AllocConsole(); }
        SetConsoleTitleW(L"MHW EffectFix (PrimStores)");
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

    // 极速特征码扫描 (memchr 优化)
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

    bool ApplyPatch()
    {
        uintptr_t baseAddr = ScanPattern("MonsterHunterWorld.exe", kPattern);
        if (!baseAddr) {
            ConsolePrint(L"[EffectFix] Failed: Pattern not found.");
            return false;
        }

        uintptr_t patchAddr = baseAddr + kPatchOffset;

        // 校验原始字节，确保游戏版本未变
        if (std::memcmp(reinterpret_cast<void*>(patchAddr), kExpected, kPatchLength) != 0) {
            ConsolePrint(L"[EffectFix] Failed: Bytes mismatch. Game updated?");
            return false;
        }

        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(patchAddr), kPatchLength, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            ConsolePrint(L"[EffectFix] Failed: VirtualProtect error.");
            return false;
        }

        std::memcpy(reinterpret_cast<void*>(patchAddr), kReplacement, kPatchLength);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(patchAddr), kPatchLength);
        
        DWORD ignoredProtect;
        VirtualProtect(reinterpret_cast<void*>(patchAddr), kPatchLength, oldProtect, &ignoredProtect);

        wchar_t msg[128];
        swprintf_s(msg, L"[EffectFix] Success! Patched at: 0x%p", reinterpret_cast<void*>(patchAddr));
        ConsolePrint(msg);
        return true;
    }

    void ThreadLoop()
    {
        InitConsole();
        ConsolePrint(L"[EffectFix] DLL Loaded. Waiting 10 seconds for game initialization...");
        
        // 必须等待游戏加载完毕，主模块解包完成后再扫描
        Sleep(10000);

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (ApplyPatch()) return; // 成功就退出线程
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // 忽略异常，继续重试
            }
            Sleep(kRetryInterval);
        }

        ConsolePrint(L"[EffectFix] Failed after 30 attempts.");
        g_started.store(false, std::memory_order_release);
    }
} // namespace

// Stracker's Loader / 其它 ASI Loader 的导出入口
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
