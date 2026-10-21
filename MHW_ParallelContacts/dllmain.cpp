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

    // setup_signature 特征码：用于获取 sMain 的全局指针
    const std::vector<int> kSetupPattern = {
        0x48, 0x8B, 0x05, -1, -1, -1, -1, 0x83, 0xB8, 0xCC, 0x00, 0x00, 0x00, 0x01, 0x0F, 0x95, 0xC0, 0x88, 0x46, 0x3C, 0x88, 0x46, 0x3D, 0x48, 0x8B, 0x5C, 0x24, 0x70, 0x44, 0x88, 0x76, 0x3E
    };

    void InitConsole()
    {
        if (!GetConsoleWindow()) { AllocConsole(); }
        SetConsoleTitleW(L"MHW ParallelContacts");
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

    uintptr_t GetRipTarget(uintptr_t match, unsigned at, unsigned len, unsigned disp_at) {
        int32_t disp = 0;
        memcpy(&disp, (void*)(match + at + disp_at), 4);
        return match + at + len + disp;
    }

    bool PatchContacts()
    {
        // 1. 找到 setup 代码，获取 sMain 的全局指针地址
        uintptr_t setup_site = ScanPattern("MonsterHunterWorld.exe", kSetupPattern);
        if (!setup_site) {
            ConsolePrint(L"[ParallelContacts] Failed: Pattern not found.");
            return false;
        }

        // mov rax, [rip+disp] 的指令在特征码偏移 0，disp 在 3，长度 7
        uintptr_t smain_global = GetRipTarget(setup_site, 0, 7, 3);

        // 2. 顺着指针链找到 collider 对象
        __try {
            uintptr_t smain = *reinterpret_cast<uintptr_t*>(smain_global);
            if (!smain) return false;

            // sMain + 0xAF8E8 -> sCollision
            uintptr_t collision = *reinterpret_cast<uintptr_t*>(smain + 0xAF8E8);
            if (!collision) return false;

            // sCollision + 0x84E8 -> collider
            // 但注意，collider 是一个嵌入在 sCollision 里的结构，或者是指针？
            // 原版代码: collision + collider_offset + contact_flag
            // 意思是：collider 结构体就在 collision + 0x84E8 处。
            uintptr_t collider = collision + 0x84E8;

            // 3. 直接写 1
            DWORD oldProtect;
            if (!VirtualProtect((void*)collider, 0x3E, PAGE_READWRITE, &oldProtect)) {
                return false;
            }

            uint8_t* flags = reinterpret_cast<uint8_t*>(collider);
            if (flags[0x3C] == 0) flags[0x3C] = 1; // Setup pass
            if (flags[0x3D] == 0) flags[0x3D] = 1; // Contact pass

            VirtualProtect((void*)collider, 0x3E, oldProtect, &oldProtect);

            wchar_t msg[128];
            swprintf_s(msg, L"[ParallelContacts] Success! Flags set at: 0x%p", (void*)collider);
            ConsolePrint(msg);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ConsolePrint(L"[ParallelContacts] Failed: Memory access exception.");
            return false;
        }
    }

    void ThreadLoop()
    {
        InitConsole();
        ConsolePrint(L"[ParallelContacts] DLL Loaded. Waiting 10 seconds...");
        Sleep(10000);

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (PatchContacts()) return;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            Sleep(kRetryInterval);
        }

        ConsolePrint(L"[ParallelContacts] Failed after 30 attempts.");
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
