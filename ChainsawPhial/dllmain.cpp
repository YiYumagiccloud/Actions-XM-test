
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace
{
    std::atomic_bool g_started{ false };

    constexpr size_t kPatchLength = 6;
    constexpr size_t kCaveSize = 0x1000;

    // -1 表示通配符；其余字节精确匹配。
    const std::vector<int> kPattern = {
        0x89, 0x8B, 0x74, 0x23, 0x00, 0x00, 0x72
    };


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

            // 使用偏移量控制范围，避免指针减法越界。
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


    // 保留原来的向低地址查找及任意地址回退策略。
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

        // 保留原版的回退方式。
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

        // 覆盖 6 字节，回到原条件跳转指令所在的位置。
        const uintptr_t returnAddr =
            scanAddr + kPatchLength;

        const uintptr_t caveAddr =
            AllocNear(scanAddr, kCaveSize);

        if (!caveAddr)
            return false;

        // 保留 CE 脚本中的汇编逻辑及执行顺序。
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
            // 恢复原逻辑需要的条件标志位
            0x0F, 0x2F, 0x83, 0x70, 0x24, 0x00, 0x00,

            // jmp return
            0xE9, 0x00, 0x00, 0x00, 0x00
        };

        static_assert(sizeof(code) == 34,
                      "Unexpected Code Cave size");

        // 计算 Code Cave 返回原程序的 rel32 位移。
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

        // 同时检查 Hook 跳转的距离，避免位移截断。
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

        // 保留原版 Code Cave 的内存保护属性。
        std::memcpy(
            reinterpret_cast<void*>(caveAddr),
            code,
            sizeof(code));

        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(caveAddr),
            sizeof(code));

        // E9 rel32 + NOP，与原 CE 脚本覆盖长度一致。
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


    void ThreadLoop()
    {
        // 保留原版延迟，避免过早扫描游戏内存。
        Sleep(10000);

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        for (int i = 0; i < kMaxAttempts; ++i)
        {
            __try
            {
                if (SetupHook())
                    return;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // 静默捕获异常，保留原来的重试行为。
            }

            if (i + 1 < kMaxAttempts)
                Sleep(kRetryInterval);
        }

        // 安装失败时允许再次调用 Load() 尝试。
        g_started.store(false, std::memory_order_release);
    }
}


// 保留 Stracker's Loader 所需的 C++ 导出形式。
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
        DisableThreadLibraryCalls(hModule);

        // 特意保留原版的启动调用，不改变原来的启动路径。
        Load();
    }

    return TRUE;
}
