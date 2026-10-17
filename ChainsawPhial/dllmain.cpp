
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

#if !defined(_WIN64)
#error This MOD requires a 64-bit build.
#endif

namespace
{
    using std::int32_t;
    using std::size_t;
    using std::uint8_t;
    using std::uintptr_t;

    constexpr char kGameModule[] = "MonsterHunterWorld.exe";

    // -1 表示通配符；其他值必须精确匹配。
    constexpr std::array<int, 7> kPattern = {
        0x89, 0x8B, 0x74, 0x23, 0x00, 0x00, 0x72
    };

    constexpr size_t kPatchLength = 6;
    constexpr size_t kCaveAllocationSize = 0x1000;

    // 留出安全余量，保证 rel32 跳转处于有符号 32 位范围内。
    constexpr uintptr_t kNearRange = 0x7FFF0000ULL;

    std::atomic_bool g_loadStarted{ false };


    // 计算 JMP/CALL 所使用的 signed rel32 位移。
    // nextInstruction 是下一条指令的地址，不是当前指令地址。
    bool MakeRelative32(
        uintptr_t nextInstruction,
        uintptr_t destination,
        int32_t& displacement) noexcept
    {
        const uintptr_t positiveLimit =
            static_cast<uintptr_t>(
                (std::numeric_limits<int32_t>::max)());

        const uintptr_t negativeLimit = positiveLimit + 1;

        if (destination >= nextInstruction)
        {
            const uintptr_t distance =
                destination - nextInstruction;

            if (distance > positiveLimit)
                return false;

            displacement = static_cast<int32_t>(distance);
            return true;
        }

        const uintptr_t distance =
            nextInstruction - destination;

        if (distance > negativeLimit)
            return false;

        if (distance == negativeLimit)
        {
            displacement = (std::numeric_limits<int32_t>::min)();
        }
        else
        {
            displacement = -static_cast<int32_t>(distance);
        }

        return true;
    }


    uintptr_t AlignUp(
        uintptr_t value,
        uintptr_t alignment) noexcept
    {
        const uintptr_t maxValue =
            (std::numeric_limits<uintptr_t>::max)();

        if (alignment == 0)
            return maxValue;

        const uintptr_t remainder = value % alignment;

        if (remainder == 0)
            return value;

        const uintptr_t increment = alignment - remainder;

        if (value > maxValue - increment)
            return maxValue;

        return value + increment;
    }


    // 在指定范围内寻找可用的内存区域。
    void* AllocateInRange(
        uintptr_t begin,
        uintptr_t end,
        size_t size,
        uintptr_t granularity) noexcept
    {
        if (begin > end || granularity == 0)
            return nullptr;

        const uintptr_t maxValue =
            (std::numeric_limits<uintptr_t>::max)();

        uintptr_t cursor = AlignUp(begin, granularity);

        while (cursor != maxValue && cursor <= end)
        {
            MEMORY_BASIC_INFORMATION mbi{};

            if (VirtualQuery(
                    reinterpret_cast<LPCVOID>(cursor),
                    &mbi,
                    sizeof(mbi)) == 0)
            {
                break;
            }

            const uintptr_t regionBase =
                reinterpret_cast<uintptr_t>(mbi.BaseAddress);

            const uintptr_t regionSize =
                static_cast<uintptr_t>(mbi.RegionSize);

            if (regionSize == 0 ||
                regionSize > maxValue - regionBase)
            {
                break;
            }

            const uintptr_t regionEnd =
                regionBase + regionSize;

            if (mbi.State == MEM_FREE)
            {
                uintptr_t candidate = cursor;

                if (candidate < regionBase)
                {
                    candidate = AlignUp(
                        regionBase, granularity);
                }

                if (candidate != maxValue &&
                    candidate <= end &&
                    candidate < regionEnd &&
                    size <= regionEnd - candidate &&
                    size <= end - candidate)
                {
                    void* allocation = VirtualAlloc(
                        reinterpret_cast<void*>(candidate),
                        size,
                        MEM_RESERVE | MEM_COMMIT,
                        PAGE_READWRITE);

                    if (allocation)
                        return allocation;
                }
            }

            // 防止异常区域信息导致死循环。
            if (regionEnd <= cursor)
                break;

            const uintptr_t next =
                AlignUp(regionEnd, granularity);

            if (next == maxValue || next <= cursor)
                break;

            cursor = next;
        }

        return nullptr;
    }


    // 在目标地址附近分配内存，不再回退到任意远的地址。
    void* AllocNear(
        uintptr_t target,
        size_t size) noexcept
    {
        SYSTEM_INFO systemInfo{};
        GetSystemInfo(&systemInfo);

        const uintptr_t granularity =
            static_cast<uintptr_t>(
                systemInfo.dwAllocationGranularity);

        if (granularity == 0)
            return nullptr;

        const uintptr_t minAddress =
            reinterpret_cast<uintptr_t>(
                systemInfo.lpMinimumApplicationAddress);

        const uintptr_t maxAddress =
            reinterpret_cast<uintptr_t>(
                systemInfo.lpMaximumApplicationAddress);

        if (target < minAddress || target > maxAddress)
            return nullptr;

        uintptr_t lowerBound = minAddress;

        if (target > kNearRange)
            lowerBound = target - kNearRange;

        if (lowerBound < minAddress)
            lowerBound = minAddress;

        uintptr_t upperBound = maxAddress;

        if (target <= maxAddress - kNearRange)
            upperBound = target + kNearRange;

        const uintptr_t alignedTarget =
            target - target % granularity;

        // 优先向高地址寻找。
        uintptr_t upperStart = upperBound;

        if (alignedTarget <= maxAddress - granularity)
            upperStart = alignedTarget + granularity;

        if (upperStart <= upperBound)
        {
            void* allocation = AllocateInRange(
                upperStart,
                upperBound,
                size,
                granularity);

            if (allocation)
                return allocation;
        }

        // 高地址没有合适空间时，再向低地址寻找。
        if (alignedTarget >= granularity)
        {
            const uintptr_t lowerEnd =
                alignedTarget - granularity;

            if (lowerBound <= lowerEnd)
            {
                return AllocateInRange(
                    lowerBound,
                    lowerEnd,
                    size,
                    granularity);
            }
        }

        return nullptr;
    }


    // 只扫描目标模块的 .text 节。
    uintptr_t ScanPattern(
        const char* moduleName,
        const std::array<int, 7>& pattern) noexcept
    {
        HMODULE module = GetModuleHandleA(moduleName);

        if (!module)
            return 0;

        const auto* base =
            reinterpret_cast<const uint8_t*>(module);

        const auto* dosHeader =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
            dosHeader->e_lfanew <= 0)
        {
            return 0;
        }

        const size_t ntOffset =
            static_cast<size_t>(dosHeader->e_lfanew);

        const auto* ntHeaders =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                base + ntOffset);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
            ntHeaders->OptionalHeader.Magic !=
                IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return 0;
        }

        const size_t imageSize =
            ntHeaders->OptionalHeader.SizeOfImage;

        if (imageSize == 0 ||
            ntOffset > imageSize ||
            sizeof(IMAGE_NT_HEADERS64) > imageSize - ntOffset)
        {
            return 0;
        }

        if (ntHeaders->FileHeader.SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER64))
        {
            return 0;
        }

        const size_t sectionTableRelative =
            offsetof(
                IMAGE_NT_HEADERS64, OptionalHeader) +
            ntHeaders->FileHeader.SizeOfOptionalHeader;

        if (sectionTableRelative > imageSize - ntOffset)
            return 0;

        const size_t sectionTableOffset =
            ntOffset + sectionTableRelative;

        const size_t sectionCount =
            ntHeaders->FileHeader.NumberOfSections;

        if (sectionCount == 0 ||
            sectionCount >
                (imageSize - sectionTableOffset) /
                    sizeof(IMAGE_SECTION_HEADER))
        {
            return 0;
        }

        const auto* sections =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(
                base + sectionTableOffset);

        for (size_t s = 0; s < sectionCount; ++s)
        {
            const auto& section = sections[s];

            if (std::memcmp(section.Name, ".text", 5) != 0)
                continue;

            if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                return 0;

            const size_t textRva =
                static_cast<size_t>(section.VirtualAddress);

            if (textRva >= imageSize)
                return 0;

            size_t textSize =
                static_cast<size_t>(section.Misc.VirtualSize);

            if (textSize == 0)
            {
                textSize =
                    static_cast<size_t>(section.SizeOfRawData);
            }

            if (textSize > imageSize - textRva)
                textSize = imageSize - textRva;

            if (textSize < pattern.size())
                return 0;

            const uint8_t* text = base + textRva;

            for (size_t offset = 0;
                 offset <= textSize - pattern.size();
                 ++offset)
            {
                bool found = true;

                for (size_t i = 0; i < pattern.size(); ++i)
                {
                    const int expected = pattern[i];

                    if (expected >= 0 &&
                        (expected > 0xFF ||
                         text[offset + i] !=
                             static_cast<uint8_t>(expected)))
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


    bool SetupHook()
    {
        const uintptr_t scanAddr =
            ScanPattern(kGameModule, kPattern);

        if (!scanAddr)
            return false;

        const uintptr_t returnAddr =
            scanAddr + kPatchLength;

        void* cave = AllocNear(
            scanAddr,
            kCaveAllocationSize);

        if (!cave)
            return false;

        const uintptr_t caveAddr =
            reinterpret_cast<uintptr_t>(cave);

        // 保留原始汇编逻辑，仅修正相对跳转的写入方式。
        std::array<uint8_t, 34> caveCode = {{
            0xF3, 0x0F, 0x10, 0x8B, 0x70, 0x24, 0x00, 0x00,
            0x0F, 0x57, 0xD2,
            0x0F, 0x2F, 0xCA,
            0x77, 0x06,
            0x89, 0x8B, 0x74, 0x23, 0x00, 0x00,
            0x0F, 0x2F, 0x83, 0x70, 0x24, 0x00, 0x00,
            0xE9, 0x00, 0x00, 0x00, 0x00
        }};

        // 计算 Code Cave 返回原程序的位置。
        int32_t returnDisplacement = 0;

        if (!MakeRelative32(
                caveAddr + caveCode.size(),
                returnAddr,
                returnDisplacement))
        {
            VirtualFree(cave, 0, MEM_RELEASE);
            return false;
        }

        std::memcpy(
            caveCode.data() + caveCode.size() - sizeof(returnDisplacement),
            &returnDisplacement,
            sizeof(returnDisplacement));

        // 先以可写权限填充代码，再改为只读可执行。
        std::memcpy(cave, caveCode.data(), caveCode.size());

        DWORD oldCaveProtect = 0;

        if (!VirtualProtect(
                cave,
                caveCode.size(),
                PAGE_EXECUTE_READ,
                &oldCaveProtect))
        {
            VirtualFree(cave, 0, MEM_RELEASE);
            return false;
        }

        if (!FlushInstructionCache(
                GetCurrentProcess(),
                cave,
                caveCode.size()))
        {
            VirtualFree(cave, 0, MEM_RELEASE);
            return false;
        }

        // 构造目标位置的 E9 rel32 + NOP。
        std::array<uint8_t, kPatchLength> patch = {{
            0xE9, 0x00, 0x00, 0x00, 0x00, 0x90
        }};

        int32_t patchDisplacement = 0;

        if (!MakeRelative32(
                scanAddr + 5,
                caveAddr,
                patchDisplacement))
        {
            VirtualFree(cave, 0, MEM_RELEASE);
            return false;
        }

        std::memcpy(
            patch.data() + 1,
            &patchDisplacement,
            sizeof(patchDisplacement));

        DWORD oldTargetProtect = 0;

        if (!VirtualProtect(
                reinterpret_cast<void*>(scanAddr),
                patch.size(),
                PAGE_EXECUTE_READWRITE,
                &oldTargetProtect))
        {
            VirtualFree(cave, 0, MEM_RELEASE);
            return false;
        }

        // 安装 Hook。此后 Code Cave 必须保持有效。
        std::memcpy(
            reinterpret_cast<void*>(scanAddr),
            patch.data(),
            patch.size());

        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<void*>(scanAddr),
            patch.size());

        // 恢复原页面保护。即使恢复失败，也不能释放已被跳转引用的 Cave。
        DWORD ignoredProtect = 0;

        VirtualProtect(
            reinterpret_cast<void*>(scanAddr),
            patch.size(),
            oldTargetProtect,
            &ignoredProtect);

        return true;
    }


    DWORD WINAPI WorkerThread(LPVOID)
    {
        // 延迟执行，不在 DLL 初始化过程中扫描或修改游戏内存。
        Sleep(10000);

        constexpr unsigned kMaxAttempts = 30;
        constexpr DWORD kRetryIntervalMs = 2000;

        for (unsigned attempt = 0;
             attempt < kMaxAttempts;
             ++attempt)
        {
            if (SetupHook())
                return 0;

            if (attempt + 1 < kMaxAttempts)
                Sleep(kRetryIntervalMs);
        }

        // 安装失败后允许后续再次调用 Load() 重试。
        g_loadStarted.store(
            false,
            std::memory_order_release);

        return 0;
    }
}


// 保留 C++ 导出形式，兼容原来的 Stracker's Loader 入口约定。
__declspec(dllexport) bool Load()
{
    bool expected = false;

    if (!g_loadStarted.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel))
    {
        return true;
    }

    HANDLE thread = CreateThread(
        nullptr,
        0,
        WorkerThread,
        nullptr,
        0,
        nullptr);

    if (!thread)
    {
        g_loadStarted.store(
            false,
            std::memory_order_release);

        return false;
    }

    // 线程句柄不再需要，但工作线程会继续运行。
    CloseHandle(thread);

    return true;
}


// DllMain 不负责启动 Hook 线程。
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD reason,
    LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
    }

    return TRUE;
}
