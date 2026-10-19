#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>

namespace
{
    std::atomic_bool g_started{ false };
    HMODULE g_hModule = nullptr;

    // =========================================================
    // 日志
    // =========================================================
    FILE* g_logFile = nullptr;

    void Log(const char* fmt, ...)
    {
        char body[1024] = {};
        va_list args;
        va_start(args, fmt);
        vsnprintf_s(body, _countof(body), _TRUNCATE, fmt, args);
        va_end(args);

        SYSTEMTIME now{};
        GetLocalTime(&now);
        char line[1280] = {};
        sprintf_s(line, _countof(line),
            "[PrimaryShadow %02u:%02u:%02u] %s\r\n",
            static_cast<unsigned>(now.wHour),
            static_cast<unsigned>(now.wMinute),
            static_cast<unsigned>(now.wSecond),
            body);

        OutputDebugStringA(line);
        if (g_logFile) { fputs(line, g_logFile); fflush(g_logFile); }
    }

    std::wstring AsciiToW(const char* s)
    {
        size_t n = std::strlen(s);
        std::wstring out(n, L'\0');
        for (size_t i = 0; i < n; ++i) out[i] = static_cast<wchar_t>(s[i]);
        return out;
    }

    // =========================================================
    // AOB 扫描
    // =========================================================
    uintptr_t ScanPattern(const char* moduleName, const std::vector<int>& pattern)
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
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

        const auto* sections = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            const auto& section = sections[i];
            if (std::memcmp(section.Name, ".text", 5) != 0) continue;

            const size_t textSize = static_cast<size_t>(section.Misc.VirtualSize);
            if (textSize < pattern.size()) return 0;

            const uint8_t* text = reinterpret_cast<const uint8_t*>(
                moduleBase + section.VirtualAddress);
            const uint8_t* textEnd = text + textSize - pattern.size() + 1;
            const uint8_t firstByte = static_cast<uint8_t>(pattern[0]);

            for (const uint8_t* q = text; q < textEnd;)
            {
                q = static_cast<const uint8_t*>(
                    std::memchr(q, firstByte, static_cast<size_t>(textEnd - q)));
                if (!q) break;

                bool found = true;
                for (size_t j = 1; j < pattern.size(); ++j)
                {
                    if (pattern[j] != -1 && q[j] != static_cast<uint8_t>(pattern[j]))
                    { found = false; break; }
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
        const uintptr_t searchRange = 0x10000000ULL;
        const uintptr_t lowerBound = target > searchRange ? target - searchRange : granularity;
        const uintptr_t upperBound = target + searchRange;

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
                    void* m = VirtualAlloc(reinterpret_cast<void*>(allocAddr), size,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (m) return reinterpret_cast<uintptr_t>(m);
                    if (allocAddr < granularity) break;
                    allocAddr -= granularity;
                }
            }
            if (regionBase >= granularity && regionBase - granularity > lowerBound)
                addr = regionBase - granularity;
            else break;
        }

        addr = (target & ~(granularity - 1)) + granularity;
        while (addr < upperBound)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) break;
            uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t regionEnd = regionBase + mbi.RegionSize;
            if (mbi.State == MEM_FREE)
            {
                uintptr_t allocAddr = regionBase < addr ? addr : regionBase;
                allocAddr = (allocAddr + granularity - 1) & ~(granularity - 1);
                while (allocAddr + size <= regionEnd && allocAddr < upperBound)
                {
                    void* m = VirtualAlloc(reinterpret_cast<void*>(allocAddr), size,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (m) return reinterpret_cast<uintptr_t>(m);
                    allocAddr += granularity;
                }
            }
            if (regionEnd < upperBound && regionEnd > addr) addr = regionEnd;
            else break;
        }

        // 兜底：.text 0xCC 填充
        HMODULE module = GetModuleHandleA("MonsterHunterWorld.exe");
        if (!module) return 0;
        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            moduleBase + dosHeader->e_lfanew);
        const auto* sections = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            if (std::memcmp(sections[i].Name, ".text", 5) != 0) continue;
            const uintptr_t textBase = moduleBase + sections[i].VirtualAddress;
            const size_t textSize = sections[i].Misc.VirtualSize;
            const uint8_t* text = reinterpret_cast<const uint8_t*>(textBase);

            for (size_t off = 0; off + size <= textSize; off += 16)
            {
                bool pad = true;
                for (size_t j = 0; j < size; ++j)
                    if (text[off + j] != 0xCC) { pad = false; break; }
                if (pad)
                {
                    uintptr_t cand = textBase + off;
                    int64_t dist = static_cast<int64_t>(cand) - static_cast<int64_t>(target);
                    if (dist >= INT32_MIN && dist <= INT32_MAX)
                    {
                        DWORD old;
                        if (VirtualProtect(reinterpret_cast<void*>(cand), size,
                            PAGE_EXECUTE_READWRITE, &old))
                        {
                            std::memset(reinterpret_cast<void*>(cand), 0x90, size);
                            return cand;
                        }
                    }
                }
            }
        }
        return 0;
    }

    bool FitsRel32(int64_t d)
    {
        return d >= (std::numeric_limits<int32_t>::min)()
            && d <= (std::numeric_limits<int32_t>::max)();
    }

    // =========================================================
    // Shadow 参数定义
    // =========================================================
    constexpr int32_t kNoLimit = INT32_MIN;

    enum class ParamType : uint32_t
    {
        Bool,
        Int,
        Float,
    };

    struct ShadowOverrideDef
    {
        const char* iniKey;
        uint32_t offset;       // stackOffset 内偏移
        ParamType type;
        int32_t minValue;      // kNoLimit 表示无限制
        int32_t maxValue;
        bool negativeMeansDisable; // ShadowMapSize / CascadeMode 用
    };

    const ShadowOverrideDef kShadowOverrideDefs[] = {
        // ===== Primary Shadow Map Size / Cascade Mode =====
        { "ShadowMapSize",                             0x30,  ParamType::Int,   0,        kNoLimit, true },
        { "CascadeMode",                               0x174, ParamType::Int,   0,        3,        true },

        // ===== Primary Shadow 基础 =====
        { "PrimaryShadowCast",                         0x23,  ParamType::Bool,  0,        1,        false },
        { "PrimaryShadowNearClipDistance",             0x28,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowSampleNum",                    0x1DC, ParamType::Int,   0,        kNoLimit, false },
        { "PrimaryShadowRadius",                       0x1EC, ParamType::Float, kNoLimit, kNoLimit, false },

        // ===== FOV =====
        { "PrimaryShadowIsFixedFovMode",               0x1F9, ParamType::Bool,  0,        1,        false },
        { "PrimaryShadowFov",                          0x1F4, ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowIsDiscretizationFovMode",      0x205, ParamType::Bool,  0,        1,        false },
        { "PrimaryShadowDiscretizationAngle",          0x200, ParamType::Float, kNoLimit, kNoLimit, false },

        // ===== Cascade 基础 =====
        { "PrimaryShadowCascade2WayBias",              0x17C, ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeDistance",              0x6C,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeBackforwardDistance",   0x7C,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeDistribution",          0x74,  ParamType::Float, kNoLimit, kNoLimit, false },

        // ===== Cascade 手动分割 =====
        { "PrimaryShadowCascadeManualSplit",           0x4D,  ParamType::Bool,  0,        1,        false },
        { "PrimaryShadowCascadeManualSplitDistance0",  0x54,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeManualSplitDistance1",  0x5C,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeManualSplitDistance2",  0x64,  ParamType::Float, kNoLimit, kNoLimit, false },

        // ===== 通用 Depth Bias =====
        { "PrimaryShadowDepthBias",                    0x38,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowSlopedDepthBias",              0x40,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowMaxDepthBias",                 0x48,  ParamType::Float, kNoLimit, kNoLimit, false },

        // ===== 单独 Cascade Bias =====
        { "PrimaryShadowCascadeIndividualShadowBias",  0x81,  ParamType::Bool,  0,        1,        false },
        { "PrimaryShadowCascadeDepthBias0",            0x88,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeDepthBias1",            0x90,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeDepthBias2",            0x98,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeSlopedDepthBias0",      0xA0,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeSlopedDepthBias1",      0xA8,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeSlopedDepthBias2",      0xB0,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeMaxDepthBias0",         0xB8,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeMaxDepthBias1",         0xC0,  ParamType::Float, kNoLimit, kNoLimit, false },
        { "PrimaryShadowCascadeMaxDepthBias2",         0xC8,  ParamType::Float, kNoLimit, kNoLimit, false },

        // ===== Broad Area（同样在 primary light params 内）=====
        { "BroadAreaShadowDepthBias",                  0x1C4, ParamType::Float, kNoLimit, kNoLimit, false },
        { "BroadAreaShadowSlopedDepthBias",            0x1CC, ParamType::Float, kNoLimit, kNoLimit, false },
        { "BroadAreaShadowMaxDepthBias",               0x1D4, ParamType::Float, kNoLimit, kNoLimit, false },
    };

    constexpr size_t kShadowOverrideCount =
        sizeof(kShadowOverrideDefs) / sizeof(kShadowOverrideDefs[0]);

    struct ShadowOverrideRuntime
    {
        std::atomic<bool> enabled{ false };
        std::atomic<int32_t> bits{ 0 };
    };

    ShadowOverrideRuntime g_shadowRuntime[kShadowOverrideCount];

    void ApplyShadowOverridesImpl(uintptr_t stackOffset)
    {
        if (!stackOffset) return;

        // 与 World Tuning Tool 一致：只对主光源写
        if (*reinterpret_cast<uint8_t*>(stackOffset + 0x1D) != 1) return;

        for (size_t i = 0; i < kShadowOverrideCount; ++i)
        {
            auto& rt = g_shadowRuntime[i];
            if (!rt.enabled.load(std::memory_order_relaxed)) continue;

            int32_t bits = rt.bits.load(std::memory_order_relaxed);
            const auto& def = kShadowOverrideDefs[i];

            switch (def.type)
            {
            case ParamType::Bool:
                *reinterpret_cast<uint8_t*>(stackOffset + def.offset) =
                    (bits != 0) ? 1 : 0;
                break;
            case ParamType::Int:
                *reinterpret_cast<int32_t*>(stackOffset + def.offset) = bits;
                break;
            case ParamType::Float:
            {
                float f;
                std::memcpy(&f, &bits, 4);
                *reinterpret_cast<float*>(stackOffset + def.offset) = f;
                break;
            }
            }
        }
    }

    // 由 trampoline 调用，栈对齐已由 trampoline 保证
    extern "C" void ApplyShadowOverrides(uintptr_t stackOffset)
    {
        __try { ApplyShadowOverridesImpl(stackOffset); }
        __except (EXCEPTION_EXECUTE_HANDLER) { /* 无效指针，忽略 */ }
    }

    // =========================================================
    // 安装 PrimaryLight Hook
    // =========================================================
    constexpr size_t kPatchLength = 5;
    constexpr size_t kCaveSize = 0x100;
    constexpr uintptr_t kExpectedRva = 0x1AB2260;

    const std::vector<int> kPrimaryLightPattern = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
        0x48, 0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57,
        0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0xFA,
        0x48, 0x8B, 0xD9, 0xE8, 0xAA, 0xB6, 0xC1, 0xFF, 0x48, 0x8B,
        0x47, 0x10, 0x48, 0x8D, 0x57, 0x50
    };

    uintptr_t g_caveAddr = 0;

    bool SetupPrimaryShadowHook()
    {
        HMODULE module = GetModuleHandleA("MonsterHunterWorld.exe");
        if (!module) { Log("module not found"); return false; }

        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);
        const uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", kPrimaryLightPattern);
        if (!scanAddr) { Log("pattern not found"); return false; }

        const uintptr_t rva = scanAddr - moduleBase;
        Log("found UpdatePrimaryLightParams at 0x%p (RVA 0x%p)",
            reinterpret_cast<void*>(scanAddr), reinterpret_cast<void*>(rva));
        if (rva != kExpectedRva)
            Log("WARNING: RVA mismatch (expected 0x%p)", reinterpret_cast<void*>(kExpectedRva));

        const uintptr_t returnAddr = scanAddr + kPatchLength;
        const uintptr_t caveAddr = AllocNear(scanAddr, kCaveSize);
        if (!caveAddr) { Log("AllocNear failed"); return false; }

        uint8_t code[0x40] = {};
        size_t p = 0;

        // 原指令: mov [rsp+0x10], rbx
        code[p++] = 0x48; code[p++] = 0x89; code[p++] = 0x5C;
        code[p++] = 0x24; code[p++] = 0x10;

        // push rax, rcx, rdx, r8, r9, r10, r11
        code[p++] = 0x50;                     // push rax
        code[p++] = 0x51;                     // push rcx
        code[p++] = 0x52;                     // push rdx
        code[p++] = 0x41; code[p++] = 0x50;   // push r8
        code[p++] = 0x41; code[p++] = 0x51;   // push r9
        code[p++] = 0x41; code[p++] = 0x52;   // push r10
        code[p++] = 0x41; code[p++] = 0x53;   // push r11

        // mov rcx, rdx  (stackOffset -> 第一个参数)
        code[p++] = 0x48; code[p++] = 0x89; code[p++] = 0xD1;

        // mov rax, &ApplyShadowOverrides ; call rax
        code[p++] = 0x48; code[p++] = 0xB8;
        uint64_t funcAddr = reinterpret_cast<uint64_t>(&ApplyShadowOverrides);
        std::memcpy(&code[p], &funcAddr, 8); p += 8;
        code[p++] = 0xFF; code[p++] = 0xD0;

        // pop r11, r10, r9, r8, rdx, rcx, rax
        code[p++] = 0x41; code[p++] = 0x5B;
        code[p++] = 0x41; code[p++] = 0x5A;
        code[p++] = 0x41; code[p++] = 0x59;
        code[p++] = 0x41; code[p++] = 0x58;
        code[p++] = 0x5A;
        code[p++] = 0x59;
        code[p++] = 0x58;

        // jmp returnAddr
        code[p++] = 0xE9;
        const size_t jmp_disp_pos = p;
        p += 4;

        const int64_t back_disp =
            static_cast<int64_t>(returnAddr) - static_cast<int64_t>(caveAddr + p);
        if (!FitsRel32(back_disp))
        {
            Log("back jump out of range");
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }
        int32_t back_disp32 = static_cast<int32_t>(back_disp);
        std::memcpy(&code[jmp_disp_pos], &back_disp32, 4);

        std::memcpy(reinterpret_cast<void*>(caveAddr), code, p);
        FlushInstructionCache(GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(caveAddr), p);

        const int64_t patch_disp =
            static_cast<int64_t>(caveAddr) - static_cast<int64_t>(scanAddr + 5);
        if (!FitsRel32(patch_disp))
        {
            Log("patch jump out of range");
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }
        int32_t patch_disp32 = static_cast<int32_t>(patch_disp);

        uint8_t jmp_patch[kPatchLength] = { 0xE9 };
        std::memcpy(&jmp_patch[1], &patch_disp32, 4);

        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(scanAddr), kPatchLength,
            PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            Log("VirtualProtect failed");
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }
        std::memcpy(reinterpret_cast<void*>(scanAddr), jmp_patch, kPatchLength);
        FlushInstructionCache(GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(scanAddr), kPatchLength);
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(scanAddr), kPatchLength,
            oldProtect, &ignored);

        g_caveAddr = caveAddr;
        Log("hook installed, trampoline=%zu bytes, cave=0x%p",
            p, reinterpret_cast<void*>(caveAddr));
        return true;
    }

    bool TryInstallHookSeh()
    {
        __try { return SetupPrimaryShadowHook(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    // =========================================================
    // Patch 系统（保持上一版）
    // =========================================================
    struct PatchEntry
    {
        const char* feature;
        uintptr_t rva;
        const uint8_t* data;
        size_t length;
    };

    static const uint8_t kHQModeBytes[]              = { 0xC6, 0x87, 0xA3, 0xE9, 0x00, 0x00, 0x01 };
    static const uint8_t kVolumeQualityBytes[]       = { 0xB8, 0x02, 0x00, 0x00, 0x00, 0x90 };
    static const uint8_t kNukeEffectsBytes[]         = { 0xEB };
    static const uint8_t kSkipSSLRMipMapBytes[]      = { 0x31, 0xC0, 0x90, 0x90, 0x90 };
    static const uint8_t kSSLRTemporalResetBytes[]   = { 0xB9, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90 };
    static const uint8_t kFrameSkipBytes[]           = { 0x31, 0xC0, 0x90, 0x90, 0x90, 0x90 };
    static const uint8_t kCharCreatorFaceBytes[]     = { 0x01 };
    static const uint8_t kFoliageSwayBytes[]         = { 0x04 };
    static const uint8_t kViewModeLOD1Bytes[]        = { 0x1C, 0x02, 0x00, 0x00 };
    static const uint8_t kViewModeLOD2Bytes[]        = { 0x20, 0x02, 0x00, 0x00 };
    static const uint8_t kDisableLODLimits1Bytes[]   = { 0x07, 0x74, 0x0A, 0xC7, 0x83, 0xDC, 0xEB, 0x00, 0x00, 0x07 };
    static const uint8_t kSingleByte07[]             = { 0x07 };
    static const uint8_t kVolumeBlurNop[]            = { 0x90, 0x90 };

    static const PatchEntry kPatchTable[] = {
        { "HQMode",                    0x226562B, kHQModeBytes,            sizeof(kHQModeBytes) },
        { "VolumeQuality",             0x2389652, kVolumeQualityBytes,     sizeof(kVolumeQualityBytes) },
        { "NukeEffects",               0x263483B, kNukeEffectsBytes,       sizeof(kNukeEffectsBytes) },
        { "SkipSSLRMipMap",            0x2282B53, kSkipSSLRMipMapBytes,    sizeof(kSkipSSLRMipMapBytes) },
        { "ContinousSSLRTemporalReset",0x228CE53, kSSLRTemporalResetBytes, sizeof(kSSLRTemporalResetBytes) },
        { "DisableFrameSkip",          0x2246948, kFrameSkipBytes,         sizeof(kFrameSkipBytes) },
        { "CharCreatorFace",           0x1B1A0C7, kCharCreatorFaceBytes,   sizeof(kCharCreatorFaceBytes) },
        { "FoliageSway",               0x26D89D1, kFoliageSwayBytes,       sizeof(kFoliageSwayBytes) },
        { "ViewModeLOD",               0x1B19A70, kViewModeLOD1Bytes,      sizeof(kViewModeLOD1Bytes) },
        { "ViewModeLOD",               0x1B19B80, kViewModeLOD2Bytes,      sizeof(kViewModeLOD2Bytes) },
        { "DisableLODLimits",          0x1B1A0F4, kDisableLODLimits1Bytes, sizeof(kDisableLODLimits1Bytes) },
        { "DisableLODLimits",          0x0257B08, kSingleByte07,           1 },
        { "DisableLODLimits",          0x175445C, kSingleByte07,           1 },
        { "DisableLODLimits",          0x128F1AD, kSingleByte07,           1 },
        { "DisableLODLimits",          0x128F1BB, kSingleByte07,           1 },
        { "FullResVolumeBlur",         0x24D0159, kVolumeBlurNop,          2 },
        { "FullResVolumeBlur",         0x24D01A0, kVolumeBlurNop,          2 },
        { "FullResVolumeBlur",         0x24D01C6, kVolumeBlurNop,          2 },
        { "FullResVolumeBlur",         0x24D0219, kVolumeBlurNop,          2 },
        { "FullResVolumeBlur",         0x24D0242, kVolumeBlurNop,          2 },
        { "FullResVolumeBlur",         0x24D029D, kVolumeBlurNop,          2 },
        { "FullResVolumeBlur",         0x24D02C6, kVolumeBlurNop,          2 },
        { "FullResVolumeBlur",         0x24D0321, kVolumeBlurNop,          2 },
        { "FullResVolumeBlur",         0x24D034A, kVolumeBlurNop,          2 },
    };
    constexpr size_t kPatchCount = sizeof(kPatchTable) / sizeof(kPatchTable[0]);

    const char* kFeatureNames[] = {
        "HQMode", "VolumeQuality", "NukeEffects", "SkipSSLRMipMap",
        "ContinousSSLRTemporalReset", "DisableFrameSkip", "CharCreatorFace",
        "FoliageSway", "ViewModeLOD", "DisableLODLimits", "FullResVolumeBlur",
    };
    constexpr size_t kFeatureCount = sizeof(kFeatureNames) / sizeof(kFeatureNames[0]);

    struct PatchRuntime { std::vector<uint8_t> original; bool saved = false; };
    PatchRuntime g_patchRuntime[kPatchCount];

    void ApplyFeature(const char* feature, bool enable)
    {
        HMODULE module = GetModuleHandleA("MonsterHunterWorld.exe");
        if (!module) { Log("ApplyFeature(%s): module not found", feature); return; }
        const uintptr_t base = reinterpret_cast<uintptr_t>(module);
        int applied = 0;

        for (size_t i = 0; i < kPatchCount; ++i)
        {
            const auto& e = kPatchTable[i];
            if (_stricmp(e.feature, feature) != 0) continue;

            const uintptr_t addr = base + e.rva;
            auto& rt = g_patchRuntime[i];
            if (!rt.saved)
            {
                rt.original.resize(e.length);
                std::memcpy(rt.original.data(), reinterpret_cast<void*>(addr), e.length);
                rt.saved = true;
            }

            DWORD old = 0;
            if (!VirtualProtect(reinterpret_cast<void*>(addr), e.length,
                PAGE_EXECUTE_READWRITE, &old))
            {
                Log("VirtualProtect failed for %s at 0x%p", feature,
                    reinterpret_cast<void*>(addr));
                continue;
            }

            std::memcpy(reinterpret_cast<void*>(addr),
                enable ? e.data : rt.original.data(), e.length);
            FlushInstructionCache(GetCurrentProcess(),
                reinterpret_cast<void*>(addr), e.length);

            DWORD ignored = 0;
            VirtualProtect(reinterpret_cast<void*>(addr), e.length, old, &ignored);
            ++applied;
        }
        Log("feature %s: %s (%d sites)", feature, enable ? "on" : "off", applied);
    }

    // =========================================================
    // INI
    // =========================================================
    bool TryParseInt(const wchar_t* s, int& out)
    {
        if (!s || !s[0]) return false;
        wchar_t* end = nullptr;
        long v = wcstol(s, &end, 10);
        if (end == s) return false;
        while (*end == L' ' || *end == L'\t') ++end;
        if (*end != 0) return false;
        out = static_cast<int>(v);
        return true;
    }

    int ReadInt(const wchar_t* sec, const wchar_t* key, int def, const wchar_t* file)
    {
        wchar_t buf[64] = {};
        GetPrivateProfileStringW(sec, key, L"", buf, _countof(buf), file);
        if (buf[0] == 0) return def;
        int v = 0;
        return TryParseInt(buf, v) ? v : def;
    }

    FILETIME GetFileWriteTime(const std::wstring& path)
    {
        FILETIME ft{};
        WIN32_FILE_ATTRIBUTE_DATA d{};
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &d))
            ft = d.ftLastWriteTime;
        return ft;
    }

    void ReloadShadowOverrides(const std::wstring& iniPath)
    {
        int enabled = 0;
        for (size_t i = 0; i < kShadowOverrideCount; ++i)
        {
            const auto& def = kShadowOverrideDefs[i];
            std::wstring wkey = AsciiToW(def.iniKey);

            wchar_t buf[128] = {};
            GetPrivateProfileStringW(L"Shadow", wkey.c_str(), L"", buf,
                _countof(buf), iniPath.c_str());

            if (buf[0] == 0)
            {
                g_shadowRuntime[i].enabled.store(false, std::memory_order_relaxed);
                continue;
            }

            bool ok = false;
            int32_t bits = 0;

            switch (def.type)
            {
            case ParamType::Bool:
            {
                int v = 0;
                if (TryParseInt(buf, v)) { bits = (v != 0) ? 1 : 0; ok = true; }
                break;
            }
            case ParamType::Int:
            {
                int v = 0;
                if (TryParseInt(buf, v)) { bits = v; ok = true; }
                break;
            }
            case ParamType::Float:
            {
                wchar_t* end = nullptr;
                double d = wcstod(buf, &end);
                if (end != buf)
                {
                    float f = static_cast<float>(d);
                    std::memcpy(&bits, &f, 4);
                    ok = true;
                }
                break;
            }
            }

            if (!ok)
            {
                Log("failed to parse %s = %ls", def.iniKey, buf);
                g_shadowRuntime[i].enabled.store(false, std::memory_order_relaxed);
                continue;
            }

            // 负值禁用 + 对齐/clamp
            bool disabled = false;
            if (def.negativeMeansDisable)
            {
                if (bits < 0) disabled = true;
                else if (strcmp(def.iniKey, "ShadowMapSize") == 0)
                    bits = (bits + 127) & ~127;
                else if (strcmp(def.iniKey, "CascadeMode") == 0)
                    bits = (bits > 3) ? 3 : bits;
            }
            else
            {
                if (def.minValue != kNoLimit && bits < def.minValue) bits = def.minValue;
                if (def.maxValue != kNoLimit && bits > def.maxValue) bits = def.maxValue;
            }

            if (disabled)
            {
                g_shadowRuntime[i].enabled.store(false, std::memory_order_relaxed);
                continue;
            }

            g_shadowRuntime[i].bits.store(bits, std::memory_order_relaxed);
            g_shadowRuntime[i].enabled.store(true, std::memory_order_relaxed);
            ++enabled;
        }
        Log("shadow overrides: %d / %zu enabled", enabled, kShadowOverrideCount);
    }

    void ApplyAllPatches(const std::wstring& iniPath)
    {
        for (size_t i = 0; i < kFeatureCount; ++i)
        {
            std::wstring wname = AsciiToW(kFeatureNames[i]);
            int v = ReadInt(L"Patches", wname.c_str(), 0, iniPath.c_str());
            ApplyFeature(kFeatureNames[i], v != 0);
        }
    }

    void CreateDefaultIni(const std::filesystem::path& path)
    {
        std::error_code ec;
        if (std::filesystem::exists(path, ec)) return;

        FILE* f = nullptr;
        _wfopen_s(&f, path.c_str(), L"w");
        if (!f) return;

        fputs(
            "; PrimaryShadow\r\n"
            "; Version-locked to the MonsterHunterWorld.exe build targeted by\r\n"
            "; World Tuning Tool. If a value causes issues, clear it.\r\n"
            "\r\n"
            "[Shadow]\r\n"
            "; Leave a value empty to disable that override.\r\n"
            "; Ints / bools: decimal integer. Floats: decimal floating point.\r\n"
            "; Negative values disable only ShadowMapSize and CascadeMode.\r\n"
            "\r\n"
            "; --- Primary shadow map / cascade ---\r\n"
            "; Shadow Map Size: 0 = 64x64, otherwise aligned up to a multiple of 128.\r\n"
            "ShadowMapSize=\r\n"
            "; Cascade Mode: 0..3.\r\n"
            "CascadeMode=\r\n"
            "\r\n"
            "; --- Primary Shadow basic ---\r\n"
            "PrimaryShadowCast=\r\n"
            "PrimaryShadowNearClipDistance=\r\n"
            "PrimaryShadowSampleNum=\r\n"
            "PrimaryShadowRadius=\r\n"
            "\r\n"
            "; --- FOV ---\r\n"
            "PrimaryShadowIsFixedFovMode=\r\n"
            "PrimaryShadowFov=\r\n"
            "PrimaryShadowIsDiscretizationFovMode=\r\n"
            "PrimaryShadowDiscretizationAngle=\r\n"
            "\r\n"
            "; --- Cascade ---\r\n"
            "PrimaryShadowCascade2WayBias=\r\n"
            "PrimaryShadowCascadeDistance=\r\n"
            "PrimaryShadowCascadeBackforwardDistance=\r\n"
            "PrimaryShadowCascadeDistribution=\r\n"
            "PrimaryShadowCascadeManualSplit=\r\n"
            "PrimaryShadowCascadeManualSplitDistance0=\r\n"
            "PrimaryShadowCascadeManualSplitDistance1=\r\n"
            "PrimaryShadowCascadeManualSplitDistance2=\r\n"
            "\r\n"
            "; --- Depth bias ---\r\n"
            "PrimaryShadowDepthBias=\r\n"
            "PrimaryShadowSlopedDepthBias=\r\n"
            "PrimaryShadowMaxDepthBias=\r\n"
            "\r\n"
            "; --- Per-cascade bias ---\r\n"
            "PrimaryShadowCascadeIndividualShadowBias=\r\n"
            "PrimaryShadowCascadeDepthBias0=\r\n"
            "PrimaryShadowCascadeDepthBias1=\r\n"
            "PrimaryShadowCascadeDepthBias2=\r\n"
            "PrimaryShadowCascadeSlopedDepthBias0=\r\n"
            "PrimaryShadowCascadeSlopedDepthBias1=\r\n"
            "PrimaryShadowCascadeSlopedDepthBias2=\r\n"
            "PrimaryShadowCascadeMaxDepthBias0=\r\n"
            "PrimaryShadowCascadeMaxDepthBias1=\r\n"
            "PrimaryShadowCascadeMaxDepthBias2=\r\n"
            "\r\n"
            "; --- Broad area (within primary light params) ---\r\n"
            "BroadAreaShadowDepthBias=\r\n"
            "BroadAreaShadowSlopedDepthBias=\r\n"
            "BroadAreaShadowMaxDepthBias=\r\n"
            "\r\n"
            "[Patches]\r\n"
            "; 0 = disabled, 1 = enabled.\r\n"
            "HQMode=0\r\n"
            "VolumeQuality=0\r\n"
            "NukeEffects=0\r\n"
            "SkipSSLRMipMap=0\r\n"
            "ContinousSSLRTemporalReset=0\r\n"
            "DisableFrameSkip=0\r\n"
            "CharCreatorFace=0\r\n"
            "FoliageSway=0\r\n"
            "ViewModeLOD=0\r\n"
            "DisableLODLimits=0\r\n"
            "FullResVolumeBlur=0\r\n",
            f);
        fclose(f);
    }

    // =========================================================
    // Worker
    // =========================================================
    void Worker(HMODULE module)
    {
        wchar_t buf[MAX_PATH] = {};
        GetModuleFileNameW(module, buf, MAX_PATH);
        std::filesystem::path dllPath(buf);
        std::filesystem::path dir = dllPath.parent_path();
        std::wstring stem = dllPath.stem().wstring();

        std::wstring iniPath = (dir / (stem + L".ini")).wstring();
        std::wstring logPath = (dir / (stem + L".log")).wstring();

        _wfopen_s(&g_logFile, logPath.c_str(), L"w");
        Log("loaded from %ls", dllPath.c_str());

        CreateDefaultIni(iniPath);
        FILETIME iniTime = GetFileWriteTime(iniPath);

        Log("waiting 10s for game init...");
        Sleep(10000);

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;
        bool hookDone = false;

        for (int i = 0; i < kMaxAttempts && !hookDone; ++i)
        {
            if (TryInstallHookSeh()) { hookDone = true; break; }
            if (i + 1 < kMaxAttempts) Sleep(kRetryInterval);
        }

        if (!hookDone)
        {
            Log("failed to install hook after %d attempts", kMaxAttempts);
            g_started.store(false, std::memory_order_release);
            return;
        }

        ApplyAllPatches(iniPath);
        ReloadShadowOverrides(iniPath);

        while (g_started.load(std::memory_order_acquire))
        {
            Sleep(1000);
            if (!g_started.load(std::memory_order_acquire)) break;

            FILETIME ft = GetFileWriteTime(iniPath);
            if (CompareFileTime(&ft, &iniTime) == 0) continue;

            iniTime = ft;
            Log("INI changed, reloading...");
            ApplyAllPatches(iniPath);
            ReloadShadowOverrides(iniPath);
        }

        if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
    }
} // namespace

__declspec(dllexport) bool Load()
{
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return true;

    HMODULE module = g_hModule;
    if (!module)
    {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&Load), &module);
    }

    HANDLE thread = CreateThread(nullptr, 0,
        [](LPVOID param) -> DWORD
        { Worker(static_cast<HMODULE>(param)); return 0; },
        module, 0, nullptr);

    if (!thread)
    {
        g_started.store(false, std::memory_order_release);
        return false;
    }
    CloseHandle(thread);
    return true;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        g_hModule = module;
        Load();
    }
    return TRUE;
}
