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

    // 与 C# 版一致：
    //   [rdx+0x1D]  == 1  时才认为是主光源
    //   [rdx+0x30]  = Primary Shadow Map Size
    //   [rdx+0x174] = Primary Shadow Cascade Mode
    //
    // 只覆盖函数入口的第一条完整指令（5 字节，mov [rsp+0x10], rbx），
    // 这样跳回 scanAddr+5 时后续指令完全保持原样。
    constexpr size_t kPatchLength = 5;
    constexpr size_t kCaveSize = 0x100;

    // cave 内数据槽偏移，构造时用 static_assert 校验。
    constexpr size_t kShadowMapSizeOffset = 0x3A;
    constexpr size_t kCascadeModeOffset = 0x3E;

    // C# 版 Assert(addr == 0x141AB2260)；模块基址 0x140000000 时 RVA = 0x1AB2260。
    constexpr uintptr_t kExpectedRva = 0x1AB2260;

    // UpdatePrimaryLightParams 入口特征码。
    // 对应 C# 版：
    //   "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 56 41 57
    //    48 8B EC 48 83 EC 30 48 8B FA 48 8B D9 E8 AA B6 C1 FF
    //    48 8B 47 10 48 8D 57 50"
    const std::vector<int> kPrimaryLightPattern = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18,
        0x48, 0x89, 0x7C, 0x24, 0x20, 0x55, 0x41, 0x56, 0x41, 0x57,
        0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B, 0xFA,
        0x48, 0x8B, 0xD9, 0xE8, 0xAA, 0xB6, 0xC1, 0xFF, 0x48, 0x8B,
        0x47, 0x10, 0x48, 0x8D, 0x57, 0x50
    };

    uintptr_t g_caveAddr = 0;
    std::wstring g_iniPath;
    std::wstring g_logPath;
    FILETIME g_iniWriteTime{};
    FILE* g_logFile = nullptr;

    // ---------------------------------------------------------
    // 日志
    // ---------------------------------------------------------
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
        sprintf_s(
            line,
            _countof(line),
            "[PrimaryShadow %02u:%02u:%02u] %s\r\n",
            static_cast<unsigned>(now.wHour),
            static_cast<unsigned>(now.wMinute),
            static_cast<unsigned>(now.wSecond),
            body);

        OutputDebugStringA(line);

        if (g_logFile)
        {
            fputs(line, g_logFile);
            fflush(g_logFile);
        }
    }

    // ---------------------------------------------------------
    // 特征码扫描（保留你原来的 memchr 加速写法）
    // ---------------------------------------------------------
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
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                    return reinterpret_cast<uintptr_t>(q);

                ++q;
            }
            return 0;
        }
        return 0;
    }

    // ---------------------------------------------------------
    // Code cave 分配（同你原来的 AllocNear，含 .text 0xCC 兜底）
    // ---------------------------------------------------------
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
                    void* memory = VirtualAlloc(
                        reinterpret_cast<void*>(allocAddr),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
                    if (memory) return reinterpret_cast<uintptr_t>(memory);
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
                uintptr_t allocAddr = regionBase;
                if (allocAddr < addr) allocAddr = addr;
                allocAddr = (allocAddr + granularity - 1) & ~(granularity - 1);

                while (allocAddr + size <= regionEnd && allocAddr < upperBound)
                {
                    void* memory = VirtualAlloc(
                        reinterpret_cast<void*>(allocAddr),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
                    if (memory) return reinterpret_cast<uintptr_t>(memory);
                    allocAddr += granularity;
                }
            }
            if (regionEnd < upperBound && regionEnd > addr)
                addr = regionEnd;
            else break;
        }

        // 兜底：.text 段中连续的 0xCC 填充作为 cave。
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

            for (size_t offset = 0; offset + size <= textSize; offset += 16)
            {
                bool isPadding = true;
                for (size_t j = 0; j < size; ++j)
                {
                    if (text[offset + j] != 0xCC)
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
                        if (VirtualProtect(
                                reinterpret_cast<void*>(candidate),
                                size,
                                PAGE_EXECUTE_READWRITE,
                                &oldProtect))
                        {
                            std::memset(reinterpret_cast<void*>(candidate), 0x90, size);
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
        return displacement >= (std::numeric_limits<int32_t>::min)()
            && displacement <= (std::numeric_limits<int32_t>::max)();
    }

    // ---------------------------------------------------------
    // 安装 hook
    // ---------------------------------------------------------
    bool SetupPrimaryShadowHook()
    {
        HMODULE module = GetModuleHandleA("MonsterHunterWorld.exe");
        if (!module)
        {
            Log("module not found");
            return false;
        }

        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);
        const uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", kPrimaryLightPattern);
        if (!scanAddr)
        {
            Log("pattern not found");
            return false;
        }

        const uintptr_t rva = scanAddr - moduleBase;
        Log("found UpdatePrimaryLightParams at 0x%p (RVA 0x%p)",
            reinterpret_cast<void*>(scanAddr), reinterpret_cast<void*>(rva));
        if (rva != kExpectedRva)
        {
            Log("WARNING: RVA mismatch (expected 0x%p), version may differ",
                reinterpret_cast<void*>(kExpectedRva));
        }

        const uintptr_t returnAddr = scanAddr + kPatchLength;
        const uintptr_t caveAddr = AllocNear(scanAddr, kCaveSize);
        if (!caveAddr)
        {
            Log("AllocNear failed");
            return false;
        }

        uint8_t code[0x50] = {};
        size_t p = 0;

        // ---- 原始指令 ----
        // 48 89 5C 24 10 : mov [rsp+0x10], rbx
        code[p++] = 0x48; code[p++] = 0x89; code[p++] = 0x5C;
        code[p++] = 0x24; code[p++] = 0x10;

        // ---- 保存临时寄存器 ----
        code[p++] = 0x50; // push rax
        code[p++] = 0x51; // push rcx
        code[p++] = 0x52; // push rdx

        // ---- rax = stackOffset (mov rax, rdx) ----
        code[p++] = 0x48; code[p++] = 0x8B; code[p++] = 0xC2;

        // ---- isPrimary = byte[rax+0x1D] == 1 ----
        code[p++] = 0x0F; code[p++] = 0xB6; code[p++] = 0x40; code[p++] = 0x1D; // movzx eax, byte [rax+0x1D]
        code[p++] = 0x3C; code[p++] = 0x01;                                       // cmp al, 1
        const size_t jne_pos = p;
        code[p++] = 0x75; code[p++] = 0x00;                                       // jne skip_all

        // ---- Primary Shadow Map Size ----
        const size_t mov1_pos = p;
        code[p++] = 0x8B; code[p++] = 0x05;                                       // mov eax, [rip+disp]
        const size_t mov1_disp_pos = p;
        p += 4;
        code[p++] = 0x83; code[p++] = 0xF8; code[p++] = 0xFF;                     // cmp eax, -1
        const size_t je_size_pos = p;
        code[p++] = 0x74; code[p++] = 0x00;                                       // je skip_size
        code[p++] = 0x89; code[p++] = 0x42; code[p++] = 0x30;                     // mov [rdx+0x30], eax
        const size_t skip_size_pos = p;

        // ---- Primary Shadow Cascade Mode ----
        const size_t mov2_pos = p;
        code[p++] = 0x8B; code[p++] = 0x05;                                       // mov eax, [rip+disp]
        const size_t mov2_disp_pos = p;
        p += 4;
        code[p++] = 0x83; code[p++] = 0xF8; code[p++] = 0xFF;                     // cmp eax, -1
        const size_t je_cascade_pos = p;
        code[p++] = 0x74; code[p++] = 0x00;                                       // je skip_cascade
        code[p++] = 0x89; code[p++] = 0x82;                                       // mov [rdx+0x174], eax
        code[p++] = 0x74; code[p++] = 0x01; code[p++] = 0x00; code[p++] = 0x00;
        const size_t skip_cascade_pos = p;
        const size_t skip_all_pos = p;

        // ---- 恢复寄存器 ----
        code[p++] = 0x5A; // pop rdx
        code[p++] = 0x59; // pop rcx
        code[p++] = 0x58; // pop rax

        // ---- 跳回 ----
        const size_t jmp_back_pos = p;
        code[p++] = 0xE9;
        const size_t jmp_back_disp_pos = p;
        p += 4;

        // ---- 数据槽 ----
        const size_t shadow_size_data_pos = p; p += 4;
        const size_t cascade_mode_data_pos = p; p += 4;

        // 编译期校验 cave 内偏移常量
        static_assert(kShadowMapSizeOffset == 0x3A, "cave data layout changed");
        static_assert(kCascadeModeOffset == 0x3E, "cave data layout changed");

        if (shadow_size_data_pos != kShadowMapSizeOffset ||
            cascade_mode_data_pos != kCascadeModeOffset)
        {
            Log("internal cave offset mismatch: got 0x%zX / 0x%zX",
                shadow_size_data_pos, cascade_mode_data_pos);
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }

        // ---- 填充相对跳转 ----
        code[jne_pos + 1] = static_cast<uint8_t>(skip_all_pos - (jne_pos + 2));

        int32_t mov1_disp = static_cast<int32_t>(
            shadow_size_data_pos - (mov1_pos + 6));
        std::memcpy(&code[mov1_disp_pos], &mov1_disp, 4);
        code[je_size_pos + 1] = static_cast<uint8_t>(
            skip_size_pos - (je_size_pos + 2));

        int32_t mov2_disp = static_cast<int32_t>(
            cascade_mode_data_pos - (mov2_pos + 6));
        std::memcpy(&code[mov2_disp_pos], &mov2_disp, 4);
        code[je_cascade_pos + 1] = static_cast<uint8_t>(
            skip_cascade_pos - (je_cascade_pos + 2));

        // ---- 数据槽初始值：-1（禁用） ----
        int32_t disabled = -1;
        std::memcpy(&code[shadow_size_data_pos], &disabled, 4);
        std::memcpy(&code[cascade_mode_data_pos], &disabled, 4);

        // ---- 跳回原函数 ----
        const int64_t back_disp =
            static_cast<int64_t>(returnAddr) -
            static_cast<int64_t>(caveAddr + jmp_back_pos + 5);
        if (!FitsRel32(back_disp))
        {
            Log("back jump out of range (cave 0x%p)", reinterpret_cast<void*>(caveAddr));
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }
        int32_t back_disp32 = static_cast<int32_t>(back_disp);
        std::memcpy(&code[jmp_back_disp_pos], &back_disp32, 4);

        // ---- 写入 cave ----
        std::memcpy(reinterpret_cast<void*>(caveAddr), code, p);
        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(caveAddr),
            p);

        // ---- Patch 入口 ----
        const int64_t patch_disp =
            static_cast<int64_t>(caveAddr) -
            static_cast<int64_t>(scanAddr + 5);
        if (!FitsRel32(patch_disp))
        {
            Log("patch jump out of range (cave 0x%p)", reinterpret_cast<void*>(caveAddr));
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }
        int32_t patch_disp32 = static_cast<int32_t>(patch_disp);

        uint8_t jmp_patch[kPatchLength] = { 0xE9 };
        std::memcpy(&jmp_patch[1], &patch_disp32, 4);

        DWORD oldProtect = 0;
        if (!VirtualProtect(
                reinterpret_cast<void*>(scanAddr),
                kPatchLength,
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            Log("VirtualProtect failed");
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }

        std::memcpy(reinterpret_cast<void*>(scanAddr), jmp_patch, kPatchLength);
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

        g_caveAddr = caveAddr;
        Log("hook installed, cave=0x%p", reinterpret_cast<void*>(caveAddr));
        return true;
    }

    // ---------------------------------------------------------
    // 配置读取 / 应用
    // ---------------------------------------------------------
    struct Settings
    {
        int shadowMapSize = -1;
        int cascadeMode = -1;
    };

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

    int ReadInt(const wchar_t* section, const wchar_t* key, int def, const wchar_t* file)
    {
        wchar_t buf[64] = {};
        GetPrivateProfileStringW(section, key, L"", buf, _countof(buf), file);
        if (buf[0] == 0) return def;
        int v = 0;
        return TryParseInt(buf, v) ? v : def;
    }

    Settings LoadSettings(const std::wstring& path)
    {
        Settings s;
        s.shadowMapSize = ReadInt(L"Settings", L"ShadowMapSize", -1, path.c_str());
        s.cascadeMode = ReadInt(L"Settings", L"CascadeMode", -1, path.c_str());
        return s;
    }

    FILETIME GetFileWriteTime(const std::wstring& path)
    {
        FILETIME ft{};
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
            ft = data.ftLastWriteTime;
        return ft;
    }

    // 与 C# 版 ALIGNED_INT pStep(128) 等价
    int32_t AlignShadowSize(int size)
    {
        if (size < 0) return -1;
        return (size + 127) & ~127;
    }

    // 与 C# 版 pMinMaxStep(0, 3, 1) 等价
    int32_t ClampCascade(int mode)
    {
        if (mode < 0) return -1;
        if (mode > 3) return 3;
        return mode;
    }

    void ApplyToCave(const Settings& s)
    {
        if (!g_caveAddr) return;

        int32_t size = AlignShadowSize(s.shadowMapSize);
        int32_t mode = ClampCascade(s.cascadeMode);

        // 4 字节对齐写入在 x64 上是原子的，无需加锁。
        *reinterpret_cast<int32_t*>(g_caveAddr + kShadowMapSizeOffset) = size;
        *reinterpret_cast<int32_t*>(g_caveAddr + kCascadeModeOffset) = mode;

        Log("applied: ShadowMapSize=%d, CascadeMode=%d", size, mode);
    }

    void CreateDefaultIni(const std::filesystem::path& path)
    {
        std::error_code ec;
        if (std::filesystem::exists(path, ec)) return;

        FILE* f = nullptr;
        _wfopen_s(&f, path.c_str(), L"w");
        if (!f) return;

        fputs(
            "; Primary Shadow Tweak\r\n"
            "; Values are clamped/sanitized at load time.\r\n"
            "\r\n"
            "[Settings]\r\n"
            "; Shadow Map Size: -1 = disabled, 0 = 64x64, otherwise aligned up to a multiple of 128.\r\n"
            "ShadowMapSize=-1\r\n"
            "; Cascade Mode: -1 = disabled, 0..3 = in-game values.\r\n"
            "CascadeMode=-1\r\n",
            f);
        fclose(f);
    }

    // MSVC C2712：__try 不能和需要对象展开的局部变量放在同一个函数里。
    // 所以这里单独抽一个只有 bool 局部变量的函数，专门负责 SEH 包裹。
    bool TryInstallHookSeh()
    {
        __try
        {
            return SetupPrimaryShadowHook();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    // ---------------------------------------------------------
    // 主流程
    // ---------------------------------------------------------
    void Worker(HMODULE module)
    {
        // 解析 ini/log 路径
        wchar_t buf[MAX_PATH] = {};
        GetModuleFileNameW(module, buf, MAX_PATH);
        std::filesystem::path dllPath(buf);
        std::filesystem::path dir = dllPath.parent_path();
        std::wstring stem = dllPath.stem().wstring();

        g_iniPath = (dir / (stem + L".ini")).wstring();
        g_logPath = (dir / (stem + L".log")).wstring();

        _wfopen_s(&g_logFile, g_logPath.c_str(), L"w");
        Log("PrimaryShadow loaded from %ls", dllPath.c_str());

        CreateDefaultIni(g_iniPath);

        Settings settings = LoadSettings(g_iniPath);
        g_iniWriteTime = GetFileWriteTime(g_iniPath);
        Log("initial: ShadowMapSize=%d, CascadeMode=%d",
            settings.shadowMapSize, settings.cascadeMode);

        // 等待游戏完成初始化，然后重试扫描/安装
        Log("waiting 10s for game init...");
        Sleep(10000);

        constexpr int kMaxAttempts = 30;
        constexpr DWORD kRetryInterval = 2000;

        bool hookDone = false;
        for (int i = 0; i < kMaxAttempts && !hookDone; ++i)
        {
            if (TryInstallHookSeh())
            {
                hookDone = true;
                break;
            }

            if (i + 1 < kMaxAttempts)
                Sleep(kRetryInterval);
        }

        if (!hookDone)
        {
            Log("failed to install hook after %d attempts", kMaxAttempts);
            g_started.store(false, std::memory_order_release);
            return;
        }

        // 应用首次配置
        ApplyToCave(settings);

        // 监听 ini 变化（热更新）
        while (g_started.load(std::memory_order_acquire))
        {
            Sleep(1000);
            if (!g_started.load(std::memory_order_acquire)) break;

            FILETIME ft = GetFileWriteTime(g_iniPath);
            if (CompareFileTime(&ft, &g_iniWriteTime) == 0)
                continue;

            g_iniWriteTime = ft;

            Settings updated = LoadSettings(g_iniPath);
            if (updated.shadowMapSize == settings.shadowMapSize &&
                updated.cascadeMode == settings.cascadeMode)
            {
                continue;
            }

            settings = updated;
            Log("reloaded: ShadowMapSize=%d, CascadeMode=%d",
                settings.shadowMapSize, settings.cascadeMode);
            ApplyToCave(settings);
        }

        if (g_logFile)
        {
            fclose(g_logFile);
            g_logFile = nullptr;
        }
    }
} // namespace

// Stracker's Loader 导出入口。
__declspec(dllexport) bool Load()
{
    bool expected = false;
    if (!g_started.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
    {
        // 已经启动过了。
        return true;
    }

    HMODULE module = g_hModule;
    if (!module)
    {
        // 兜底：从 Load 自身推导模块句柄。
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&Load),
            &module);
    }

    HANDLE thread = CreateThread(
        nullptr,
        0,
        [](LPVOID param) -> DWORD
        {
            Worker(static_cast<HMODULE>(param));
            return 0;
        },
        module,
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
