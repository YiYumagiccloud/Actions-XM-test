#include <windows.h>

#include <atomic>
#include <cstdarg>
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

    // cSystem:Ctor 的 Pattern（来自 AddressRecords.json）
    // 匹配到的是 "48 83 C1 08 ..." 这条，函数入口在匹配位置 - 19 字节。
    const std::vector<int> kCSystemCtorPattern = {
        0x48, 0x83, 0xC1, 0x08, 0xFF, 0x15, -1, -1, -1, -1,
        0x48, 0x8B, 0xC3, 0xC6, 0x43, 0x30, 0x01,
        0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
    };
    constexpr int kCSystemCtorOffset = -19;

    // 实际 prologue 是 40 53 48 83 EC XX（6 字节），覆盖 6 字节后跳回 ctor+6
    constexpr size_t kPatchLength = 6;
    constexpr size_t kCaveSize = 0x100;

    // sVolumeRenderer + 0x38 是 bool
    constexpr uintptr_t kVolumeRendererEnabledOffset = 0x38;

    // 单例记录上限
    constexpr size_t kMaxSingletons = 4096;
    void* g_singletons[kMaxSingletons] = {};
    std::atomic<size_t> g_singletonCount{ 0 };

    std::atomic<void*> g_volumeRenderer{ nullptr };

    uintptr_t g_cSystemCtorAddr = 0;
    uintptr_t g_cSystemCtorCave = 0;

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
    // 特征码扫描
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
    // Code cave 分配
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
    // cSystem::Ctor 的 cave 入口会被调用到这里
    // 运行在游戏线程，必须简单、无异常、无分配。
    // ---------------------------------------------------------
    extern "C" void RecordSingleton(void* thisPtr)
    {
        const size_t idx = g_singletonCount.fetch_add(1, std::memory_order_acq_rel);
        if (idx < kMaxSingletons)
        {
            g_singletons[idx] = thisPtr;
        }
    }

    // ---------------------------------------------------------
    // SEH 辅助（都只有标量局部变量，避免 C2712）
    // ---------------------------------------------------------
    bool TryReadU64(uintptr_t addr, uint64_t& out)
    {
        __try
        {
            out = *reinterpret_cast<uint64_t*>(addr);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool IsReadableString(uintptr_t addr)
    {
        __try
        {
            const char* p = reinterpret_cast<const char*>(addr);
            char c = p[0];
            if (c < 'a' || c > 'z') return false;
            for (int i = 1; i < 128; i++)
            {
                char ch = p[i];
                if (ch == 0) return true;
                if (ch < 0x20 || ch > 0x7E) return false;
            }
            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void* GetDtiSafe(void* inst)
    {
        __try
        {
            void** vtable = *reinterpret_cast<void***>(inst);
            if (!vtable || !vtable[4]) return nullptr;
            using GetDtiFn = void* (*)(void*);
            auto fn = reinterpret_cast<GetDtiFn>(vtable[4]);
            return fn(inst);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return nullptr;
        }
    }

    bool TryWriteBool(uintptr_t addr, bool value)
    {
        __try
        {
            *reinterpret_cast<bool*>(addr) = value;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    // ---------------------------------------------------------
    // DTI 名字读取
    // 从 MtDti:Find (39 48 34 ... 48 8B 40 28) 推断：
    //   0x28 = hash next
    //   0x30 = flags
    //   0x34 = hash
    // Name 通常在 0x20，但尝试 0x18/0x20/0x28 防止猜错。
    // ---------------------------------------------------------
    const char* ReadDtiNameSafe(void* dti)
    {
        const uintptr_t base = reinterpret_cast<uintptr_t>(dti);
        const uintptr_t candidates[] = { 0x18, 0x20, 0x28 };
        for (size_t i = 0; i < 3; i++)
        {
            uint64_t namePtr = 0;
            if (!TryReadU64(base + candidates[i], namePtr)) continue;
            if (namePtr < 0x10000) continue;
            if (IsReadableString(static_cast<uintptr_t>(namePtr)))
                return reinterpret_cast<const char*>(namePtr);
        }
        return nullptr;
    }

    // ---------------------------------------------------------
    // 安装 cSystem::Ctor Hook
    // ---------------------------------------------------------
    bool InstallCSystemCtorHook()
    {
        HMODULE module = GetModuleHandleA("MonsterHunterWorld.exe");
        if (!module)
        {
            Log("module not found");
            return false;
        }

        const uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", kCSystemCtorPattern);
        if (!scanAddr)
        {
            Log("cSystem:Ctor pattern not found");
            return false;
        }

        const uintptr_t ctorAddr = scanAddr + kCSystemCtorOffset;
        Log("cSystem:Ctor at 0x%p (pattern 0x%p)",
            reinterpret_cast<void*>(ctorAddr), reinterpret_cast<void*>(scanAddr));

        // 预期入口: 40 53 48 83 EC XX  (push rbx; sub rsp, imm8)
        const uint8_t* entry = reinterpret_cast<const uint8_t*>(ctorAddr);
        if (entry[0] != 0x40 || entry[1] != 0x53 ||
            entry[2] != 0x48 || entry[3] != 0x83 || entry[4] != 0xEC)
        {
            Log("unexpected prologue at cSystem:Ctor: %02X %02X %02X %02X %02X",
                entry[0], entry[1], entry[2], entry[3], entry[4]);
            return false;
        }

        const uint8_t stackSub = entry[5];
        Log("entry prologue: 40 53 48 83 EC %02X (sub rsp, 0x%02X)", stackSub, stackSub);

        const uintptr_t returnAddr = ctorAddr + kPatchLength;
        const uintptr_t caveAddr = AllocNear(ctorAddr, kCaveSize);
        if (!caveAddr)
        {
            Log("AllocNear failed for cSystem:Ctor");
            return false;
        }

        uint8_t code[0x80] = {};
        size_t p = 0;

        // 重放被覆盖的 prologue: push rbx; sub rsp, XX
        code[p++] = 0x40; code[p++] = 0x53;
        code[p++] = 0x48; code[p++] = 0x83; code[p++] = 0xEC; code[p++] = stackSub;

        // 保存 volatile 寄存器
        code[p++] = 0x50;                               // push rax
        code[p++] = 0x51;                               // push rcx (this)
        code[p++] = 0x52;                               // push rdx
        code[p++] = 0x41; code[p++] = 0x50;             // push r8
        code[p++] = 0x41; code[p++] = 0x51;             // push r9
        code[p++] = 0x41; code[p++] = 0x52;             // push r10
        code[p++] = 0x41; code[p++] = 0x53;             // push r11

        // mov rax, RecordSingleton
        code[p++] = 0x48;
        code[p++] = 0xB8;
        const uint64_t fnAddr = reinterpret_cast<uint64_t>(&RecordSingleton);
        std::memcpy(&code[p], &fnAddr, 8);
        p += 8;

        // call rax  (rcx 仍为 this)
        code[p++] = 0xFF;
        code[p++] = 0xD0;

        // 恢复 volatile 寄存器
        code[p++] = 0x41; code[p++] = 0x5B;             // pop r11
        code[p++] = 0x41; code[p++] = 0x5A;             // pop r10
        code[p++] = 0x41; code[p++] = 0x59;             // pop r9
        code[p++] = 0x41; code[p++] = 0x58;             // pop r8
        code[p++] = 0x5A;                               // pop rdx
        code[p++] = 0x59;                               // pop rcx
        code[p++] = 0x58;                               // pop rax

        // jmp returnAddr
        const size_t jmp_pos = p;
        code[p++] = 0xE9;
        const size_t jmp_disp_pos = p;
        p += 4;

        const int64_t backDisp =
            static_cast<int64_t>(returnAddr) -
            static_cast<int64_t>(caveAddr + jmp_pos + 5);
        if (!FitsRel32(backDisp))
        {
            Log("cSystem:Ctor back jump out of range (cave 0x%p)",
                reinterpret_cast<void*>(caveAddr));
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }
        int32_t backDisp32 = static_cast<int32_t>(backDisp);
        std::memcpy(&code[jmp_disp_pos], &backDisp32, 4);

        std::memcpy(reinterpret_cast<void*>(caveAddr), code, p);
        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(caveAddr),
            p);

        // Patch 前 6 字节: E9 rel32 90
        const int64_t patchDisp =
            static_cast<int64_t>(caveAddr) -
            static_cast<int64_t>(ctorAddr + 5);
        if (!FitsRel32(patchDisp))
        {
            Log("cSystem:Ctor patch jump out of range (cave 0x%p)",
                reinterpret_cast<void*>(caveAddr));
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }
        int32_t patchDisp32 = static_cast<int32_t>(patchDisp);

        uint8_t jmpPatch[kPatchLength] = { 0xE9, 0, 0, 0, 0, 0x90 };
        std::memcpy(&jmpPatch[1], &patchDisp32, 4);

        DWORD oldProtect = 0;
        if (!VirtualProtect(
                reinterpret_cast<void*>(ctorAddr),
                kPatchLength,
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            Log("cSystem:Ctor VirtualProtect failed");
            VirtualFree(reinterpret_cast<void*>(caveAddr), 0, MEM_RELEASE);
            return false;
        }

        std::memcpy(reinterpret_cast<void*>(ctorAddr), jmpPatch, kPatchLength);
        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(ctorAddr),
            kPatchLength);

        DWORD ignoredProtect = 0;
        VirtualProtect(
            reinterpret_cast<void*>(ctorAddr),
            kPatchLength,
            oldProtect,
            &ignoredProtect);

        g_cSystemCtorAddr = ctorAddr;
        g_cSystemCtorCave = caveAddr;
        Log("cSystem:Ctor hooked, cave=0x%p", reinterpret_cast<void*>(caveAddr));
        return true;
    }

    bool TryInstallHookSeh()
    {
        __try
        {
            return InstallCSystemCtorHook();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    // ---------------------------------------------------------
    // 查找 sVolumeRenderer
    // ---------------------------------------------------------
    void DumpSingletons()
    {
        const size_t count = g_singletonCount.load(std::memory_order_acquire);
        const size_t limit = count < 100 ? count : 100;
        Log("dumping %zu singletons (showing up to %zu)", count, limit);
        for (size_t i = 0; i < limit; i++)
        {
            void* inst = g_singletons[i];
            if (!inst) continue;
            void* dti = GetDtiSafe(inst);
            const char* name = dti ? ReadDtiNameSafe(dti) : nullptr;
            Log("  [%zu] inst=0x%p dti=0x%p name=%s",
                i, inst, dti, name ? name : "?");
        }
    }

    bool TryFindVolumeRenderer()
    {
        const size_t count = g_singletonCount.load(std::memory_order_acquire);
        for (size_t i = 0; i < count; i++)
        {
            void* inst = g_singletons[i];
            if (!inst) continue;
            void* dti = GetDtiSafe(inst);
            if (!dti) continue;
            const char* name = ReadDtiNameSafe(dti);
            if (name && std::strcmp(name, "sVolumeRenderer") == 0)
            {
                g_volumeRenderer.store(inst, std::memory_order_release);
                Log("found sVolumeRenderer at 0x%p (index %zu)", inst, i);
                return true;
            }
        }
        Log("sVolumeRenderer not found among %zu singletons", count);
        return false;
    }

    // ---------------------------------------------------------
    // 配置
    // ---------------------------------------------------------
    struct Settings
    {
        int volumeRendering = -1;          // -1 = 不修改, 0 = 强制关闭, 1 = 强制开启
        uintptr_t volumeRendererAddress = 0; // 手动兜底
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

    uintptr_t ReadUIntPtr(const wchar_t* section, const wchar_t* key, uintptr_t def, const wchar_t* file)
    {
        wchar_t buf[64] = {};
        GetPrivateProfileStringW(section, key, L"", buf, _countof(buf), file);
        if (buf[0] == 0) return def;
        wchar_t* end = nullptr;
        unsigned long long v = wcstoull(buf, &end, 0); // 0 自动识别 0x 前缀
        return end == buf ? def : static_cast<uintptr_t>(v);
    }

    Settings LoadSettings(const std::wstring& path)
    {
        Settings s;
        s.volumeRendering = ReadInt(L"Settings", L"VolumeRendering", -1, path.c_str());
        s.volumeRendererAddress = ReadUIntPtr(L"Settings", L"VolumeRendererAddress", 0, path.c_str());
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

    void ApplyVolumeRendering(const Settings& s)
    {
        void* vr = g_volumeRenderer.load(std::memory_order_acquire);

        if (!vr && s.volumeRendererAddress)
        {
            vr = reinterpret_cast<void*>(s.volumeRendererAddress);
            g_volumeRenderer.store(vr, std::memory_order_release);
            Log("using manual VolumeRenderer address 0x%p",
                reinterpret_cast<void*>(s.volumeRendererAddress));
        }

        if (!vr) return;
        if (s.volumeRendering < 0) return;

        const bool enabled = (s.volumeRendering != 0);
        const uintptr_t addr = reinterpret_cast<uintptr_t>(vr) + kVolumeRendererEnabledOffset;

        if (!TryWriteBool(addr, enabled))
        {
            Log("failed to write volume renderer at 0x%p, will retry",
                reinterpret_cast<void*>(addr));
            g_volumeRenderer.store(nullptr, std::memory_order_release);
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
            "; Primary Shadow Tweak (Volume Rendering)\r\n"
            "\r\n"
            "[Settings]\r\n"
            "; -1 = 不修改（游戏内设置生效）\r\n"
            ";  0 = 强制关闭体积雾（包括瘴气谷）\r\n"
            ";  1 = 强制开启\r\n"
            "VolumeRendering=-1\r\n"
            "\r\n"
            "; 兜底：如果自动找不到 sVolumeRenderer，可以在这里手填对象地址（十六进制，0x 开头）。\r\n"
            "; 留 0 表示自动查找。\r\n"
            "VolumeRendererAddress=0\r\n",
            f);
        fclose(f);
    }

    // ---------------------------------------------------------
    // 主流程
    // ---------------------------------------------------------
    void Worker(HMODULE module)
    {
        wchar_t buf[MAX_PATH] = {};
        GetModuleFileNameW(module, buf, MAX_PATH);
        std::filesystem::path dllPath(buf);
        std::filesystem::path dir = dllPath.parent_path();
        std::wstring stem = dllPath.stem().wstring();

        g_iniPath = (dir / (stem + L".ini")).wstring();
        g_logPath = (dir / (stem + L".log")).wstring();

        _wfopen_s(&g_logFile, g_logPath.c_str(), L"w");
        Log("PrimaryShadow (Volume) loaded from %ls", dllPath.c_str());

        CreateDefaultIni(g_iniPath);

        Settings settings = LoadSettings(g_iniPath);
        g_iniWriteTime = GetFileWriteTime(g_iniPath);
        Log("initial: VolumeRendering=%d, VolumeRendererAddress=0x%p",
            settings.volumeRendering,
            reinterpret_cast<void*>(settings.volumeRendererAddress));

        Log("waiting 300ms for game init...");
        Sleep(300);

        constexpr int kMaxHookAttempts = 60;
        constexpr DWORD kHookRetryInterval = 300;
        bool hookDone = false;
        for (int i = 0; i < kMaxHookAttempts && !hookDone; ++i)
        {
            if (TryInstallHookSeh())
            {
                hookDone = true;
                break;
            }
            if (i + 1 < kMaxHookAttempts)
                Sleep(kHookRetryInterval);
        }

        if (!hookDone)
        {
            Log("failed to install cSystem::Ctor hook after %d attempts", kMaxHookAttempts);
            g_started.store(false, std::memory_order_release);
            return;
        }

        // 等所有单例构造完成
        Sleep(10000);
        Log("recorded %zu singletons so far", g_singletonCount.load(std::memory_order_acquire));

        // 查找 sVolumeRenderer
        constexpr int kMaxFindAttempts = 30;
        constexpr DWORD kFindRetryInterval = 2000;
        bool found = false;
        for (int i = 0; i < kMaxFindAttempts && !found; ++i)
        {
            if (TryFindVolumeRenderer())
            {
                found = true;
                break;
            }
            if (i + 1 < kMaxFindAttempts)
                Sleep(kFindRetryInterval);
        }

        if (!found)
        {
            Log("sVolumeRenderer not found, dumping singletons for diagnosis");
            DumpSingletons();
            Log("volume rendering patch inactive; hook stays installed");
        }

        // 主循环
        while (g_started.load(std::memory_order_acquire))
        {
            Sleep(10);

            if (!g_started.load(std::memory_order_acquire))
                break;

            // 如果还没找到 sVolumeRenderer，定期重试
            if (!g_volumeRenderer.load(std::memory_order_acquire))
            {
                TryFindVolumeRenderer();
                continue;
            }

            // 应用设置
            ApplyVolumeRendering(settings);

            // INI 热更新（每秒检查一次）
            static int tick = 0;
            if (++tick >= 100)
            {
                tick = 0;
                FILETIME ft = GetFileWriteTime(g_iniPath);
                if (CompareFileTime(&ft, &g_iniWriteTime) != 0)
                {
                    g_iniWriteTime = ft;
                    Settings updated = LoadSettings(g_iniPath);
                    if (updated.volumeRendering != settings.volumeRendering ||
                        updated.volumeRendererAddress != settings.volumeRendererAddress)
                    {
                        settings = updated;
                        if (settings.volumeRendererAddress)
                            g_volumeRenderer.store(
                                reinterpret_cast<void*>(settings.volumeRendererAddress),
                                std::memory_order_release);
                        Log("reloaded: VolumeRendering=%d, VolumeRendererAddress=0x%p",
                            settings.volumeRendering,
                            reinterpret_cast<void*>(settings.volumeRendererAddress));
                    }
                }
            }
        }

        if (g_logFile)
        {
            fclose(g_logFile);
            g_logFile = nullptr;
        }
    }
} // namespace

__declspec(dllexport) bool Load()
{
    bool expected = false;
    if (!g_started.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
    {
        return true;
    }

    HMODULE module = g_hModule;
    if (!module)
    {
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
