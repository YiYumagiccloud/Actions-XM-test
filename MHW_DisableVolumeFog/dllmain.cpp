#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>

namespace
{
    std::atomic_bool g_started{ false };
    HMODULE g_hModule = nullptr;

    // cSystem:Ctor 特征码与偏移（定位函数入口）
    const std::vector<int> kCSystemCtorPattern = {
        0x48, 0x83, 0xC1, 0x08, 0xFF, 0x15, -1, -1, -1, -1,
        0x48, 0x8B, 0xC3, 0xC6, 0x43, 0x30, 0x01,
        0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
    };
    constexpr int kCSystemCtorOffset = -19;

    // 覆盖 6 字节: 40 53 48 83 EC XX
    constexpr size_t kPatchLength = 6;
    constexpr size_t kCaveSize = 0x100;

    // sVolumeRenderer + 0x38 是 bool (Volume Rendering Enabled)
    constexpr uintptr_t kVolumeRendererEnabledOffset = 0x38;

    // 单例记录池
    constexpr size_t kMaxSingletons = 8192;
    void* g_singletons[kMaxSingletons] = {};
    std::atomic<size_t> g_singletonCount{ 0 };

    std::atomic<void*> g_volumeRenderer{ nullptr };

    // 供调试器查看的极简日志（不写文件）
    void Log(const char* msg)
    {
        OutputDebugStringA(msg);
    }

    // ---------------------------------------------------------
    // 特征码扫描
    // ---------------------------------------------------------
    uintptr_t ScanPattern(const char* moduleName, const std::vector<int>& pattern)
    {
        if (pattern.empty()) return 0;
        HMODULE module = GetModuleHandleA(moduleName);
        if (!module) return 0;

        const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module);
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) return 0;

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + (uintptr_t)dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

        const auto* sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            const auto& section = sections[i];
            if (std::memcmp(section.Name, ".text", 5) != 0) continue;

            const size_t textSize = (size_t)section.Misc.VirtualSize;
            if (textSize < pattern.size()) return 0;

            const uint8_t* text = reinterpret_cast<const uint8_t*>(moduleBase + section.VirtualAddress);
            const uint8_t* textEnd = text + textSize - pattern.size() + 1;
            const uint8_t firstByte = (uint8_t)pattern[0];

            for (const uint8_t* q = text; q < textEnd;)
            {
                q = (const uint8_t*)std::memchr(q, firstByte, (size_t)(textEnd - q));
                if (!q) break;

                bool found = true;
                for (size_t j = 1; j < pattern.size(); ++j)
                {
                    if (pattern[j] != -1 && q[j] != (uint8_t)pattern[j])
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

    // ---------------------------------------------------------
    // Code cave 分配
    // ---------------------------------------------------------
    uintptr_t AllocNear(uintptr_t target, size_t size)
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        const uintptr_t granularity = si.dwAllocationGranularity;
        const uintptr_t searchRange = 0x10000000ULL;
        const uintptr_t lowerBound = target > searchRange ? target - searchRange : granularity;
        const uintptr_t upperBound = target + searchRange;

        uintptr_t addr = target & ~(granularity - 1);
        while (addr > lowerBound)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
            uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
            if (mbi.State == MEM_FREE)
            {
                uintptr_t regionEnd = regionBase + mbi.RegionSize;
                uintptr_t allocAddr = (regionEnd - size) & ~(granularity - 1);
                while (allocAddr >= regionBase && allocAddr >= lowerBound)
                {
                    void* memory = VirtualAlloc((void*)allocAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (memory) return (uintptr_t)memory;
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
            if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
            uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
            uintptr_t regionEnd = regionBase + mbi.RegionSize;
            if (mbi.State == MEM_FREE)
            {
                uintptr_t allocAddr = regionBase < addr ? addr : regionBase;
                allocAddr = (allocAddr + granularity - 1) & ~(granularity - 1);
                while (allocAddr + size <= regionEnd && allocAddr < upperBound)
                {
                    void* memory = VirtualAlloc((void*)allocAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (memory) return (uintptr_t)memory;
                    allocAddr += granularity;
                }
            }
            if (regionEnd < upperBound && regionEnd > addr) addr = regionEnd;
            else break;
        }
        return 0;
    }

    // ---------------------------------------------------------
    // Hook 回调与安全读写
    // ---------------------------------------------------------
    extern "C" void RecordSingleton(void* thisPtr)
    {
        const size_t idx = g_singletonCount.fetch_add(1, std::memory_order_acq_rel);
        if (idx < kMaxSingletons)
        {
            g_singletons[idx] = thisPtr;
        }
    }

    bool TryReadU64(uintptr_t addr, uint64_t& out)
    {
        __try { out = *reinterpret_cast<uint64_t*>(addr); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    bool IsReadableString(uintptr_t addr)
    {
        __try
        {
            const char* p = (const char*)addr;
            char c = p[0];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_')) return false;
            for (int i = 1; i < 128; i++)
            {
                char ch = p[i];
                if (ch == 0) return true;
                if (ch < 0x20 || ch > 0x7E) return false;
            }
            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
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
        __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    }

    bool TryWriteBool(uintptr_t addr, bool value)
    {
        __try { *reinterpret_cast<bool*>(addr) = value; return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    // 暴破所有可能的指针，因为不同版本的 DTI 布局可能略有差异
    const char* ReadDtiNameSafe(void* dti)
    {
        const uintptr_t base = (uintptr_t)dti;
        const uintptr_t candidates[] = { 0x20, 0x28, 0x08, 0x10, 0x18 };
        for (size_t i = 0; i < 5; i++)
        {
            uint64_t namePtr = 0;
            if (!TryReadU64(base + candidates[i], namePtr)) continue;
            if (namePtr < 0x10000) continue;

            if (IsReadableString((uintptr_t)namePtr))
                return (const char*)namePtr;

            if (namePtr > 0x140000000 && namePtr < 0x150000000)
            {
                __try {
                    const char* p = (const char*)namePtr;
                    if ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
                        return p;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
        return nullptr;
    }

    // ---------------------------------------------------------
    // 安装 cSystem::Ctor Hook
    // ---------------------------------------------------------
    bool InstallCSystemCtorHook()
    {
        HMODULE module = GetModuleHandleA("MonsterHunterWorld.exe");
        if (!module) return false;

        const uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", kCSystemCtorPattern);
        if (!scanAddr) return false;

        const uintptr_t ctorAddr = scanAddr + kCSystemCtorOffset;
        const uint8_t* entry = (const uint8_t*)ctorAddr;
        if (entry[0] != 0x40 || entry[1] != 0x53 || entry[2] != 0x48 || entry[3] != 0x83 || entry[4] != 0xEC)
            return false;

        const uint8_t stackSub = entry[5];
        const uintptr_t returnAddr = ctorAddr + kPatchLength;
        const uintptr_t caveAddr = AllocNear(ctorAddr, kCaveSize);
        if (!caveAddr) return false;

        uint8_t code[0x80] = {};
        size_t p = 0;

        // 还原被覆盖的代码：push rbx; sub rsp, XX
        code[p++] = 0x40; code[p++] = 0x53;
        code[p++] = 0x48; code[p++] = 0x83; code[p++] = 0xEC; code[p++] = stackSub;

        // 保存 volatile 寄存器
        code[p++] = 0x50; code[p++] = 0x51; code[p++] = 0x52;
        code[p++] = 0x41; code[p++] = 0x50; code[p++] = 0x41; code[p++] = 0x51;
        code[p++] = 0x41; code[p++] = 0x52; code[p++] = 0x41; code[p++] = 0x53;

        // 调用 RecordSingleton
        code[p++] = 0x48; code[p++] = 0xB8;
        const uint64_t fnAddr = (uint64_t)&RecordSingleton;
        std::memcpy(&code[p], &fnAddr, 8); p += 8;
        code[p++] = 0xFF; code[p++] = 0xD0;

        // 恢复 volatile 寄存器
        code[p++] = 0x41; code[p++] = 0x5B; code[p++] = 0x41; code[p++] = 0x5A;
        code[p++] = 0x41; code[p++] = 0x59; code[p++] = 0x41; code[p++] = 0x58;
        code[p++] = 0x5A; code[p++] = 0x59; code[p++] = 0x58;

        // 跳回原函数
        const size_t jmp_pos = p;
        code[p++] = 0xE9;
        const size_t jmp_disp_pos = p;
        p += 4;

        int64_t backDisp = (int64_t)returnAddr - (int64_t)(caveAddr + jmp_pos + 5);
        int32_t backDisp32 = (int32_t)backDisp;
        std::memcpy(&code[jmp_disp_pos], &backDisp32, 4);

        std::memcpy((void*)caveAddr, code, p);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)caveAddr, p);

        // 写入 JMP 指令到函数入口
        int64_t patchDisp = (int64_t)caveAddr - (int64_t)(ctorAddr + 5);
        int32_t patchDisp32 = (int32_t)patchDisp;

        uint8_t jmpPatch[kPatchLength] = { 0xE9, 0, 0, 0, 0, 0x90 };
        std::memcpy(&jmpPatch[1], &patchDisp32, 4);

        DWORD oldProtect = 0;
        if (!VirtualProtect((void*)ctorAddr, kPatchLength, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;

        std::memcpy((void*)ctorAddr, jmpPatch, kPatchLength);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)ctorAddr, kPatchLength);
        VirtualProtect((void*)ctorAddr, kPatchLength, oldProtect, &oldProtect);

        return true;
    }

    bool TryInstallHookSeh()
    {
        __try { return InstallCSystemCtorHook(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    // ---------------------------------------------------------
    // 查找并强制关闭体积雾
    // ---------------------------------------------------------
    bool TryFindAndDisableVolumeRenderer()
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
                // 找到了就直接写入 0 关闭
                TryWriteBool((uintptr_t)inst + kVolumeRendererEnabledOffset, false);
                return true;
            }
        }
        return false;
    }

    // ---------------------------------------------------------
    // 主线程
    // ---------------------------------------------------------
    void Worker(HMODULE module)
    {
        Log("DisableVolumeFog: Worker started.\n");

        // 立即开始尝试注入
        bool hookInstalled = false;
        while (g_started.load() && !hookInstalled) {
            if (TryInstallHookSeh()) {
                hookInstalled = true;
                Log("DisableVolumeFog: cSystem::Ctor hooked.\n");
                break;
            }
            Sleep(10);
        }

        if (!hookInstalled) {
            Log("DisableVolumeFog: Failed to hook, aborting.\n");
            return;
        }

        // 等待游戏加载单例（给主菜单和初次加载留出时间）
        Sleep(8000);

        // 尝试查找并关闭
        bool found = false;
        for (int i = 0; i < 30 && !found && g_started.load(); ++i) {
            if (TryFindAndDisableVolumeRenderer()) {
                found = true;
                Log("DisableVolumeFog: Found sVolumeRenderer, forced OFF.\n");
            } else {
                Sleep(2000);
            }
        }

        // 持续监控并写入 0
        while (g_started.load())
        {
            Sleep(10);
            void* vr = g_volumeRenderer.load(std::memory_order_acquire);
            
            if (!vr) {
                // 如果还没找到（例如一直在主菜单没进图），每 5 秒找一次
                static DWORD lastRetry = 0;
                DWORD now = GetTickCount();
                if (now - lastRetry >= 5000) {
                    lastRetry = now;
                    if (TryFindAndDisableVolumeRenderer()) {
                        Log("DisableVolumeFog: Found sVolumeRenderer on retry.\n");
                    }
                }
                continue;
            }

            // 强制将 +0x38 处的 bool 写为 false，防止游戏内部重置
            TryWriteBool((uintptr_t)vr + kVolumeRendererEnabledOffset, false);
        }
    }
}

// Stracker's Loader 导出入口
__declspec(dllexport) bool Load()
{
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) 
        return true;

    HMODULE module = g_hModule;
    if (!module) {
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)&Load, &module);
    }

    HANDLE thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        Worker((HMODULE)param);
        return 0;
    }, module, 0, nullptr);

    if (!thread) {
        g_started.store(false, std::memory_order_release);
        return false;
    }

    CloseHandle(thread);
    return true;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        g_hModule = module;
        Load();
    }
    return TRUE;
}
