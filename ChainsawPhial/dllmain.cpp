#include <windows.h>
#include <vector>
#include <cstdint>
#include <cstdio>

namespace {
    FILE* g_logFile = nullptr;

    // 简单的日志输出函数
    void Log(const char* format, ...) {
        if (!g_logFile) return;
        va_list args;
        va_start(args, format);
        vfprintf(g_logFile, format, args);
        va_end(args);
        fflush(g_logFile); // 立即写入硬盘，防崩溃丢失
    }

    void InitLog() {
        // 将日志保存在 nativePC/plugins 目录下
        fopen_s(&g_logFile, "nativePC\\plugins\\ChainsawPhial.log", "w");
        if (g_logFile) {
            Log("=== Chainsaw Phial Mod Loaded ===\n");
        }
    }

    // 安全的 AOB 扫描器
    uintptr_t ScanPattern(const char* moduleName, const std::vector<int>& pattern) {
        uintptr_t moduleBase = (uintptr_t)GetModuleHandleA(moduleName);
        if (!moduleBase) {
            Log("[Error] Module %s not found!\n", moduleName);
            return 0;
        }

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(moduleBase + dosHeader->e_lfanew);
        
        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
        uint8_t* scanStart = nullptr;
        uint8_t* scanEnd = nullptr;
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            if (memcmp(section[i].Name, ".text", 5) == 0) {
                scanStart = (uint8_t*)(moduleBase + section[i].VirtualAddress);
                scanEnd = scanStart + section[i].Misc.VirtualSize;
                break;
            }
        }
        if (!scanStart) {
            Log("[Error] .text section not found!\n");
            return 0;
        }

        // 修复了数组越界漏洞 (<= 而不是 <)
        for (uint8_t* p = scanStart; p <= scanEnd - pattern.size(); ++p) {
            bool found = true;
            for (size_t i = 0; i < pattern.size(); ++i) {
                if (pattern[i] != -1 && p[i] != pattern[i]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                Log("[Success] Pattern found at: %p\n", p);
                return (uintptr_t)p;
            }
        }
        return 0;
    }

    // 在目标地址附近分配内存
    uintptr_t AllocNear(uintptr_t target, size_t size) {
        uintptr_t start = target & ~0xFFFF;
        for (uintptr_t addr = start; addr > start - 0x7FFF0000; addr -= 0x10000) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPVOID)addr, &mbi, sizeof(mbi)) == 0) continue;
            
            if (mbi.State == MEM_FREE) {
                void* p = VirtualAlloc((LPVOID)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) return (uintptr_t)p;
            }
        }
        // 如果附近找不到，尝试让系统随机分配（虽然极大概率超过2GB，但万一呢）
        void* p = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        return (uintptr_t)p;
    }

    bool SetupHook() {
        std::vector<int> pattern = { 0x89, 0x8B, 0x74, 0x23, 0x00, 0x00, 0x72 };
        uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", pattern);

        if (!scanAddr) return false; 

        uintptr_t caveAddr = AllocNear(scanAddr, 0x1000);
        if (!caveAddr) {
            Log("[Error] Failed to allocate memory cave!\n");
            return false;
        }
        Log("[Success] Cave allocated at: %p\n", (void*)caveAddr);

        uint8_t code[] = {
            0xF3, 0x0F, 0x10, 0x8B, 0x70, 0x24, 0x00, 0x00, // movss xmm1, [rbx+2470]
            0x0F, 0x57, 0xD2,                               // xorps xmm2, xmm2
            0x0F, 0x2F, 0xCA,                               // comiss xmm1, xmm2
            0x77, 0x06,                                     // ja skip_consume
            0x89, 0x8B, 0x74, 0x23, 0x00, 0x00,             // mov [rbx+2374], ecx
            0x0F, 0x2F, 0x83, 0x70, 0x24, 0x00, 0x00,       // comiss xmm0, [rbx+2470]
            0xE9, 0x00, 0x00, 0x00, 0x00                    // jmp returnAddr
        };

        uintptr_t returnAddr = scanAddr + 6;
        uintptr_t jmpAddr = caveAddr + sizeof(code) - 5; 
        
        int64_t relativeJump = (int64_t)returnAddr - (int64_t)(jmpAddr + 5);
        if (relativeJump < INT32_MIN || relativeJump > INT32_MAX) {
            Log("[Error] Jump distance too far! (Over 2GB)\n");
            VirtualFree((LPVOID)caveAddr, 0, MEM_RELEASE);
            return false;
        }
        *(int32_t*)&code[sizeof(code) - 4] = (int32_t)relativeJump;

        memcpy((void*)caveAddr, code, sizeof(code));

        uint8_t jmpPatch[6] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90 };
        int64_t patchJump = (int64_t)caveAddr - (int64_t)(scanAddr + 5);
        *(int32_t*)&jmpPatch[1] = (int32_t)patchJump;

        DWORD oldProtect;
        if (VirtualProtect((LPVOID)scanAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy((void*)scanAddr, jmpPatch, 6);
            VirtualProtect((LPVOID)scanAddr, 6, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), (LPVOID)scanAddr, 6);
            Log("[Success] Hook applied successfully!\n");
            return true;
        } else {
            Log("[Error] VirtualProtect failed! Error: %lu\n", GetLastError());
        }
        
        VirtualFree((LPVOID)caveAddr, 0, MEM_RELEASE);
        return false;
    }

    void ThreadLoop() {
        // 如果日志打开失败，不要阻塞游戏
        if (!g_logFile) return;

        for (int i = 0; i < 30; ++i) {
            Log("[Info] Attempt %d: Scanning memory...\n", i + 1);
            __try {
                if (SetupHook()) {
                    return;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Log("[Error] Exception caught during SetupHook!\n");
            }
            Sleep(2000);
        }
        Log("[Error] Timeout. Could not find AOB pattern.\n");
    }
}

extern "C" __declspec(dllexport) bool Load() {
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        InitLog(); // 初始化日志
        // 等游戏稍微加载一会再开始扫描
        Sleep(5000);
        ThreadLoop();
        return 0;
    }, nullptr, 0, nullptr);
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}
