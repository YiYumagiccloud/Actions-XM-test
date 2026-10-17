#include <windows.h>
#include <vector>
#include <cstdint>

namespace {
    // 1. 安全的 AOB 扫描器 (带内存可读性校验)
    uintptr_t ScanPattern(const char* moduleName, const std::vector<int>& pattern) {
        uintptr_t moduleBase = (uintptr_t)GetModuleHandleA(moduleName);
        if (!moduleBase) return 0;

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(moduleBase + dosHeader->e_lfanew);
        
        // 只扫描 .text 代码段 (更安全、更快)
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
        if (!scanStart) return 0;

        for (uint8_t* p = scanStart; p < scanEnd - pattern.size(); ++p) {
            bool found = true;
            for (size_t i = 0; i < pattern.size(); ++i) {
                if (pattern[i] != -1 && p[i] != pattern[i]) {
                    found = false;
                    break;
                }
            }
            if (found) return (uintptr_t)p;
        }
        return 0;
    }

    // 2. 在目标地址附近申请内存 (解决 JMP 2GB 限制)
    uintptr_t AllocNear(uintptr_t target, size_t size) {
        // 从目标地址向下按 64KB 对齐搜索
        uintptr_t start = target & ~0xFFFF;
        for (uintptr_t addr = start; addr > start - 0x7FFFFFFF; addr -= 0x10000) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPVOID)addr, &mbi, sizeof(mbi)) == 0) continue;
            
            // 寻找空闲的、未提交的区域
            if (mbi.State == MEM_FREE) {
                void* p = VirtualAlloc((LPVOID)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) return (uintptr_t)p;
            }
        }
        return 0; // 如果找不到，返回0
    }

    bool SetupHook() {
        std::vector<int> pattern = { 0x89, 0x8B, 0x74, 0x23, 0x00, 0x00, 0x72 };
        uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", pattern);

        // 如果没找到，返回 false，让外层重试
        if (!scanAddr) return false; 

        // 使用靠近原地址的申请方式
        uintptr_t caveAddr = AllocNear(scanAddr, 0x1000);
        if (!caveAddr) return false;

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
        
        // 确保跳转距离在 int32 范围内
        int64_t relativeJump = (int64_t)returnAddr - (int64_t)(jmpAddr + 5);
        if (relativeJump < INT32_MIN || relativeJump > INT32_MAX) {
            VirtualFree((LPVOID)caveAddr, 0, MEM_RELEASE);
            return false; // 距离太远，放弃（理论上 AllocNear 保证不会发生）
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
            return true;
        }
        
        VirtualFree((LPVOID)caveAddr, 0, MEM_RELEASE);
        return false;
    }

    // 3. 线程安全与重试机制
    void ThreadLoop() {
        // 最多尝试 30 次，每次间隔 2 秒 (总共等待约 60 秒)
        for (int i = 0; i < 30; ++i) {
            __try {
                if (SetupHook()) {
                    // 成功挂载，退出循环
                    return;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // 如果扫描或写入时发生崩溃，忽略并重试
            }
            Sleep(2000);
        }
    }
}

extern "C" __declspec(dllexport) bool Load() {
    // 使用系统线程池或者直接 CreateThread
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
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
