#include <windows.h>
#include <vector>
#include <cstdint>

namespace {
    // AOB 扫描器
    uintptr_t ScanPattern(const char* moduleName, const std::vector<int>& pattern) {
        uintptr_t moduleBase = (uintptr_t)GetModuleHandleA(moduleName);
        if (!moduleBase) return 0;

        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(moduleBase + dosHeader->e_lfanew);
        uintptr_t sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

        uint8_t* scanStart = (uint8_t*)moduleBase;
        uint8_t* scanEnd = scanStart + sizeOfImage;

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

    void SetupHook() {
        // 一解/二解扣瓶的特征码
        std::vector<int> pattern = { 0x89, 0x8B, 0x74, 0x23, 0x00, 0x00, 0x72 };
        uintptr_t scanAddr = ScanPattern("MonsterHunterWorld.exe", pattern);

        if (!scanAddr) {
            // 如果找不到特征码，说明游戏更新了或者没加载完
            return; 
        }

        // 1. 申请内存（代码洞穴）
        uintptr_t caveAddr = (uintptr_t)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!caveAddr) return;

        // 2. 手写机器码 (对应我们 CE 里测试成功的汇编逻辑)
        uint8_t code[] = {
            // movss xmm1, [rbx+2470]  (读取电锯计时器)
            0xF3, 0x0F, 0x10, 0x8B, 0x70, 0x24, 0x00, 0x00,
            // xorps xmm2, xmm2        (清零 xmm2)
            0x0F, 0x57, 0xD2,
            // comiss xmm1, xmm2       (比较)
            0x0F, 0x2F, 0xCA,
            // ja skip_consume (+6)    (如果计时器 > 0，跳过扣瓶)
            0x77, 0x06,
            // 原扣瓶指令: mov [rbx+2374], ecx
            0x89, 0x8B, 0x74, 0x23, 0x00, 0x00,
            // skip_consume:
            // 恢复标志位: comiss xmm0, [rbx+2470]
            0x0F, 0x2F, 0x83, 0x70, 0x24, 0x00, 0x00,
            // jmp returnAddr
            0xE9, 0x00, 0x00, 0x00, 0x00
        };

        // 计算跳回原程序的偏移量 (原程序覆盖了 6 个字节)
        uintptr_t returnAddr = scanAddr + 6;
        uintptr_t jmpAddr = caveAddr + sizeof(code) - 5; 
        *(int32_t*)&code[sizeof(code) - 4] = (int32_t)(returnAddr - (jmpAddr + 5));

        // 写入代码
        memcpy((void*)caveAddr, code, sizeof(code));

        // 3. 修改原程序指令（前 6 字节覆盖为 jmp caveAddr + nop）
        uint8_t jmpPatch[6] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90 };
        *(int32_t*)&jmpPatch[1] = (int32_t)(caveAddr - (scanAddr + 5));

        DWORD oldProtect;
        VirtualProtect((LPVOID)scanAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((void*)scanAddr, jmpPatch, 6);
        VirtualProtect((LPVOID)scanAddr, 6, oldProtect, &oldProtect);

        FlushInstructionCache(GetCurrentProcess(), (LPVOID)scanAddr, 6);
    }
}

// Stracker's Loader 要求的导出函数
extern "C" __declspec(dllexport) bool Load() {
    // 开线程延迟执行，确保游戏内存已经加载完毕
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        Sleep(5000); 
        SetupHook();
        return 0;
    }, nullptr, 0, nullptr);
    return true;
}

// 标准的 DllMain
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}
