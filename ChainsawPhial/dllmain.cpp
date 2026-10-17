#include <windows.h>
#include <cstdio>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // 故意写一个绝对路径 C 盘根目录，排除路径干扰
        FILE* f;
        fopen_s(&f, "C:\\Chainsaw_DllMain.txt", "w");
        if (f) {
            fprintf(f, "DllMain has been loaded by the system!\n");
            fclose(f);
        }
    }
    return TRUE;
}

// 强制导出 Load
extern "C" __declspec(dllexport) bool Load() {
    FILE* f;
    fopen_s(&f, "C:\\Chainsaw_Load.txt", "w");
    if (f) {
        fprintf(f, "Load function has been called by Stracker!\n");
        fclose(f);
    }
    return true;
}
