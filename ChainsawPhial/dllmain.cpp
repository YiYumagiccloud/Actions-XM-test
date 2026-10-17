#include <windows.h>
#include "loader.h" // 引入 Stracker's Loader 的头文件

// 使用 loader 命名空间，方便调用 LOG 宏
using namespace loader;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // 当 DLL 被加载到游戏进程时，这里的代码会被执行
        LOG(INFO) << "我的第一个 Stracker 插件已加载！";
        // 建议在这里创建一个新线程来执行主要逻辑，避免阻塞游戏主线程
        // CreateThread(nullptr, 0, MyModThread, nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        LOG(INFO) << "我的 Stracker 插件已卸载。";
        break;
    }
    return TRUE;
}
