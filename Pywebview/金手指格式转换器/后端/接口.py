# -*- coding: utf-8 -*-
"""前后端之间唯一的通道：暴露给 JS 的函数都写在这里。

前端这样调用（异步，返回 Promise）：
    const 结果 = await window.pywebview.api.转换文本(文本);

三条规矩，保证「后端出错不会把整个应用带走」：

  1. 每个方法都套上 @安全 装饰器。里面出任何异常都会被接住，
     统一变成 {"成功": false, "错误": "..."} 返回给前端，前端弹个提示就完了。
  2. 返回值必须是能 JSON 序列化的东西（str / int / float / bool / list / dict）。
  3. 方法名别以下划线开头 —— pywebview 只暴露公开方法。
"""

from __future__ import annotations

import ctypes
import functools
import json
import os
import sys
import traceback
from typing import Any, Callable

from . import 环境, 转换


# ---------------------------------------------------------------------------
# 统一的异常兜底
# ---------------------------------------------------------------------------

def 安全(方法: Callable) -> Callable:
    """任何异常都变成一句人话返回给前端，程序本体继续活着。"""

    @functools.wraps(方法)
    def 包装(self: "接口", *参数, **关键字) -> dict:
        try:
            结果 = 方法(self, *参数, **关键字)
            if isinstance(结果, dict):
                结果.setdefault("成功", True)
                return 结果
            return {"成功": True, "结果": 结果}
        except Exception as 错误:  # noqa: BLE001  这里就是要兜住所有异常
            print(f"[接口出错] {方法.__name__}: {type(错误).__name__}: {错误}")
            print(traceback.format_exc())
            return {"成功": False, "错误": f"{type(错误).__name__}: {错误}"}

    return 包装


# ---------------------------------------------------------------------------
# 剪贴板（Win32 API，比浏览器那套可靠）
# ---------------------------------------------------------------------------

def 写剪贴板(文本: str) -> bool:
    """往剪贴板写文本。非 Windows 返回 False，让前端走浏览器的兜底方案。

    注意：64 位下必须显式声明 restype/argtypes，否则 GlobalAlloc 返回的句柄
    会被截成 32 位，然后就崩了 —— 这是 ctypes 的经典坑。
    """
    if not sys.platform.startswith("win"):
        return False

    from ctypes import wintypes

    用户 = ctypes.windll.user32
    内核 = ctypes.windll.kernel32

    内核.GlobalAlloc.restype = wintypes.HGLOBAL
    内核.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    内核.GlobalLock.restype = wintypes.LPVOID
    内核.GlobalLock.argtypes = [wintypes.HGLOBAL]
    内核.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    用户.SetClipboardData.restype = wintypes.HANDLE
    用户.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    if not 用户.OpenClipboard(None):
        return False
    try:
        用户.EmptyClipboard()
        数据 = 文本.encode("utf-16-le") + b"\x00\x00"
        句柄 = 内核.GlobalAlloc(GMEM_MOVEABLE, len(数据))
        if not 句柄:
            return False
        指针 = 内核.GlobalLock(句柄)
        if not 指针:
            内核.GlobalFree(句柄)
            return False
        try:
            ctypes.memmove(指针, 数据, len(数据))
        finally:
            内核.GlobalUnlock(句柄)

        if not 用户.SetClipboardData(CF_UNICODETEXT, 句柄):
            内核.GlobalFree(句柄)
            return False
        # SetClipboardData 成功之后，内存所有权归系统，不能再自己 free
        return True
    finally:
        用户.CloseClipboard()


# ---------------------------------------------------------------------------
# 暴露给 JS 的接口
# ---------------------------------------------------------------------------

class 接口:
    """一个实例对应一个窗口。主程序创建窗口时通过 js_api 把它挂上去。"""

    def __init__(self) -> None:
        self._窗口: Any = None            # 由主程序在创建窗口后塞进来
        self.前端已就绪 = False

    # -- 内部小工具 --------------------------------------------------------

    def _通知前端(self, 函数名: str, *参数) -> None:
        """从 Python 主动调前端里的 JS 函数（用来推进度）。

        转换是在 pywebview 的工作线程里跑的，所以界面不会被卡住，
        进度可以这样实时推过去。
        注意：前端那个函数必须是**同步**的；如果它返回 Promise，
        evaluate_js 会拿到一堆没完成的东西，反而容易串味。
        """
        if not (self._窗口 and self.前端已就绪):
            return
        参数串 = ", ".join(json.dumps(项, ensure_ascii=False) for 项 in 参数)
        try:
            self._窗口.evaluate_js(f"window.{函数名} && window.{函数名}({参数串})")
        except Exception as 错误:  # 前端没准备好 / 窗口正在关闭，都不该影响流程
            print(f"[提示] 通知前端 {函数名} 失败：{错误}")

    # -- 生命周期 ----------------------------------------------------------

    @安全
    def 初始化(self) -> dict:
        """前端一加载完就调它，拿初始数据（配置、环境信息、示例文本）。"""
        self.前端已就绪 = True
        return {
            "配置": 环境.读配置(),
            "环境": 环境.系统信息(),
            "示例": 转换.取示例(),
            "应用名": 环境.应用名,
            "版本号": 环境.版本号,
        }

    @安全
    def 保存外观(self, 外观: str, 配色: str) -> dict:
        """记住用户选的配色，下次启动窗口底色就能对上，不会先白一下再变黑。"""
        配置 = 环境.读配置()
        配置["外观"] = 外观
        配置["配色"] = 配色
        环境.写配置(配置)
        return {"配置": 配置}

    @安全
    def 取环境信息(self) -> dict:
        return {"环境": 环境.系统信息()}

    # -- 转换 --------------------------------------------------------------

    @安全
    def 转换文本(self, 文本: str) -> dict:
        """核心接口：把输入文本转成输出文本。

        进度通过 evaluate_js 回推给前端的 window.更新进度(百分比, 行数)。
        """
        结果 = 转换.转换(文本, 进度回调=lambda 百分比, 行数: self._通知前端("更新进度", 百分比, 行数))
        self._通知前端("更新进度", 1.0, 结果["行数"])
        return 结果

    # -- 文件 --------------------------------------------------------------

    @安全
    def 打开文件(self) -> dict:
        """弹系统对话框选文件，读进来（带编码探测），把文本交给前端。"""
        import webview

        路径们 = self._窗口.create_file_dialog(
            webview.FileDialog.OPEN,
            allow_multiple=False,
            file_types=("XML 金手指文件 (*.xml)", "文本文件 (*.txt)", "所有文件 (*.*)"),
        )
        if not 路径们:
            return {"取消": True}  # 用户点了取消，不是错误

        路径 = 路径们[0]
        文本, 编码 = 环境.读取文本文件(路径)
        return {
            "文件名": os.path.basename(路径),
            "路径": 路径,
            "文本": 文本,
            "编码": 编码,
            "行数": len(文本.splitlines()),
        }

    @安全
    def 保存文件(self, 文本: str, 建议名: str = "金手指.txt") -> dict:
        import webview

        路径 = self._窗口.create_file_dialog(
            webview.FileDialog.SAVE,
            save_filename=建议名,
            file_types=("文本文件 (*.txt)", "所有文件 (*.*)"),
        )
        if not 路径:
            return {"取消": True}
        目标 = 路径[0] if isinstance(路径, (list, tuple)) else 路径
        环境.写入文本文件(目标, 文本)
        return {"文件名": os.path.basename(目标), "路径": 目标, "字符数": len(文本)}

    # -- 杂项 --------------------------------------------------------------

    @安全
    def 复制到剪贴板(self, 文本: str) -> dict:
        if 写剪贴板(文本):
            return {"字符数": len(文本), "方式": "系统接口"}
        return {"成功": False, "错误": "系统接口写入失败，请让前端用浏览器方案重试", "字符数": len(文本)}

    @安全
    def 打开目录(self, 路径: str = "") -> dict:
        """在文件管理器里打开某个目录（默认打开程序目录）。"""
        目标 = 路径 or 环境.程序根目录()
        if not os.path.isdir(目标):
            目标 = os.path.dirname(目标)
        if sys.platform.startswith("win"):
            os.startfile(目标)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            os.system(f'open "{目标}"')
        else:
            os.system(f'xdg-open "{目标}"')
        return {"目录": 目标}

    @安全
    def 退出程序(self) -> dict:
        if self._窗口:
            self._窗口.destroy()
        return {"已退出": True}
