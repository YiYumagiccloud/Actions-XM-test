# -*- coding: utf-8 -*-
"""环境与路径：所有「找文件、读写配置、起本地服务」的事都集中在这里。

为什么单独一个文件：
  打包（Nuitka / PyInstaller）之后，「程序在哪」和「当前工作目录」是两回事，
  相对路径全都会失效。这类逻辑最容易到处重复写错，集中到一处，别的模块只管调用。
"""

from __future__ import annotations

import functools
import http.server
import json
import os
import platform
import socketserver
import sys
import threading

应用名 = "金手指格式转换器"
版本号 = "1.0.0"

# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------


def 程序根目录(*相对路径: str) -> str:
    """把相对路径解析成绝对路径，兼容源码运行和各种打包方式。

    依次在几个候选根目录里找，谁先找到就用谁：
      1. 打包后的解包目录 / exe 所在目录
      2. 本文件所在目录的上一级（也就是项目根目录）
      3. 启动参数 argv[0] 所在目录
    全找不到就返回第一个候选，让上层去报「文件不存在」，比抛莫名其妙的错好排查。
    """
    目标 = os.path.join(*相对路径) if 相对路径 else ""
    这里 = os.path.dirname(os.path.abspath(__file__))
    项目根 = os.path.dirname(这里)  # 后端/ 的上一级

    候选根: list[str] = []
    if 是否已打包():
        候选根.append(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
        候选根.append(os.path.dirname(os.path.abspath(sys.executable)))
    候选根.append(项目根)
    候选根.append(os.path.dirname(os.path.abspath(sys.argv[0])))

    for 根 in 候选根:
        路径 = os.path.join(根, 目标)
        if os.path.exists(路径):
            return 路径
    return os.path.join(候选根[0], 目标) if 目标 else 候选根[0]


def 是否已打包() -> bool:
    """PyInstaller 会设置 sys.frozen；Nuitka 会往模块里塞一个 __compiled__ 全局名字。"""
    return bool(getattr(sys, "frozen", False)) or "__compiled__" in globals() or "__compiled__" in dir(sys.modules.get("__main__"))


def 前端入口() -> str:
    """返回前端首页的绝对路径。"""
    return 程序根目录("前端", "index.html")


# ---------------------------------------------------------------------------
# 用户配置（记住上次用的配色 / 外观）
# ---------------------------------------------------------------------------

配置文件名 = "配置.json"


def 用户配置目录() -> str:
    """Windows 用 %APPDATA%，其它系统用 ~/.config。

    不要往程序目录里写配置 —— 装到 Program Files 里是没有写权限的。
    """
    if sys.platform.startswith("win"):
        基础 = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        基础 = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    目录 = os.path.join(基础, 应用名)
    os.makedirs(目录, exist_ok=True)
    return 目录


def 读配置() -> dict:
    """读配置，坏了就当空的，绝不因为配置问题起不来。"""
    路径 = os.path.join(用户配置目录(), 配置文件名)
    try:
        with open(路径, "r", encoding="utf-8") as 文件:
            内容 = json.load(文件)
        return 内容 if isinstance(内容, dict) else {}
    except (OSError, ValueError):
        return {}


def 写配置(内容: dict) -> None:
    路径 = os.path.join(用户配置目录(), 配置文件名)
    try:
        with open(路径, "w", encoding="utf-8") as 文件:
            json.dump(内容, 文件, ensure_ascii=False, indent=2)
    except OSError as 错误:
        print(f"[提示] 配置写不进去（不影响使用）：{错误}")


def 浏览器数据目录() -> str:
    """WebView2 自己的缓存/配置目录（private_mode=False 时会往这里写）。"""
    目录 = os.path.join(用户配置目录(), "浏览器数据")
    os.makedirs(目录, exist_ok=True)
    return 目录


def 系统是深色() -> bool:
    """系统当前是不是深色模式。

    只为了在窗口显示之前就把底色定对，免得深色模式启动时先闪一下白。
    """
    if not sys.platform.startswith("win"):
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as 键:
            return winreg.QueryValueEx(键, "AppsUseLightTheme")[0] == 0
    except OSError:
        return False


def 取空闲端口() -> int:
    """向系统要一个当前空闲的端口号。

    为什么必须自己挑端口：pywebview 的内部 http 服务是「前端页面 + JS 接口」的载体，
    如果两个实例用同一个端口（它默认就是 42001），后来的那个会连不上自己的服务，
    页面反而由先启动的进程提供 —— 结果就是「新窗口能用，但 Python 收到的调用全跑到
    旧进程去了」，非常难查。我自己挑一个空闲端口，两边各用各的，永远不串。
    """
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as 套接字:
        套接字.bind(("127.0.0.1", 0))
        return int(套接字.getsockname()[1])


# ---------------------------------------------------------------------------
# 单实例：同一个程序只允许开一个窗口
# ---------------------------------------------------------------------------

_互斥体句柄 = None  # 必须存住，不然句柄被回收，锁就没了


def 抢单实例锁(名字: str | None = None) -> bool:
    """抢到返回 True；已经有实例在跑返回 False。

    Windows 上用命名互斥体（进程退出时系统自动释放，很干净），其它平台先放行。
    """
    if not sys.platform.startswith("win"):
        return True

    global _互斥体句柄
    import ctypes
    from ctypes import wintypes

    内核 = ctypes.WinDLL("kernel32", use_last_error=True)
    内核.CreateMutexW.restype = wintypes.HANDLE
    内核.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]

    句柄 = 内核.CreateMutexW(None, False, f"Local\\{名字 or 应用名}")
    if not 句柄:
        return True  # 创建不出来就别拦着用户

    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        return False
    _互斥体句柄 = 句柄
    return True


def 提示已经在运行() -> None:
    """再点一次图标时给个提示，而不是默默多开一个窗口。"""
    文字 = f"{应用名}已经在运行啦～\n\n看看任务栏，别开两个窗口哦。"
    if sys.platform.startswith("win"):
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, 文字, 应用名, 0x40)  # 0x40 = 信息图标
            return
        except Exception:
            pass
    print(文字.replace("\n", " "))


# ---------------------------------------------------------------------------
# 读写文本文件（编码探测）
# ---------------------------------------------------------------------------

常见编码 = ("utf-8-sig", "utf-8", "gb18030", "big5", "utf-16")


def 读取文本文件(路径: str) -> tuple[str, str]:
    """按几种常见编码依次尝试，返回 (文本, 编码)。

    金手指 XML 有不少是 GBK 存的，直接 encoding='utf-8' 打开就炸，
    多试几种比让程序崩掉友好得多。
    """
    if not os.path.isfile(路径):
        raise FileNotFoundError(f"文件不存在：{路径}")

    for 编码 in 常见编码:
        try:
            with open(路径, "r", encoding=编码) as 文件:
                return 文件.read(), 编码
        except UnicodeDecodeError:
            continue
        except OSError as 错误:
            raise OSError(f"读不了这个文件：{错误}") from 错误
    raise ValueError("换了几种编码都读不出来，这个文件可能不是纯文本。")


def 写入文本文件(路径: str, 文本: str) -> None:
    with open(路径, "w", encoding="utf-8", newline="") as 文件:
        文件.write(文本)


# ---------------------------------------------------------------------------
# 系统信息
# ---------------------------------------------------------------------------


def pywebview版本() -> str:
    try:
        from webview._version import __version__ as 版本  # type: ignore

        return 版本
    except Exception:
        return getattr(__import__("webview"), "__version__", "未知")


def webview2版本() -> str:
    """查注册表里 WebView2 运行时的版本。

    这是发布时最常踩的坑：Win10 的旧机器可能没装 WebView2 运行时，
    程序会起不来。自检里查一下，能提前给出人话提示。
    """
    if not sys.platform.startswith("win"):
        return "非 Windows，跳过"
    try:
        import winreg
    except ImportError:
        return "无法检测"

    for 路径 in (
        r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    ):
        for 根 in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(根, 路径) as 键:
                    版本 = winreg.QueryValueEx(键, "pv")[0]
                    if 版本:
                        return str(版本)
            except OSError:
                continue
    return "没检测到（可能没装 WebView2 运行时）"


def 系统信息() -> dict:
    """给「关于」页面用的一堆环境信息。"""
    return {
        "应用": f"{应用名} v{版本号}",
        "Python": sys.version.split()[0],
        "pywebview": pywebview版本(),
        "WebView2": webview2版本(),
        "系统": f"{platform.system()} {platform.release()}",
        "运行方式": "已打包" if 是否已打包() else "源码运行",
        "程序目录": 程序根目录(),
        "配置目录": 用户配置目录(),
    }


# ---------------------------------------------------------------------------
# 本地静态服务（可选）
# ---------------------------------------------------------------------------


class _安静的服务(http.server.SimpleHTTPRequestHandler):
    def log_message(self, 格式, *参数):  # 不想让每个请求都刷屏
        pass


class 本地服务:
    """一个只监听 127.0.0.1 的迷你静态服务。

    为什么会有这个东西：WebView2 在 file:// 协议下会拦掉不少东西 ——
    字体（@font-face）、fetch 本地文件、ES 模块，全都不行（我实测过）。
    想让前端用上这些，就得走 http。默认不开，加 --本地服务 即可，
    起不来会自动退回 file://，不会把程序搞挂。
    """

    def __init__(self, 根目录: str):
        self.根目录 = 根目录
        self.服务器: socketserver.ThreadingTCPServer | None = None
        self.端口: int | None = None

    def 启动(self) -> str | None:
        """成功返回 http://127.0.0.1:端口/ ，失败返回 None。"""
        try:
            处理器 = functools.partial(_安静的服务, directory=self.根目录)
            self.服务器 = socketserver.ThreadingTCPServer(("127.0.0.1", 0), 处理器)
            self.服务器.daemon_threads = True
            self.端口 = self.服务器.server_address[1]
            threading.Thread(target=self.服务器.serve_forever, daemon=True).start()
            return f"http://127.0.0.1:{self.端口}/"
        except OSError as 错误:
            print(f"[提示] 本地服务起不来，改用 file:// 加载：{错误}")
            return None
