# -*- coding: utf-8 -*-
"""金手指格式转换器 · 主程序（Pywebview 版）

    python 主程序.py                  正常启动
    python 主程序.py --debug          带开发者工具（右键「检查」）
    python 主程序.py --selfcheck      只做环境自检，不弹窗（CI 用）
    python 主程序.py --selfcheck-window   连窗口一起验（本地排查用）

结构（前后端彻底分开，改一边不会带崩另一边）：

    主程序.py         ← 你在这里：建窗口、挂接口、启动
    后端/环境.py      ← 路径、配置、系统信息、可选的本地静态服务
    后端/转换.py      ← ⭐ 业务逻辑，平时改这个
    后端/接口.py      ← 暴露给 JS 的函数（前后端唯一的通道）
    前端/index.html   ← 界面结构
    前端/样式.css     ← 配色和样式（顶部一堆 CSS 变量）
    前端/界面.js      ← 交互逻辑

一句话原理：WebView2（Chromium）负责画界面，Python 负责干活，
两边通过 window.pywebview.api 这个桥互相调用。界面再花哨也不会拖慢 Python，
Python 里算错了也只是前端弹一条红字，程序不会整个崩掉。
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import webview

# 让 `python 主程序.py` 在任意工作目录下都能 import 到 后端/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from 后端 import 环境, 接口, 转换  # noqa: E402

窗口宽 = 1160
窗口高 = 720
最小宽 = 900
最小高 = 580


# ---------------------------------------------------------------------------
# 窗口位置
# ---------------------------------------------------------------------------

def 算居中位置(宽: int, 高: int) -> tuple[int, int]:
    """算窗口居中时的 x/y。

    ⚠ 坑：pywebview 的 width/height/x/y 都是「逻辑像素」，会乘以屏幕缩放系数后
    再交给系统（我实测过：150% 缩放下请求 800x500@(100,100)，真实窗口是
    1200x750@(150,150)）。而 webview.screens 报的是**物理**尺寸。
    好在宽高和位置乘的是同一个系数，所以只要把屏幕也换算成逻辑尺寸，
    按逻辑尺寸居中，显示出来就是正的。
    """
    try:
        屏 = webview.screens[0]
        缩放 = 屏.scale or 1.0
        逻辑屏宽 = 屏.width / 缩放
        逻辑屏高 = 屏.height / 缩放
    except Exception:  # 拿不到屏幕信息就别居中了，交给系统安排
        return 0, 0

    x = max(0, int((逻辑屏宽 - 宽) / 2))
    y = max(0, int((逻辑屏高 - 高) / 2) - 20)
    return x, y


def 起始底色() -> str:
    """窗口还没显示时的底色。用上次记住的外观，避免深色模式先闪一下白。"""
    配置 = 环境.读配置()
    外观 = 配置.get("外观", "system")
    深色 = 环境.系统是深色() if 外观 == "system" else 外观 == "dark"
    return "#121817" if 深色 else "#EDF2F1"


# ---------------------------------------------------------------------------
# 环境自检
# ---------------------------------------------------------------------------

def 自检() -> int:
    """不弹窗的自检，CI 里跑的就是它。返回 0 表示全部通过。"""
    全部通过 = True

    def 报告(项目: str, 结果: bool, 说明: str = "") -> None:
        nonlocal 全部通过
        全部通过 = 全部通过 and 结果
        print(f"  [{'OK' if 结果 else '!!'}] {项目}{(' · ' + 说明) if 说明 else ''}")

    print(f"{环境.应用名} v{环境.版本号} 环境自检")
    print(f"  Python        {sys.version.split()[0]}")
    print(f"  运行方式      {'已打包' if 环境.是否已打包() else '源码运行'}")
    print(f"  程序目录      {环境.程序根目录()}")

    # 1) 前端三件套
    for 文件, 说明 in (("前端/index.html", "界面结构"), ("前端/样式.css", "样式"), ("前端/界面.js", "交互逻辑")):
        路径 = 环境.程序根目录(*文件.split("/"))
        报告(f"前端文件 {说明}", os.path.isfile(路径), 路径)

    # 2) 窗口图标
    报告("窗口图标", os.path.isfile(环境.程序根目录("图片素材", "湍流模型.ico")))

    # 3) pywebview / pythonnet
    try:
        import webview  # noqa: F401

        报告("pywebview", True, f"{环境.pywebview版本()}")
    except Exception as 错误:
        报告("pywebview", False, str(错误))

    try:
        import clr  # noqa: F401

        报告("pythonnet(.NET 桥)", True, "Windows 后端需要它")
    except Exception as 错误:
        报告("pythonnet(.NET 桥)", False, str(错误))

    # 4) WebView2 运行时（发布时最常踩的坑：老 Win10 上可能没装）
    #    CI 的机器不一定有，那边只提醒、不判失败
    在CI = os.environ.get("CI", "").lower() in ("1", "true", "yes")
    版本 = 环境.webview2版本()
    有运行时 = "没检测到" not in 版本
    报告("WebView2 运行时", 有运行时 or 在CI,
        版本 + ("（CI 上不强制要求）" if (在CI and not 有运行时) else ""))

    # 5) 转换逻辑跑一遍
    try:
        结果 = 转换.转换(转换.取示例())
        正常 = 结果["行数"] > 0 and len(结果["输出"]) > 0
        报告("转换逻辑", 正常, f"{结果['行数']} 行 / {结果['字符数']} 字")
    except Exception as 错误:
        报告("转换逻辑", False, str(错误))

    # 6) 接口层（异常兜底是不是真的兜住了）
    try:
        面 = 接口.接口()
        好的 = 面.转换文本("CODE 0 测试\nabcd ef01")
        坏的 = 面.转换文本(None)  # 故意传错类型，应该被兜住而不是抛出来
        报告("接口转换", bool(好的.get("成功")) and "CODE 0 测试" in 好的.get("输出", ""))
        报告("异常兜底", 坏的.get("成功") is False and bool(坏的.get("错误")), str(坏的.get("错误"))[:60])
    except Exception as 错误:
        报告("接口层", False, f"{type(错误).__name__}: {错误}")

    print("自检结果：", "通过" if 全部通过 else "有项目未通过")
    return 0 if 全部通过 else 1


def 自检_带窗口(超时秒: float = 30.0) -> int:
    """连窗口一起验：真的把界面打开，等前端报到，再读一下 DOM。

    这个不放进 CI（CI 上没有交互桌面，WebView2 不一定起得来），
    但你在本机排查「界面白屏 / 桥不通」时非常有用。
    """
    记录 = {"前端就绪": False, "版本行": "", "控件数": 0, "错误": "", "界面错误": ""}
    面 = 接口.接口()

    def 启动后():
        print("[自检] 窗口已启动，等前端报到…", flush=True)
        截止 = time.time() + 超时秒
        while time.time() < 截止:
            if 面.前端已就绪:
                记录["前端就绪"] = True
                break
            time.sleep(0.2)
        print(f"[自检] 前端就绪 = {记录['前端就绪']}", flush=True)

        if 记录["前端就绪"]:
            time.sleep(0.8)  # 等界面把初始数据渲染完
            try:
                记录["版本行"] = 面._窗口.evaluate_js("document.getElementById('版本行').textContent") or ""
                记录["控件数"] = 面._窗口.evaluate_js("document.querySelectorAll('button, textarea').length") or 0
                记录["界面错误"] = 面._窗口.evaluate_js("window.最后错误 || ''") or ""
            except Exception as 错误:
                记录["错误"] = f"{type(错误).__name__}: {错误}"
        else:
            记录["错误"] = f"{超时秒:.0f} 秒内前端没有报到（可能是白屏或脚本报错）"
            # 白屏时把现场问出来：页面到底加没加载、JS 有没有报错、状态栏写了什么
            for 名字, 脚本 in (
                ("页面地址", "location.href"),
                ("加载状态", "document.readyState"),
                ("界面错误", "window.最后错误 || ''"),
                ("状态栏", "document.getElementById('状态文字') ? document.getElementById('状态文字').textContent : '(没有状态栏)'"),
                ("桥梁", "typeof window.pywebview + ' / ' + (window.pywebview && window.pywebview.api ? Object.keys(window.pywebview.api).length + ' 个接口' : '无 api')"),
            ):
                try:
                    记录[名字] = 面._窗口.evaluate_js(脚本)
                except Exception as 错误2:
                    记录[名字] = f"（问不出来：{type(错误2).__name__}）"

        print("[自检] 准备关闭窗口", flush=True)
        面._窗口.destroy()
        print("[自检] 已请求关闭", flush=True)

    建窗口(面, 隐藏=False)
    webview.start(启动后, debug=False, private_mode=False, storage_path=环境.浏览器数据目录())

    print("带窗口自检：")
    print(f"  前端报到      {'OK' if 记录['前端就绪'] else '失败'}")
    print(f"  版本行        {记录['版本行']!r}")
    print(f"  可交互控件数  {记录['控件数']}")
    for 名字 in ("页面地址", "加载状态", "界面错误", "状态栏", "桥梁"):
        if 名字 in 记录:
            print(f"  {名字:<10}  {记录[名字]!r}")
    if 记录["错误"]:
        print(f"  错误          {记录['错误']}")
    通过 = 记录["前端就绪"] and 记录["版本行"].startswith("v") and 记录["控件数"] > 5
    print("带窗口自检结果：", "通过" if 通过 else "未通过")
    return 0 if 通过 else 1


# ---------------------------------------------------------------------------
# 建窗口
# ---------------------------------------------------------------------------

def 建窗口(面: 接口.接口, 隐藏: bool = False, 用本地服务: bool = False) -> webview.Window:
    """创建窗口并把接口挂上去。"""
    入口 = 环境.前端入口()
    if not os.path.isfile(入口):
        raise SystemExit(f"[错误] 找不到前端页面：{入口}\n是不是没把 前端/ 目录一起拷过来？")

    地址 = 入口
    if 用本地服务:
        # 想用 @font-face / fetch 本地文件 / ES 模块时才需要，见 README
        服务 = 环境.本地服务(环境.程序根目录())
        前缀 = 服务.启动()
        if 前缀:
            地址 = 前缀 + "前端/index.html"
            print(f"[信息] 本地服务已启动：{前缀}")

    x, y = 算居中位置(窗口宽, 窗口高)
    窗口 = webview.create_window(
        title=f"{环境.应用名} v{环境.版本号}",
        url=地址,
        js_api=面,
        width=窗口宽,
        height=窗口高,
        x=x,
        y=y,
        min_size=(最小宽, 最小高),
        background_color=起始底色(),
        text_select=True,          # 允许选中文字，不然文本框里选不了
        hidden=隐藏,
    )
    面._窗口 = 窗口
    return 窗口


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def 解析参数() -> argparse.Namespace:
    解析器 = argparse.ArgumentParser(description=f"{环境.应用名} v{环境.版本号}（pywebview 版）")
    解析器.add_argument("--debug", action="store_true", help="打开开发者工具，方便调前端")
    解析器.add_argument("--selfcheck", action="store_true", help="只做环境自检，不弹窗")
    解析器.add_argument("--selfcheck-window", action="store_true", help="自检并真的打开窗口验证")
    解析器.add_argument("--本地服务", action="store_true", help="用本地 http 服务加载前端（需要 @font-face/fetch 时用）")
    解析器.add_argument("--version", action="version", version=f"{环境.应用名} {环境.版本号}")
    return 解析器.parse_args()


def main() -> int:
    参数 = 解析参数()

    if 参数.selfcheck:
        return 自检()
    if 参数.selfcheck_window:
        return 自检_带窗口()

    # 干净的单窗口应用样子：程序只允许开一个，别让两个实例互相打架
    if not 环境.抢单实例锁():
        环境.提示已经在运行()
        return 0

    # 干净的桌面应用样子：不要默认菜单栏，不要下载行为
    try:
        webview.settings["SHOW_DEFAULT_MENUS"] = False
        webview.settings["ALLOW_DOWNLOADS"] = False
        webview.settings["OPEN_DEVTOOLS_IN_DEBUG"] = True
    except Exception as 错误:
        print(f"[提示] 改不了 pywebview 设置（无伤大雅）：{错误}")

    面 = 接口.接口()
    建窗口(面, 用本地服务=参数.本地服务)

    webview.start(
        debug=参数.debug,
        icon=环境.程序根目录("图片素材", "湍流模型.ico"),
        private_mode=False,                    # 关掉隐私模式，让 WebView2 有持久缓存，第二次启动更快
        storage_path=环境.浏览器数据目录(),
        http_port=环境.取空闲端口(),            # ⚠ 必须自己指定：private_mode=False 时 pywebview 会写死 42001
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
