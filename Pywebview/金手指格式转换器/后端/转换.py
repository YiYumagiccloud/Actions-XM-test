# -*- coding: utf-8 -*-
"""金手指格式转换 —— 这个文件就是你的「业务逻辑」，平时改它就够了。

三条约定（照着来，前后端就不会互相拖累）：

  1. 这里只做**纯数据处理**：不碰窗口、不碰界面、不碰 pywebview。
  2. 输入字符串，输出字典；出错就直接抛异常。
  3. 抛出的异常会被 后端/接口.py 的「安全」装饰器接住，变成前端右下角的一条红色提示。
     —— 也就是说：**这里写崩了，程序不会崩**，只是这次转换失败而已。

想把老代码接进来（你的 格式化.py，用 BeautifulSoup 解析 usrch​​eat.xml）：
    from 格式化 import 格式转换          # 你原来的函数
    def 转换(文本, 进度回调=None):
        输出 = 格式转换(文本)
        return {"输出": 输出, ...}
只要保证「字符串进、字符串出」，前端一行都不用改。
"""

from __future__ import annotations

import time
from typing import Callable

# 每批处理多少行。太大了界面上的进度条会一跳到底，太小了又是白白开销
每批行数 = 500

# 首次打开时放在左边输入框里的示例内容（给用户一眼看到效果，点「清空」就没了）
示例原文 = """<?xml version="1.0" encoding="UTF-8"?>
<_S>
  <folder name="宝可梦 白金">
    <name>宝可梦 白金</name>
    <cheat>
      <name>无限金钱</name>
      <codes>94000130 fcff0000 62101d40 00000000</codes>
    </cheat>
    <cheat>
      <name>全部道具</name>
      <codes>d5000000 00000001 c0000000 0000000f</codes>
    </cheat>
  </folder>
</S>"""


def 整理一行(行: str) -> str:
    """单行处理：去掉首尾空白；CODE 行里的十六进制统一成大写，读起来对起来都省事。"""
    行 = 行.strip()
    if 行.upper().startswith("CODE"):
        行 = 行.upper()
    return 行


def 转换(文本: str, 进度回调: Callable[[float, int], None] | None = None) -> dict:
    """把原文转成目标格式。

    参数：
        文本      输入文本（整篇）
        进度回调  可选。形如 回调(百分比, 已处理行数)，用来把进度推给界面

    返回：
        {"输出": str, "行数": int, "字符数": int, "耗时": float}
    """
    开始 = time.perf_counter()
    原文行 = 文本.splitlines()
    总数 = len(原文行) or 1
    结果行: list[str] = []

    for 序号, 行 in enumerate(原文行):
        结果行.append(整理一行(行))
        # 每批汇报一次进度就够了，逐行汇报会把 JS 桥刷爆
        if 进度回调 and (序号 + 1) % 每批行数 == 0:
            进度回调((序号 + 1) / 总数, 序号 + 1)

    if 进度回调:
        进度回调(1.0, len(原文行))

    输出 = "\n".join(结果行)
    return {
        "输出": 输出,
        "行数": len(结果行),
        "字符数": len(输出),
        "耗时": round(time.perf_counter() - 开始, 4),
    }


def 取示例() -> str:
    return 示例原文
# -*- coding: utf-8 -*-
"""金手指格式转换 —— 这个文件就是你的「业务逻辑」，平时改它就够了。

三条约定（照着来，前后端就不会互相拖累）：

  1. 这里只做**纯数据处理**：不碰窗口、不碰界面、不碰 pywebview。
  2. 输入字符串，输出字典；出错就直接抛异常。
  3. 抛出的异常会被 后端/接口.py 的「安全」装饰器接住，变成前端右下角的一条红色提示。
     —— 也就是说：**这里写崩了，程序不会崩**，只是这次转换失败而已。

想把老代码接进来（你的 格式化.py，用 BeautifulSoup 解析 usrch​​eat.xml）：
    from 格式化 import 格式转换          # 你原来的函数
    def 转换(文本, 进度回调=None):
        输出 = 格式转换(文本)
        return {"输出": 输出, ...}
只要保证「字符串进、字符串出」，前端一行都不用改。
"""

from __future__ import annotations

import time
from typing import Callable

# 每批处理多少行。太大了界面上的进度条会一跳到底，太小了又是白白开销
每批行数 = 500

# 首次打开时放在左边输入框里的示例内容（给用户一眼看到效果，点「清空」就没了）
示例原文 = """<?xml version="1.0" encoding="UTF-8"?>
<_S>
  <folder name="宝可梦 白金">
    <name>宝可梦 白金</name>
    <cheat>
      <name>无限金钱</name>
      <codes>94000130 fcff0000 62101d40 00000000</codes>
    </cheat>
    <cheat>
      <name>全部道具</name>
      <codes>d5000000 00000001 c0000000 0000000f</codes>
    </cheat>
  </folder>
</S>"""


def 整理一行(行: str) -> str:
    """单行处理：去掉首尾空白；CODE 行里的十六进制统一成大写，读起来对起来都省事。"""
    行 = 行.strip()
    if 行.upper().startswith("CODE"):
        行 = 行.upper()
    return 行


def 转换(文本: str, 进度回调: Callable[[float, int], None] | None = None) -> dict:
    """把原文转成目标格式。

    参数：
        文本      输入文本（整篇）
        进度回调  可选。形如 回调(百分比, 已处理行数)，用来把进度推给界面

    返回：
        {"输出": str, "行数": int, "字符数": int, "耗时": float}
    """
    开始 = time.perf_counter()
    原文行 = 文本.splitlines()
    总数 = len(原文行) or 1
    结果行: list[str] = []

    for 序号, 行 in enumerate(原文行):
        结果行.append(整理一行(行))
        # 每批汇报一次进度就够了，逐行汇报会把 JS 桥刷爆
        if 进度回调 and (序号 + 1) % 每批行数 == 0:
            进度回调((序号 + 1) / 总数, 序号 + 1)

    if 进度回调:
        进度回调(1.0, len(原文行))

    输出 = "\n".join(结果行)
    return {
        "输出": 输出,
        "行数": len(结果行),
        "字符数": len(输出),
        "耗时": round(time.perf_counter() - 开始, 4),
    }


def 取示例() -> str:
    return 示例原文
