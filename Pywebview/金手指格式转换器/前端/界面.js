/* ==========================================================================
   界面.js —— 前端的全部逻辑
   --------------------------------------------------------------------------
   和后端说话只有一种方式：await window.pywebview.api.某方法(参数…)
   后端的方法写在 后端/接口.py，每个都返回一个对象，失败时形如
       { 成功: false, 错误: "..." }
   所以前端只要统一判断 成功 就够了 —— 后端崩了也只是这一次操作失败，
   界面照常在，用户还能继续操作（这正是前后端分离最大的好处）。

   另外：在普通浏览器里直接打开这个页面也能跑（会进入「预览模式」，
   用一份假的接口顶上），方便你只改样式的时候不用每次都启动 Python。
   ========================================================================== */

(() => {
  "use strict";

  /* 把界面里冒出来的错误攒下来，方便 Python 侧自检时读（白屏时全靠它） */
  window.最后错误 = "";
  window.addEventListener("error", (事件) => {
    window.最后错误 = `${事件.message} @${事件.filename}:${事件.lineno}`;
  });
  window.addEventListener("unhandledrejection", (事件) => {
    window.最后错误 = String((事件.reason && 事件.reason.message) || 事件.reason);
  });

  /* ------------------------------------------------------------------
     0. 小工具
     ------------------------------------------------------------------ */
  const $ = (选择器) => document.querySelector(选择器);
  const $$ = (选择器) => Array.from(document.querySelectorAll(选择器));
  const 转义 = (文本) => String(文本 ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  // 配色表：名字要和 样式.css 里 html[data-配色="…"] 对得上
  const 配色表 = [
    { 名: "青瓷", 色: "#1F8A70" },
    { 名: "黛蓝", 色: "#2C6FB5" },
    { 名: "紫棠", 色: "#7A5AC7" },
    { 名: "琥珀", 色: "#B8792A" },
  ];

  const 元素 = {
    输入框: $("#输入框"),
    输出框: $("#输出框"),
    统计: $("#统计"),
    进度条: $("#进度条"),
    状态文字: $("#状态文字"),
    版本行: $("#版本行"),
    信息表: $("#信息表"),
    提示层: $("#提示层"),
    拖拽层: $("#拖拽层"),
    外观分段: $("#外观分段"),
    配色行: $("#配色行"),
    主按钮: $("#按钮-转换"),
  };

  const 状态 = {
    外观: "dark",     // light / dark / system
    配色: "青瓷",
    桥: null,         // 真正的 pywebview.api，或预览模式下的假接口
    预览模式: false,
    转换中: false,
    上次保存: "",
  };

  /* ------------------------------------------------------------------
     1. 跟后端说话
     ------------------------------------------------------------------ */
  async function 调用(方法, ...参数) {
    const 桥 = 状态.桥;
    if (!桥 || typeof 桥[方法] !== "function") {
      return { 成功: false, 错误: `后端没有提供接口：${方法}` };
    }
    try {
      return (await 桥[方法](...参数)) || { 成功: true };
    } catch (错误) {
      return { 成功: false, 错误: String((错误 && 错误.message) || 错误) };
    }
  }

  /* ------------------------------------------------------------------
     2. 外观与配色
     ------------------------------------------------------------------ */
  function 生效外观() {
    if (状态.外观 !== "system") return 状态.外观;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function 刷新外观界面() {
    document.documentElement.dataset.外观 = 生效外观();
    document.documentElement.dataset.配色 = 状态.配色;
    $$("#外观分段 button").forEach((按钮) =>
      按钮.classList.toggle("选中", 按钮.dataset.外观值 === 状态.外观));
    $$(".色点").forEach((按钮) =>
      按钮.classList.toggle("选中", 按钮.dataset.配色 === 状态.配色));
  }

  function 设外观(值, 要记住 = true) {
    状态.外观 = 值;
    刷新外观界面();
    if (要记住) 记住外观();
  }

  function 设配色(名, 要记住 = true) {
    状态.配色 = 名;
    刷新外观界面();
    if (要记住) 记住外观();
  }

  function 记住外观() {
    try {
      localStorage.setItem("外观", 状态.外观);
      localStorage.setItem("配色", 状态.配色);
    } catch (错误) { /* 隐私模式下写不了，无所谓 */ }

    // 同时告诉 Python 存一份，下次启动窗口底色直接对上，不会先白一下再变黑
    const 签名 = `${状态.外观}/${状态.配色}`;
    if (签名 === 状态.上次保存) return;
    状态.上次保存 = 签名;
    调用("保存外观", 状态.外观, 状态.配色);
  }

  function 建配色按钮() {
    元素.配色行.innerHTML = "";
    配色表.forEach(({ 名, 色 }) => {
      const 按钮 = document.createElement("button");
      按钮.className = "色点";
      按钮.dataset.配色 = 名;
      按钮.title = 名;
      按钮.style.background = 色;
      按钮.addEventListener("click", () => 设配色(名));
      元素.配色行.appendChild(按钮);
    });
  }

  /* ------------------------------------------------------------------
     3. 状态栏 / 气泡提示
     ------------------------------------------------------------------ */
  function 设状态(文字) {
    元素.状态文字.textContent = 文字;
  }

  function 提示(文字, 类型 = "") {
    const 气泡 = document.createElement("div");
    气泡.className = "提示" + (类型 ? " " + 类型 : "");
    气泡.textContent = 文字;
    元素.提示层.appendChild(气泡);
    setTimeout(() => {
      气泡.classList.add("淡出");
      setTimeout(() => 气泡.remove(), 300);
    }, 类型 === "错误" ? 6000 : 2600);
  }

  // 统一处理接口返回：失败就弹红条，成功返回 true
  function 检查(结果, 成功提示) {
    if (结果 && 结果.成功 === false) {
      提示(结果.错误 || "操作失败", "错误");
      设状态("出错了：" + (结果.错误 || "未知错误"));
      return false;
    }
    if (成功提示) 提示(成功提示);
    return true;
  }

  /* ------------------------------------------------------------------
     4. 统计与进度
     ------------------------------------------------------------------ */
  function 数行数(文本) {
    if (!文本) return 0;
    return 文本.split(/\r\n|\r|\n/).length;
  }

  function 刷新统计() {
    const 入 = 元素.输入框.value;
    const 出 = 元素.输出框.value;
    元素.统计.textContent =
      `输入 ${数行数(入)} 行 / ${入.length} 字 · 输出 ${数行数(出)} 行 / ${出.length} 字`;
  }

  function 设进度(百分比) {
    元素.进度条.style.width = Math.max(0, Math.min(1, 百分比)) * 100 + "%";
  }

  // ↓ Python 会通过 evaluate_js 调这个函数推进度，所以必须挂在 window 上、且是同步函数
  window.更新进度 = function (百分比, 行数) {
    设进度(百分比);
    if (行数) 设状态(`转换中… 已处理 ${行数} 行`);
  };

  /* ------------------------------------------------------------------
     5. 主要动作
     ------------------------------------------------------------------ */
  async function 转换() {
    if (状态.转换中) return;
    const 原文 = 元素.输入框.value;
    if (!原文.trim()) {
      设状态("左边还是空的 —— 先贴点内容，或者按 Ctrl+O 打开文件");
      元素.输入框.focus();
      return;
    }

    状态.转换中 = true;
    元素.主按钮.disabled = true;
    元素.主按钮.textContent = "转换中…";
    设进度(0);
    设状态("转换中…");

    const 结果 = await 调用("转换文本", 原文);

    状态.转换中 = false;
    元素.主按钮.disabled = false;
    元素.主按钮.textContent = "开始转换";

    if (!检查(结果)) {
      设进度(0);
      return;
    }

    元素.输出框.value = 结果.输出 || "";
    设进度(1);
    刷新统计();
    设状态(`转换完成：${结果.行数} 行，用时 ${Math.round((结果.耗时 || 0) * 1000)} 毫秒`);
  }

  async function 打开文件() {
    const 结果 = await 调用("打开文件");
    if (结果.取消) { 设状态("已取消打开"); return; }
    if (!检查(结果)) return;

    元素.输入框.value = 结果.文本 || "";
    元素.输出框.value = "";
    设进度(0);
    刷新统计();
    设状态(`已打开 ${结果.文件名}（${结果.编码}，${结果.行数} 行）`);
    提示(`已打开 ${结果.文件名}`);
  }

  async function 保存文件() {
    const 文本 = 元素.输出框.value;
    if (!文本.trim()) { 设状态("右边还没有内容，先按 Ctrl+Enter 转换一下"); return; }

    const 结果 = await 调用("保存文件", 文本, "金手指.txt");
    if (结果.取消) { 设状态("已取消保存"); return; }
    if (!检查(结果)) return;
    设状态(`已保存到 ${结果.路径}`);
    提示(`已保存 ${结果.文件名}`);
  }

  async function 复制结果() {
    const 文本 = 元素.输出框.value;
    if (!文本.trim()) { 设状态("右边还没有内容，先按 Ctrl+Enter 转换一下"); return; }

    // 先用 Python 的 Win32 剪贴板；不行再退到浏览器那套
    const 结果 = await 调用("复制到剪贴板", 文本);
    let 成功 = 结果 && 结果.成功 !== false;

    if (!成功) {
      try {
        元素.输出框.select();
        成功 = document.execCommand("copy");
        window.getSelection().removeAllRanges();
      } catch (错误) { 成功 = false; }
    }

    if (成功) {
      设状态(`已复制 ${文本.length} 个字符到剪贴板`);
      提示("已复制到剪贴板");
    } else {
      提示("复制失败，请手动选中后按 Ctrl+C", "错误");
    }
  }

  function 清空() {
    元素.输入框.value = "";
    元素.输出框.value = "";
    设进度(0);
    刷新统计();
    设状态("已清空");
    元素.输入框.focus();
  }

  function 切页(名字) {
    $$(".页面").forEach((页) => 页.classList.toggle("显示", 页.dataset.页面名 === 名字));
    $$(".导航项").forEach((项) => 项.classList.toggle("选中", 项.dataset.页面 === 名字));
  }

  /* ------------------------------------------------------------------
     6. 拖拽文件进来
     ------------------------------------------------------------------ */
  function 装拖拽() {
    let 计数器 = 0;
    const 阻止 = (事件) => { 事件.preventDefault(); 事件.stopPropagation(); };

    window.addEventListener("dragenter", (事件) => {
      阻止(事件);
      计数器 += 1;
      元素.拖拽层.classList.add("激活");
    });
    window.addEventListener("dragover", 阻止);
    window.addEventListener("dragleave", (事件) => {
      阻止(事件);
      计数器 = Math.max(0, 计数器 - 1);
      if (计数器 === 0) 元素.拖拽层.classList.remove("激活");
    });

    window.addEventListener("drop", async (事件) => {
      阻止(事件);
      计数器 = 0;
      元素.拖拽层.classList.remove("激活");

      const 文件 = 事件.dataTransfer && 事件.dataTransfer.files[0];
      if (!文件) return;
      try {
        const 文本 = await 文件.text();   // 浏览器直接读，不用经过 Python
        元素.输入框.value = 文本;
        元素.输出框.value = "";
        设进度(0);
        刷新统计();
        设状态(`已读入 ${文件.name}（${文本.length} 字），Ctrl+Enter 转换`);
        提示(`已读入 ${文件.name}`);
      } catch (错误) {
        提示(`读不了这个文件：${错误}`, "错误");
      }
    });
  }

  /* ------------------------------------------------------------------
     7. 快捷键
     ------------------------------------------------------------------ */
  function 装快捷键() {
    document.addEventListener("keydown", (事件) => {
      const 控制 = 事件.ctrlKey || 事件.metaKey;

      if (事件.key === "F1") { 事件.preventDefault(); 切页("关于"); return; }

      if (!控制) {
        // 在输入框里按 Ctrl+Enter 也走转换，单独判一次
        return;
      }
      const 键 = 事件.key.toLowerCase();

      if (键 === "enter") { 事件.preventDefault(); 转换(); }
      else if (键 === "o") { 事件.preventDefault(); 打开文件(); }
      else if (键 === "s") { 事件.preventDefault(); 保存文件(); }
      else if (键 === "l") { 事件.preventDefault(); 清空(); }
      else if (键 === "c" && 事件.shiftKey) { 事件.preventDefault(); 复制结果(); }
    });

    // 输入框里按 Ctrl+Enter 容易被 textarea 自己吃掉，单独绑一遍
    元素.输入框.addEventListener("keydown", (事件) => {
      if ((事件.ctrlKey || 事件.metaKey) && 事件.key === "Enter") {
        事件.preventDefault();
        转换();
      }
    });

    // 右键菜单：文本框里保留（要复制粘贴），其他地方屏蔽掉，免得像浏览器
    document.addEventListener("contextmenu", (事件) => {
      const 是文本框 = 事件.target && 事件.target.tagName === "TEXTAREA";
      if (!是文本框) 事件.preventDefault();
    });
  }

  /* ------------------------------------------------------------------
     8. 关于页
     ------------------------------------------------------------------ */
  function 填环境信息(环境信息) {
    元素.信息表.innerHTML = Object.entries(环境信息 || {})
      .map(([键, 值]) => `<div class="信息键">${转义(键)}</div><div class="信息值">${转义(值)}</div>`)
      .join("");
  }

  /* ------------------------------------------------------------------
     9. 预览模式：在普通浏览器里打开也能看界面
     ------------------------------------------------------------------ */
  function 建假接口() {
    // 这份实现只为了让样式能单独调试，真正的转换永远在 Python 那边
    const 假转换 = (文本) =>
      文本.split(/\r\n|\r|\n/)
        .map((行) => {
          const 净 = 行.trim();
          return 净.toUpperCase().startsWith("CODE") ? 净.toUpperCase() : 净;
        })
        .join("\n");

    return {
      初始化: async () => ({
        成功: true,
        配置: {},
        环境: {
          "（预览模式）": "在浏览器里打开，后端是假的",
          应用: "金手指格式转换器 v1.0.0",
          说明: "启动 主程序.py 才是真的",
        },
        示例: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<_S>\n  <folder name=\"示例\">\n    <codes>94000130 fcff0000</codes>\n  </folder>\n</S>",
        应用名: "金手指格式转换器",
        版本号: "1.0.0",
      }),
      转换文本: async (文本) => ({
        成功: true,
        输出: 假转换(文本),
        行数: 文本.split(/\r\n|\r|\n/).length,
        字符数: 假转换(文本).length,
        耗时: 0.001,
      }),
      保存外观: async () => ({ 成功: true }),
      打开文件: async () => ({ 成功: false, 错误: "预览模式没有文件对话框" }),
      保存文件: async () => ({ 成功: false, 错误: "预览模式没有文件对话框" }),
      复制到剪贴板: async (文本) => {
        await navigator.clipboard.writeText(文本);
        return { 成功: true };
      },
      打开目录: async () => ({ 成功: false, 错误: "预览模式不支持" }),
      退出程序: async () => ({ 成功: false, 错误: "预览模式不支持" }),
    };
  }

  /* ------------------------------------------------------------------
     10. 启动
     ------------------------------------------------------------------ */
  async function 启动() {
    建配色按钮();
    刷新外观界面();
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (状态.外观 === "system") 刷新外观界面();
    });

    // 等桥：pywebview 会先抛 pywebviewready 事件
    const 桥 = await new Promise((解决) => {
      if (window.pywebview && window.pywebview.api) return 解决(window.pywebview.api);
      const 超时 = setTimeout(() => 解决(null), 2500);   // 等不到就当是在浏览器里预览
      window.addEventListener("pywebviewready", () => {
        clearTimeout(超时);
        解决(window.pywebview.api);
      }, { once: true });
    });

    状态.桥 = 桥 || 建假接口();
    状态.预览模式 = !桥;

    // 先读本地存的外观，避免闪一下
    try {
      const 存的外观 = localStorage.getItem("外观");
      const 存的配色 = localStorage.getItem("配色");
      if (存的配色 && 配色表.some((项) => 项.名 === 存的配色)) 状态.配色 = 存的配色;
      if (存的外观) 状态.外观 = 存的外观;
    } catch (错误) { /* 忽略 */ }
    刷新外观界面();

    // 再问后端要初始数据（配置里的外观优先级更高）
    const 初始 = await 调用("初始化");
    if (初始 && 初始.成功 !== false) {
      const 配置 = 初始.配置 || {};
      if (配置.配色 && 配色表.some((项) => 项.名 === 配置.配色)) 状态.配色 = 配置.配色;
      if (配置.外观) 状态.外观 = 配置.外观;
      刷新外观界面();
      元素.版本行.textContent = `v${初始.版本号} · pywebview`;
      元素.输入框.value = 初始.示例 || "";
      填环境信息(初始.环境);
      刷新统计();
      设状态("准备就绪 · 左边贴原文，Ctrl+Enter 转换，Ctrl+O 打开文件");
    } else if (初始 && 初始.错误) {
      提示("初始化失败：" + 初始.错误, "错误");
      设状态("初始化失败，但界面还能用");
    }

    // 地址栏里带 #外观=light&配色=黛蓝&页面=关于 可以强制指定本次外观。
    // 优先级最高（压过配置和 localStorage），调样式和截图时很省事。
    try {
      const 参数 = new URLSearchParams(location.hash.replace(/^#/, ""));
      const 指定外观 = 参数.get("外观");
      const 指定配色 = 参数.get("配色");
      if (指定外观 && ["light", "dark", "system"].includes(指定外观)) 状态.外观 = 指定外观;
      if (指定配色 && 配色表.some((项) => 项.名 === 指定配色)) 状态.配色 = 指定配色;
      if (指定外观 || 指定配色) 刷新外观界面();
      if (参数.get("页面") === "关于") 切页("关于");
    } catch (错误) { /* 忽略 */ }

    if (状态.预览模式) {
      提示("浏览器预览模式：后端是假的，启动 主程序.py 才是真的", "错误");
    }

    // 事件绑定
    元素.主按钮.addEventListener("click", 转换);
    $("#按钮-打开").addEventListener("click", 打开文件);
    $("#按钮-保存").addEventListener("click", 保存文件);
    $("#按钮-复制").addEventListener("click", 复制结果);
    $("#按钮-清空").addEventListener("click", 清空);
    $("#按钮-目录").addEventListener("click", async () => 检查(await 调用("打开目录", "")));
    $("#按钮-环境").addEventListener("click", async () => {
      const 行 = Object.entries((await 调用("取环境信息")).环境 || {})
        .map(([键, 值]) => `${键}：${值}`).join("\n");
      await 调用("复制到剪贴板", 行);
      提示("环境信息已复制，提 issue 时贴上去很方便");
    });
    $("#按钮-退出").addEventListener("click", () => 调用("退出程序"));

    元素.外观分段.addEventListener("click", (事件) => {
      const 按钮 = 事件.target.closest("button");
      if (按钮) 设外观(按钮.dataset.外观值);
    });
    $$(".导航项").forEach((项) => 项.addEventListener("click", () => 切页(项.dataset.页面)));

    元素.输入框.addEventListener("input", () => {
      刷新统计();
      if (!元素.输入框.value.trim()) 设进度(0);
    });
    元素.输出框.addEventListener("input", 刷新统计);

    装拖拽();
    装快捷键();
    元素.输入框.focus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", 启动);
  } else {
    启动();
  }
})();
