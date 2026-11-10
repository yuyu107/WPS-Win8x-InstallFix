# WPS-Win8x-InstallFix

WPS Office 在 Windows 8 / 8.1 上的安装限制修补与研究，无需扩展内核，保留官方安装流程。

**2026-11-10：国际版在线安装 Test4 已在 Windows 8.1 成功完成安装，实际下载构建为 12.1.0.29681。专业版 12.1.0.29161 此前也已完整安装成功。**

## 为什么会有这个项目？

部分较新的 WPS Office 安装包出现了这样的现象：**仍允许 Windows 7 安装，却在 Windows 8 / Windows 8.1 上直接提示“不支持当前操作系统版本”**，弹窗只列出 Windows 7、Windows 10 和 Windows 11。对于希望继续使用 Windows 8.x 的用户，这道检查会直接阻止使用官方安装器。

本项目由这个实际问题开始：分析拦截发生在哪里、能否只修改安装器自身的系统支持检查，让 Windows 8.x 继续完成原有的官方安装流程。研究从普通版和国际版离线包，扩展到专业版及国际版在线安装，保留了对应的定位依据、修补方案与验证结果。

目前已在 Windows 8.1 完成专业版和国际版在线安装。方案无需扩展内核，不替换系统 DLL，也不通过手动复制 WPS 文件来重制安装流程。

## WPS 对 Windows 8.x 的具体限制

| 系统 | 本次研究涉及的安装器行为 |
| --- | --- |
| Windows 7 | 安装器列为允许的操作系统之一 |
| Windows 8（NT 6.2） | 代码中存在针对 Windows 8.x 的支持检查，完整安装仍需独立实测 |
| Windows 8.1（NT 6.3） | 原版提示不支持；专业版 29161、国际版在线 29681 经修补已完整安装成功 |
| Windows 10 / 11 | 安装器列为允许的操作系统 |

这些结论对应本项目研究的具体构建。国际版在线和离线安装器采用不同流程，官网的系统支持列表也不能代替具体安装包的实测。

### 为什么 Windows 7 能安装，却拦截 Windows 8.x？

分析发现，这些安装器使用自己的系统支持判断，并非仅按“Windows 7 或更新版本”决定是否允许继续。一个程序把 Windows 7、10、11 列入支持范围，并不意味着中间的 Windows 8.x 会自动通过其检查。

**目前没有可信的官方技术说明可以证实厂商的决策动机。** 支持名单、维护成本、兼容测试范围或既有安装器代码都可能相关，但不能把这些解释写成已证实的厂商意图。

## 为什么普通兼容模式没能解决？

此前用户尝试 Windows 7 兼容模式仍被拦截。安装器可以在多个进程中通过不同版本接口、模块信息及内部逻辑判断系统；某个版本查询受兼容层影响，不表示整条安装链的所有判断都会改变。

本项目已确认的结果是：修补安装器内部共享的系统支持函数，可以解除所研究构建的拦截。尚未保留所有失败路径的完整动态调用链，因此不把兼容模式失败归因于某一个未经验证的 API。

## 修补原理与研究记录

| 方案 | 处理方式 | 详细说明 |
| --- | --- | --- |
| 普通版 x64 离线 | 动态提取官方内层安装器，修改共享检查函数入口六字节，使本项检查返回成功 | [普通版分析](Standard/docs/Analysis.md) |
| 国际版 x64 离线 | 独立维护 NSIS 提取及 AMD64 检测规则，修改内层检查六字节 | [国际版离线分析](International-Offline/docs/Analysis.md) |
| 专业版 | 修改外层 PE32 安装器三字节，跳到原有成功返回分支，避开入口处的重定位项 | [专业版调用关系与 ASLR 修正](Professional/docs/Analysis.md) |
| 国际版在线 | 在进程创建事件中分别处理引导器和下载后安装包的检查，验证后修改内存并继续官方进程 | [在线版两层检查及 Test1–4 记录](International-Online/docs/Analysis.md) |

这些改动针对安装器的支持判断，不修改 Windows 的全局版本报告。各版本的具体函数结构、参考位置、哈希与验证边界保留在各自目录中；参考构建的地址不作为新构建的固定修补地址。

## 按版本独立维护

| 方案 | 独立目录与入口 | 当前验证结果 |
| --- | --- | --- |
| 普通版（中国大陆版）x64 离线包 | [Standard](Standard/README.md)：`Patch/01-Apply-Patch.cmd` | 29158 已进入安装界面，输出哈希已复现 |
| 专业版 | [Professional](Professional/README.md)：`Patch/02-Apply-Pro-Patch.cmd` | 29161 在 Windows 8.1 完整安装成功 |
| 国际版 x64 离线包 | [International-Offline](International-Offline/README.md)：`Patch/01-Apply-Patch.cmd` | 29162 已进入安装界面，输出哈希已复现 |
| 国际版在线安装 | [International-Online](International-Online/README.md)：`Patch/Start_Online_Test4.cmd` | 引导器 25872 → 安装包 29681 在 Windows 8.1 完整安装成功 |

每个目录分别保存自己的脚本、检测规则、参考哈希、说明和测试；**可以单独复制一个目录使用，不导入其它版本的实现，也不保留统一修补入口**。部分版本现阶段采用相同原理，但保留独立文件，后续可分别修改。

请进入对应目录阅读用法。原来的根目录 `Patch/`、`docs/`、`tests/` 已拆分，旧路径不再使用。这里的“多版本”指同一产品版本内多个构建的结构适配，不代表四种安装流程混用。

## 多版本适配范围

普通版、国际版离线包按 NSIS 数据块和 AMD64 代码结构定位；专业版按 PE32 KPacket 结构定位。它们不因同一家族内的偏移变化而使用旧地址；结构或语义改变、候选不唯一、重定位冲突时停止。匹配新构建不等同于独立完成安装实测。

国际版在线方案对下载后的 AMD64 安装包动态定位，**在线引导器本身目前仍限定已验证的精确原始哈希**。两层修补仅发生在进程内存，磁盘原包及其签名保持原样。离线方案生成修补副本，副本原厂签名失效。

## 已知情况

国际版在线安装末尾出现过 **WPS Office Expansion tool 已停止工作**。用户确认关闭该程序后可继续并成功完成安装；扩展工具崩溃原因尚未定位，未标记为已修复。

Windows 8.1 的上述成功结果不能替代 Windows 8 的独立实测，也不能据此保证所有 WPS 组件或未来构建均兼容。

## 测试与反馈

GitHub Actions 按四个独立方案分别运行 Windows PowerShell 测试。在线方案另测 32 位父进程到 64 位子进程的调试事件、内存读写与继续执行，以及编译后检测器的结构拒绝和大代码区耗时。合成夹具不包含厂商完整程序，自动测试不代替安装实测。

提交 Issue 时注明所用目录、系统版本、安装包版本及 SHA256，附错误、补丁 JSON 或日志，并删除个人路径等隐私信息。

本仓库不分发原版或已修补的 WPS 安装器，不修改系统 DLL 或全局系统版本。项目与 WPS 官方无关联。

## English summary

Independent Windows 8/8.1 installer compatibility solutions for Standard, Professional, International Offline and International Online editions. Each directory owns its implementation, rules, documentation and tests without cross-edition runtime dependencies. Professional 12.1.0.29161 and the international online 25872 → 29681 flow completed installation on Windows 8.1. The online bootstrapper remains pinned to the verified original hash; downloaded AMD64 installers use structural detection. An end-of-install Expansion tool crash was reported without preventing completion; its cause remains unknown. No vendor binaries are redistributed.
