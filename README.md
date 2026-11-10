# WPS-Win8x-InstallFix

WPS Office 在 Windows 8 / 8.1 上的安装限制修补与研究，无需扩展内核，保留官方安装流程。

**2026-11-10：国际版在线安装 Test4 已在 Windows 8.1 成功完成安装，实际下载构建为 12.1.0.29681。专业版 12.1.0.29161 此前也已完整安装成功。**

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
