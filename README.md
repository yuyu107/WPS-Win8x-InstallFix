# WPS-Win8x-InstallFix

**WPS Office Windows 8 / 8.1 安装限制修复与技术研究**（无需扩展内核）

部分较新的 WPS Office 安装器出现了令人困惑的现象：**仍允许 Windows 7 安装，却在 Windows 8 / Windows 8.1 上直接提示操作系统不受支持**。本仓库记录该现象、分析其安装器的系统版本检查，并提供针对两个经过静态校验的 x64 离线安装包的实验性补丁。

> 当前仅由用户实测确认：修补后能**进入安装界面**。尚不能据此认定安装全部完成、运行/更新/卸载正常，亦不代表官方支持 Windows 8.x。

## WPS 对 Windows 8.x 的具体限制

| 系统 | 此次研究所涉及离线安装包的行为 |
| --- | --- |
| Windows 7 | 安装器列为允许的操作系统之一 |
| Windows 8 (NT 6.2) | 安装器存在拦截 Windows 8.x 的版本检测逻辑；需进一步区分各系统的独立完整测试 |
| Windows 8.1 (NT 6.3) | 原版测试时提示不支持；修补后可进入安装界面 |
| Windows 10 / 11 | 安装器列为允许的操作系统 |

本项目涉及两个不同地区的 **x64 离线包**：中国大陆版 `12.1.0.29158` 和国际版 `12.1.0.29162`。两者原版均被报告在 Windows 8.x 上拦截，使用相同原理修改后均已进入安装界面。**不能简单断言所有国际版都兼容或都不兼容**：在线安装包与离线安装包可能采用不同流程，WPS 官网支持列表也不一定反映某个构建的实际安装器行为。

官方背景资料：
- [WPS 官方社区：有关 Win8/8.1 安装新版 WPS 的讨论](https://bbs.wps.cn/)
- [WPS 国际版官网](https://www.wps.com/)（网站的系统要求应与具体安装包行为分开看）

### 为什么会专门限制 Windows 8.x？

**目前没有可信的官方技术说明可以证实厂商的真实决策动机。** 一种可能是支持名单按特定系统版本设定，而不是简单的“Windows 7 或更高版本”；另一个可能原因是产品维护、兼容测试成本或既有安装器代码。但这些都只是解释假设，**不是已证实的厂商意图**。

## 原理：为什么兼容模式没能解决？

常规兼容模式并不会把 Windows 8.x 完整变成 Windows 7。安装器可以通过不同版本 API、文件版本资源以及多个进程自行检查操作系统；部分检查不一定受普通 Windows 7 兼容层影响。此次实验中，原版外层和内层安装器使用 Windows 7 兼容模式仍然遭到拦截。

反汇编显示，上述两个构建的内层 64 位程序具有相似的共享版本检查函数（虚拟地址 `0x1400C3280`，文件偏移 `0xC2680`）。将入口原始字节 `40 53 48 83 EC 20` 替换为 `B8 01 00 00 00 C3`（`mov eax,1; ret`），会让**这一项检查**直接返回成功，因此不必伪装整个 Windows 版本。

这一测试能够证明**安装界面前的拦截可由程序自身检查决定**，但不能证明 WPS 完全无其他系统依赖。具体是哪条 API/进程路径导致兼容模式失败，目前尚缺动态断点证据。详见 [技术分析](docs/Technical-Analysis.md)。

## 支持版本和测试情况

| 离线包 | 架构 | 原版表现 | 修补结果 |
| --- | --- | --- | --- |
| 中国大陆版 12.1.0.29158 | x64 | 系统不支持 | **进入安装界面** |
| 国际版 12.1.0.29162 | x64 | 系统不支持 | **进入安装界面** |

仅限 [已列出 SHA-256 的原始文件](docs/Supported-Builds.md)。32 位、在线安装器、其他构建和重新打包的安装器尚不支持。

## 使用方法

1. 从官方渠道获取对应的原版 **x64 离线安装包**。
2. 将 `Patch/01-Apply-Patch.cmd`、`Patch/Patch-WPS.ps1` 和原始安装包放在同一个目录。
3. 在 Windows 测试环境中运行 `01-Apply-Patch.cmd`，脚本会校验原包、提取内层安装器、验证并修补 **6 个字节**、再次校验结果。
4. 用生成的 `WPS_29158_x64_Win8x_Patched.exe` 或 `WPS_29162_x64_Win8x_Patched.exe` 进行独立测试。

推荐事先创建虚拟机快照。原文件不会被覆盖；修补后 EXE 的原厂数字签名失效。**不要为了使用本工具而关闭安全防护。** 安装、启动 WPS 或执行升级都可能另有兼容性问题。

## 项目边界

- 不使用扩展内核，不更换系统 DLL，也不修改 Windows 的全局版本报告。
- 不提供原版或已修补的 WPS 安装程序，用户须自行从合法渠道获得。
- 这是独立兼容性研究，与金山办公及 WPS 官方无关联。
- 目前未发布稳定版；欢迎附系统版本、文件 SHA-256、错误截图和日志提交 Issue（请删除隐私信息）。

## English summary

Experimental Windows 8/8.1 installer compatibility research for WPS Office x64 offline builds **12.1.0.29158** and **12.1.0.29162**. Despite the installers listing Windows 7 and Windows 10/11 as supported, users observed an OS-version block on Windows 8.x. A six-byte modification to the shared version-check function allowed the installer UI to open. Full installation and application compatibility remain **unverified**. No vendor binaries are redistributed.
