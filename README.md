# WPS-Win8x-InstallFix

**WPS Office Windows 8 / 8.1 安装限制修复与技术研究**（无需扩展内核）

部分较新的 WPS Office 安装器出现了令人困惑的现象：**仍允许 Windows 7 安装，却在 Windows 8 / Windows 8.1 上直接提示操作系统不受支持**。本仓库记录该现象、分析其安装器的系统版本检查，并提供普通版、国际版与专业版的安装检查补丁。普通版、国际版和专业版均已加入基于代码结构的多版本定位。

> **最新结果（2026-11-10）：专业版 12.1.0.29161 已在 Windows 8.1 使用修补后的官方安装器成功完成安装。** 最终仅修改外层 EXE 的 3 字节，不重组安装包、不替换 DLL。

## WPS 对 Windows 8.x 的具体限制

| 系统 | 此次研究所涉及离线安装包的行为 |
| --- | --- |
| Windows 7 | 安装器列为允许的操作系统之一 |
| Windows 8 (NT 6.2) | 安装器存在拦截 Windows 8.x 的版本检测逻辑；需进一步区分各系统的独立完整测试 |
| Windows 8.1 (NT 6.3) | 原版测试时提示不支持；专业版 29161 修补后已完成安装 |
| Windows 10 / 11 | 安装器列为允许的操作系统 |

原有补丁涉及两个不同地区的 **x64 离线包**：中国大陆版 `12.1.0.29158` 和国际版 `12.1.0.29162`。两者原版均被报告在 Windows 8.x 上拦截，使用相同原理修改后均已进入安装界面。**不能简单断言所有国际版都兼容或都不兼容**：在线安装包与离线安装包可能采用不同流程，WPS 官网支持列表也不一定反映某个构建的实际安装器行为。

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
| 专业版 12.1.0.29161 | 外层安装器为 PE32 / x86 | 系统不支持 | **Windows 8.1 完整安装成功** |

普通版/国际版自动遍历 NSIS 数据块、识别 AMD64 内层 EXE 并定位检查函数；专业版自动定位同类 PE32 KPacket 代码。三者均不再因已支持家族内的函数偏移变化而复用旧地址。未知构建只有通过全部结构校验才会修补，且标记为未实机验证。这里的 x86 是安装器架构，不等同于安装后的所有 WPS 组件架构。详见 [支持情况](docs/Supported-Builds.md)。

## 普通版 / 国际版：多版本定位

1. 下载仓库完整源码，保持 `Patch/01-Apply-Patch.cmd`、`Patch/Patch-WPS.ps1` 和 `Patch/WPSStandard.Core.ps1` 在一起。
2. 将官网原版 **x64 离线安装包**拖到 `01-Apply-Patch.cmd`。也支持直接传入原版 AMD64 内层安装器。
3. 脚本沿 NSIS 数据块边界寻找内层 EXE，再按完整函数结构、RIP 相对配置字符串、共享调用、AMD64 函数元数据和重定位表识别检查函数。
4. 成功后生成修补内层 EXE 和 `.patch.json`。29158/29162 保持原输出名和预期 SHA256，其它匹配构建使用原文件名加 `_x64_Win8x_Patched.exe`。

```powershell
# 只分析；NSIS 解压用临时文件，结束后清理，不生成安装器输出
powershell -NoProfile -ExecutionPolicy Bypass -File .\Patch\Patch-WPS.ps1 -Installer "D:\WPS_Setup_new.exe" -AnalyzeOnly
```

新版本不要求先登记完整哈希。原有 29158/29162 哈希用于额外校验，未知构建通过结构守卫才会生成，并标记未实机验证。只支持当前非 solid 的 NSIS Deflate/未压缩数据块布局和 AMD64 检查函数家族，结构改变时停止。原文件与已有输出不会被覆盖，输出数字签名失效。

[普通版与国际版自动适配详情](docs/Standard-Multi-Version.md)

## 专业版：多版本定位

1. 下载仓库完整源码，保持 `Patch` 下三个专业版文件在一起：`02-Apply-Pro-Patch.cmd`、`Patch-WPSPro.ps1`、`WPSPro.Core.ps1`。
2. 将原始专业版安装包拖到 `02-Apply-Pro-Patch.cmd`；29161 也可放在脚本旁直接运行 CMD。
3. 脚本检查 PE、函数特征、系统判断配置字符串、共享调用与接口跳板、重定位覆盖范围。
4. 成功后生成 `<原文件名>_Win8x_Patched.exe` 及 `.patch.json` 记录。运行生成的 EXE 即可使用原官方安装流程。

只分析、不生成安装器：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Patch\Patch-WPSPro.ps1 -Installer "D:\WPSPro.exe" -AnalyzeOnly
```

支持 Windows PowerShell 4.0（Windows 8.1 自带），不需要 Python、7-Zip 或扩展内核。原包与已有输出不会被覆盖。输出 JSON 区分已实测原包和仅匹配代码家族的构建；更换编译方式、检查逻辑、架构或出现多个候选时明确拒绝，不能保证任意未来版本都自动适配。

[专业版成功方案与 ASLR 修复](docs/Professional-Installer.md) · [多版本适配说明](docs/Multi-Version.md)

## 项目边界

国际版在线安装目前另有 [两层检查 Test3 实验](docs/Online-Installer.md)：启动检查已定位，后续下载包也有系统限制；自动内存修补方案尚待完整安装实测，不计入已成功列表。

- 不使用扩展内核，不更换系统 DLL，也不修改 Windows 的全局版本报告。
- 不提供原版或已修补的 WPS 安装程序，用户须自行从合法渠道获得。
- 这是独立兼容性研究，与金山办公及 WPS 官方无关联。
- 欢迎附系统版本、文件 SHA-256、补丁 JSON 和安装日志提交 Issue（请删除隐私信息）。

## English summary

WPS Office installer compatibility fixes for Windows 8/8.1. Regular and international x64 installers now use dynamic NSIS block traversal and structural AMD64 predicate detection; reference hashes for 12.1.0.29158 and 12.1.0.29162 remain additional integrity checks. Professional 12.1.0.29161 has completed installation on Windows 8.1 using the original official installer with a three-byte, relocation-safe change. A structural detector supports matching PE32 KPacket builds without fixed file offsets, rejects changed/ambiguous layouts, and labels untested builds. No vendor binaries are redistributed.
