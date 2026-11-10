# 国际版离线：Windows 8.x 安装修补

本目录独立维护国际版离线方案，脚本、参考哈希、说明和测试均在本目录内，不导入其它版本目录。需要 Windows PowerShell 4.0 或更新版本。

## 使用

将原始 **x64 离线安装包**拖到 `Patch/01-Apply-Patch.cmd`，也可传入原始 AMD64 内层 EXE。保留同一 Patch 目录的三个文件。输出是修改六字节的官方内层安装器，继续使用官方安装流程。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Patch\Patch-WPS.ps1 -Installer "D:\setup.exe" -AnalyzeOnly
```

去掉 `-AnalyzeOnly` 即生成修补副本及 `.patch.json`，原包和已有输出不会被覆盖，生成副本的原厂签名失效。

## 多版本与验证

已知参考构建：**12.1.0.29162**，已重新定位并复现历史输出 SHA256，用户反馈已进入安装界面。尚不据此声称该构建完整安装已验证。

同一家族的新构建按 NSIS 块布局及完整 AMD64 结构动态定位，不依赖旧偏移或哈希白名单；未知构建标记未实机验证。当前支持非 solid 的 NSIS Deflate/未压缩布局，架构或代码结构改变时停止。

[适配与维护说明](docs/Multi-Version.md) · 测试：`tests/Test-WPSStandard.ps1`。

[参考构建与哈希](docs/Reference-Build.md)

[参考构建定位分析](docs/Analysis.md)
