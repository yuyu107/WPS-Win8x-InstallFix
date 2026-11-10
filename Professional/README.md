# 专业版：Windows 8.x 安装修补

本目录的脚本、说明与测试独立维护，不依赖其它版本目录。

**12.1.0.29161 已于 2026-11-10 在 Windows 8.1 完整安装成功。**

将原始专业版 EXE 拖到 `Patch/02-Apply-Pro-Patch.cmd`，保留同一 Patch 目录的三个文件。生成的官方安装器仅修改三个字节，保留重定位和官方安装流程。原包及已有输出不覆盖，输出签名失效。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Patch\Patch-WPSPro.ps1 -Installer "D:\WPSPro.exe" -AnalyzeOnly
```

去掉 `-AnalyzeOnly` 即生成修补副本和 `.patch.json`。需要 Windows PowerShell 4.0 或更新版本。

[成功方案与 ASLR 分析](docs/Analysis.md) · [多版本定位与维护](docs/Multi-Version.md) · 测试：`tests/Test-WPSPro.ps1`。

新构建按 PE32 KPacket 代码家族识别，结构改变或候选不唯一时停止。未知构建匹配成功不等同于完成安装实测。

[参考构建与哈希](docs/Reference-Build.md)
