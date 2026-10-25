# WPS-Win8x-InstallFix

适用于部分 WPS Office x64 离线安装包的 Windows 8 / Windows 8.1 安装兼容性研究项目。无需扩展内核或替换系统 DLL。

## 当前验证情况

| 版本 | 架构 | 测试结果 |
|---|---|---|
| 12.1.0.29158 中国大陆离线版 | x64 | 修改后成功进入安装界面 |
| 12.1.0.29162 国际离线版 | x64 | 修改后成功进入安装界面 |

**尚未完成**全部安装、文字/表格/演示运行、更新、卸载等验证；进入安装界面不代表完整兼容。

## 使用方法

从官方渠道获取原版离线安装包，将其与 `Patch/01-Apply-Patch.cmd`、`Patch/Patch-WPS.ps1` 放在同一目录，运行 CMD 脚本。仅接受已知 SHA-256 的两个 x64 构建；修改原内层安装器副本中的六个字节，再校验生成文件的 SHA-256。

建议在具有快照的 Windows 8.x 虚拟机中先测试。修改后的 EXE 将失去原厂数字签名，不要为了测试关闭系统安全防护。

技术原理与哈希信息见 `docs/Technical-Analysis.md` 与 `docs/Supported-Builds.md`。

## 注意事项

- 不支持 32 位安装包、在线安装器、其他构建号或重新封装的 EXE。
- 不提供 WPS 原版或修改后的完整 EXE。
- 该工具不改 Windows 内核、系统 DLL 或全局系统版本。正式执行安装器仍会修改软件安装相关的正常系统配置。
- 独立兼容性研究，与 WPS 官方无关联。

## English summary

Experimental Windows 8 / 8.1 installer compatibility patch for selected WPS Office x64 offline installers (builds 29158 and 29162). Both were user-tested to reach the installer UI; full compatibility has not yet been verified. WPS binaries are not redistributed.
