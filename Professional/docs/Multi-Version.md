# 多版本适配

## 当前路线

| 安装包类型 | 识别与修改 |
| --- | --- |
| 专业版原生 PE32 KPacket | 扫描可执行节内的系统支持函数代码家族，动态定位 RVA 和文件偏移 |

专业版新构建的文件名、版本号、文件大小或函数所在偏移改变，不需要仅为这些变化重新填地址。绝对地址及 call 位移可以变化；指令结构和语义守卫必须仍满足当前家族。

这不是任意版本通用反编译器：如果厂商改变架构、编译器生成的指令结构、检查逻辑或接口布局，检测会明确拒绝。不能用“找到 Windows 字样”或单独的函数头作为修补依据。

## 运行

```powershell
# 只分析，返回 JSON 到控制台，不修改文件
powershell -NoProfile -ExecutionPolicy Bypass -File .\Patch\Patch-WPSPro.ps1 -Installer "D:\WPSPro.exe" -AnalyzeOnly

# 识别并生成副本
powershell -NoProfile -ExecutionPolicy Bypass -File .\Patch\Patch-WPSPro.ps1 -Installer "D:\WPSPro.exe"
```

也可把 EXE 拖到 `02-Apply-Pro-Patch.cmd`。所有专业版脚本应放在一起。

未知完整哈希通过家族验证后允许生成，控制台明确标识未实机验证；JSON 的 `InstallationVerified=false`。不依赖人为批准白名单，但不会把未测试构建写成安装成功。

## 写入约束

- 先校验 PE32 节映射、唯一候选、语义字符串、相对调用范围、共享调用与数据引用。
- 要求原始两个绝对操作数对应 HIGHLOW 重定位项；拒绝覆盖入口或成功返回区的重定位。
- 复制原包后再次核对复制件 SHA256，避免分析期间源文件变化。
- 只写入 `56 EB 6A`，原包保持不变；输出已存在即停止。
- 已知 29161 还核对最终输出 SHA256。
- 输出 `.patch.json` 记录输入/输出 SHA256、profile、RVA、偏移和安装实测状态。

`InstallationVerified=true` 仅指精确 29161 原包在 Windows 8.1 的安装已由用户确认。模板匹配成功与独立版本的实测结论分别记录。

## 维护与测试

`tests/Test-WPSPro.ps1` 构造不含 WPS 完整程序的合成 PE，检查函数位置变化、ASLR 和拒绝路径。GitHub Actions 在 Windows PowerShell 上解析并运行测试。

遇到不匹配版本，应根据具体文件扩展新的家族模板和对应测试，而不是删掉校验或复用上个版本的固定偏移。提交 Issue 时提供版本、原包 SHA256、系统版本和错误信息即可；不要提交厂商完整二进制或含个人路径的原始诊断日志。

