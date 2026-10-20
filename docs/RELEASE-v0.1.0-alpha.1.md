# v0.1.0-alpha.1

Tato Catch 首个研究工具预发布，将原先的 TatoTalk 可行性研究整理为独立的源码探针工具包，便于复核脚本、安装分析依赖和构建源码归档。此文件是发布说明，不表示 Git 标签或 GitHub Release 已创建。

## 内容

- Windows 客户端静态分析、版本绑定的限时 Frida 探针及 Ghidra 定点分析脚本。
- Android APK 结构初检与 DEX 调用引用检查脚本。
- 分阶段分析报告、8 个精选历史结果 JSON、样本与工具来源清单。
- 分析依赖准备、离线校验与源码归档构建入口。

PowerShell 脚本按自身目录定位研究文件，Ghidra/JDK 路径通过参数提供。动态探针保留历史目标路径、样本 SHA-256 和进程校验。

## 能力与限制

2026-10-20 的受控 Windows 实验成功提取过 **1 条固定测试文本**。媒体实验 **4 轮均超时、未命中**，其中第四轮访问器探针已有完整结束结果。详见 [STATUS.md](STATUS.md) 和对应历史 fixtures。

当前没有长期运行服务、通用消息监听器、会话/消息标识、路由、去重、断线恢复或补收能力。Linux 捕获与部署尚未实现；Android 运行时捕获也未验证。

此版本交付可阅读和复核的研究源码，不提供 GUI 或独立客户端安装包。

## 发布资产

预定资产：

- `tato-catch-0.1.0-alpha.1-source-probe-kit.zip`
- `SHA256SUMS`：记录上述 ZIP 的 SHA-256。

ZIP 只打包项目源码、文档与精选历史 fixtures。客户端安装包/EXE、第三方工具与依赖二进制、账号/会话、聊天数据、Ghidra 项目缓存、反编译输出和其他本地运行资料不随包发布。

下载后可在 Windows PowerShell 中计算归档哈希，并与 `SHA256SUMS` 对比：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\tato-catch-0.1.0-alpha.1-source-probe-kit.zip
Get-Content -LiteralPath .\SHA256SUMS
```

本发布说明不预填测试通过数、ZIP 校验值或远端操作状态。应在离线验证和构建完成后使用实际结果生成校验清单，并在上传后核对 Release 资产。
