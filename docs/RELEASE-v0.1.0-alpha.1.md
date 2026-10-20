# v0.1.0-alpha.1

Tato Catch 首个研究预发布：将 TatoTalk 捕获研究独立整理为可复核、可构建的 Windows 源码探针工具包。

## 本次内容

- Windows 静态分析、版本绑定的限时 Frida 探针和 Ghidra 定点分析脚本。
- Android APK / DEX 初检脚本、原创分析文档与 8 份历史验证结果。
- 便携分析环境准备、离线源码检查、安全打包测试和确定性 ZIP 构建。
- GitHub PR 校验与标签预发布工作流。

## 验证与能力

19 个 Python、6 个 JS、2 个 PowerShell、8 个 JSON 通过离线检查，14 项打包测试通过；构建和发布不启动或附加 TatoTalk 客户端。

历史 Windows 实验曾成功提取 **1 条固定测试文本**。媒体实验 **4 轮均未匹配**，尚未捕获测试图片、缩略图或原图。Linux / Android 运行时捕获、持续监听、路由、重连和去重仍未实现。

当前动态探针仍绑定 `D:\ttt\Tatotalk.exe` 及已核验的 SHA-256，保留 PID 路径和函数字节校验。详见 [当前状态](https://github.com/Akiyy-dev/tato-catch/blob/v0.1.0-alpha.1/docs/STATUS.md) 和 [使用说明](https://github.com/Akiyy-dev/tato-catch/blob/v0.1.0-alpha.1/README.md)。

## 下载

- `tato-catch-0.1.0-alpha.1-source-probe-kit.zip`：源码、文档和历史证据；内含逐文件 SHA-256 manifest。
- `SHA256SUMS`：ZIP 的 SHA-256 校验清单。

本预发布提供研究源码，不提供 GUI 或独立客户端安装包；客户端、第三方工具二进制、账号 / 会话、聊天资料、缓存和反编译输出不包含在资产中。

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\tato-catch-0.1.0-alpha.1-source-probe-kit.zip
Get-Content -LiteralPath .\SHA256SUMS
```
