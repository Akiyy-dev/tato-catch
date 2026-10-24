# Tato Catch

在已登录的 Windows 官方 TatoTalk 客户端中持续采集新文本，通过 TG-forwarder 的消息接入 API 推送到远端。当前为 **0.2.0-alpha.1 研究预发布**，仅支持已校验的客户端版本。

| 能力 | 状态 |
| --- | --- |
| 连续文本采集 | 已实现已识别的新消息更新路径，默认只接收入站消息 |
| 远端推送 | POST `/api/ingest/v1/messages`，独立 `tgfi_` 接入 Token |
| 断网恢复 | 本地 SQLite 持久队列、重试、回执和幂等 ID |
| 会话与发送者 | 已验证布局提供私聊 / 群 / 频道 ID 和可用的发送者数字 ID，无名称解析 |
| 媒体、Linux 原生采集 | 尚未实现 |

本版已在真实客户端验证三条入站私聊经持续采集到本机 HTTP 接收端，其中两条同文消息保持独立，消息 / 会话 / 发送者 ID 均已取得。合成 Frida、子进程和持久队列测试同时通过；更广的会话覆盖率及你的真实远端部署仍须验收。不会回填历史，也不保证覆盖所有客户端内部分发路径。

## 快速开始

需要 Windows x64、Python 3.12+，并保持官方客户端登录。先在仓库根目录准备工具：

```powershell
python scripts/bootstrap.py
```

在远端 TG-forwarder 管理后台进入“消息接入”，创建来源并保存 `tgfi_` Token，再配置该来源的目标和发布模式。这里使用接入 Token；拉取 API Token 和管理员密码不能替代它。

在本地 PowerShell 设置当前终端的配置：

```powershell
$client = Get-Process -Name Tatotalk | Select-Object -First 1
$env:TATO_TARGET_EXE = $client.Path
$env:TATO_INGEST_URL = 'https://forwarder.example.com'
$secret = Read-Host 'TG-forwarder 接入 Token' -AsSecureString
$env:TATO_INGEST_TOKEN = [System.Net.NetworkCredential]::new('', $secret).Password
python -m tatocatch send-test
python -m tatocatch listen
```

将示例域名替换为你的服务域名。出现 `"event": "ready"` 后开始采集；`"state": "delivered"` 表示服务器已接受入队。按 Ctrl+C 停止并移除本工具的 hook，待发消息保留在本地。

完整配置、恢复方式和能力边界见 [远端推送指南](docs/REMOTE-PUSH.md)。旧的固定标记实验仍保留在 `research/` 中。

## 隐私与发布

真实路径、Token、账号资料、运行日志、消息和队列只保留本地。默认状态目录 `.local/state` 被忽略；源码 ZIP 不包含客户端安装包、工具、原始记录或反编译输出。发布检查拒绝机器绝对路径和原始历史 fixtures。

```powershell
python scripts/verify.py
python -m unittest discover -s tests -v
python scripts/build_release.py
```

构建产物为 `dist/` 中的源码工具包及 `SHA256SUMS`。Node.js 和 PowerShell 用于离线检查；动态运行无需安装 Ghidra。

[当前状态](docs/STATUS.md) · [样本来源与哈希](docs/SOURCES.md) · [发布范围](docs/MIGRATION.md) · [版本说明](docs/RELEASE-v0.2.0-alpha.1.md)
