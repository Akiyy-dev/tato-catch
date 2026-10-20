# Tato Catch

TatoTalk 普通账号消息捕获的 Windows 研究工具，从 TG-forwarder 中独立迁移。当前版本为 **0.1.0-alpha.1 研究预发布**。

| 能力 | 当前结果 |
| --- | --- |
| Windows 新消息文本 | 已捕获一次固定测试文本，UTF-8 正确，探针正常移除 |
| 图片 / 媒体 | 已分析结构，四轮受控探针未匹配；尚未取得测试图片或缩略图 |
| 长期监听、重连、去重、消息路由 | 尚未实现 |
| Linux 无桌面服务器监听 | 尚未实现；本仓库的动态验证依赖已登录的 Windows 官方客户端 |

程序按指定 EXE 的 SHA-256、进程路径和函数字节进行校验，仅匹配固定测试标记。它不是完整客户端、登录协议实现或生产消息服务。TatoTalk 和 Potato 的账号、二维码及协议兼容性没有得到确认。

## 目录

```text
research/               Python、PowerShell、Frida JS 探针和原创分析
  fixtures/             历史文本成功 / 媒体未命中的小型证据快照
  ghidra-scripts/       定向反编译脚本
  samples/              本地样本（不进入 Git / Release）
  tools/                本地便携工具（不进入 Git / Release）
scripts/                环境准备、离线校验和源码包构建
docs/                   当前状态、样本来源、迁移和发布记录
```

## 环境准备

需要 Windows x64、Python 3.12+ 和已登录的官方 TatoTalk 客户端。`node`、PowerShell 用于源码检查；Java 21、Ghidra 12.1.4 和 JADX 1.5.6 仅用于后续静态分析。

```powershell
Set-Location D:\tato-catch
python scripts/bootstrap.py
python scripts/verify.py
python -m unittest discover -s tests -v
```

`bootstrap.py` 将分析依赖安装到 `research/tools/static-python`，下载并校验固定版本 Frida 注入工具，再解压。它不登录、不启动或附加客户端。本机迁移已保留这些便携工具；源码 ZIP 不包含第三方工具。

## 复现文本验证

已验证的客户端路径为 `D:\ttt\Tatotalk.exe`，SHA-256 为：

```text
76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58
```

当前探针仍绑定该路径与版本；移动或升级客户端后先重新分析，不能直接跳过校验。独立研究目录的迁移不会移动正在使用的客户端及其账号目录。

```powershell
Get-Process -Name Tatotalk | Select-Object Id, Path
# 用上一步的真实 PID 替换 1234，先进行无消息 hook 的代码核验：
python research/run_windows_module_probe.py --pid 1234
# 仅在上述结果四项 matches_on_disk_code 均为 true 后，启动 120 秒文本实验：
python research/run_windows_module_probe.py --pid 1234 --script windows-marked-text-probe.js --seconds 125 --marker TATO_TEXT_PROBE: --report windows-text-probe-new.json --ready-marker TATO_TEXT_READY
```

看到 `PROBE_READY` 后，从另一个账号发送 `TATO-PROBE-20261020-你好`。结果写入 `research/windows-text-probe-new.json`，正常完成或超时会移除 hook。进程 PID 会变化，不能复用历史 PID。

图片相关脚本仅供继续排查，标记为 `TATO-IMG-PROBE-20261020`；历史四轮均未匹配，不能将静态字段识别当成图片接收成功。详见 [当前状态](docs/STATUS.md)。

## 构建与发布

```powershell
python scripts/verify.py
python -m unittest discover -s tests -v
python scripts/build_release.py
```

构建产物在 `dist/`：源码探针工具包 ZIP 和 `SHA256SUMS`，不包含 TatoTalk 安装包、反编译输出、工具二进制、账号资料或运行日志。

PR 和分支推送会运行离线校验；合并后的版本标签 `v*` 会再次校验并生成 GitHub 预发布。当前发布说明为 [v0.1.0-alpha.1](docs/RELEASE-v0.1.0-alpha.1.md)。

更多信息：[样本与工具来源](docs/SOURCES.md) · [迁移记录](docs/MIGRATION.md)
