# Tato Catch

TatoTalk 普通账号消息捕获的 Windows 研究工具。当前版本为 **0.1.0-alpha.2 研究预发布**。

| 能力 | 当前结果 |
| --- | --- |
| Windows 新消息文本 | 曾在受控实验中捕获固定测试文本，UTF-8 正确，探针正常移除 |
| 图片 / 媒体 | 已分析结构，受控探针未匹配；尚未取得图片或缩略图 |
| 长期监听、重连、去重、消息路由 | 尚未实现 |
| Linux 无桌面服务器监听 | 尚未实现；动态验证依赖已登录的 Windows 官方客户端 |

探针按指定 EXE 的 SHA-256、进程路径和函数字节进行校验，仅匹配固定示例标记。当前不是完整客户端或生产消息服务。TatoTalk 与其他应用的账号和协议兼容性没有得到确认。

## 目录与隐私

```text
research/               原创分析、准备脚本与限时探针
  ghidra-scripts/       定向反编译脚本
  samples/              本地样本（忽略）
  tools/                本地便携工具（忽略）
scripts/                环境准备、隐私检查与源码包构建
tests/                  离线测试与合成测试数据
docs/                   状态、样本来源与发布说明
```

原始运行记录、机器路径、账号资料和会话信息只保留本地，不进入 Git 或发布包。运行报告位于被忽略的研究输出中；由运行器注入客户端路径的临时 JS 在退出时删除。发布检查拒绝绝对机器路径和原始历史 fixtures。

## 环境准备

需要 Windows x64、Python 3.12+ 和已登录的官方 TatoTalk 客户端。Node.js、PowerShell 用于源码检查；Java 21、Ghidra 12.1.4 和 JADX 1.5.6 用于静态分析。

在仓库根目录执行：

```powershell
python scripts/bootstrap.py
python scripts/verify.py
python -m unittest discover -s tests -v
```

`bootstrap.py` 将依赖安装到忽略的工具目录，下载并校验 Frida CLI；不会登录、启动或附加客户端。源码 ZIP 不含第三方工具。

## 复现文本验证

仅支持以下 SHA-256 的官方 EXE：

```text
76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58
```

路径通过必填参数提供；保留 PID 路径匹配、文件哈希及函数字节校验。升级客户端后须重新分析，不能跳过版本校验。

```powershell
$client = Get-Process -Name Tatotalk | Select-Object -First 1
# 先核验模块与代码；没有消息 hook：
python research/run_windows_module_probe.py --target-exe $client.Path --pid $client.Id
# 四项 matches_on_disk_code 都为 true 后，启动限时文本实验：
python research/run_windows_module_probe.py --target-exe $client.Path --pid $client.Id --script windows-marked-text-probe.js --seconds 125 --marker TATO_TEXT_PROBE: --report windows-text-probe-new.json --ready-marker TATO_TEXT_READY
```

出现 `PROBE_READY` 后，从另一个测试账号发送通用示例文本 `TATO-PROBE-你好`。结果只写入本地报告，正常结束或超时会移除 hook。图片脚本使用通用说明 `TATO-IMG-PROBE`，尚未验证成功。

Ghidra 脚本必填 `-GhidraRoot`；Java 默认从 PATH 查找，也可通过 `-JavaExecutable` 指定。客户端和工具的本机安装位置无需写入源码。

## 构建与发布

```powershell
python scripts/verify.py
python -m unittest discover -s tests -v
python scripts/build_release.py
```

`dist/` 生成源码探针 ZIP 与 `SHA256SUMS`。构建使用与校验相同的白名单和隐私检查，不包含原始运行记录、安装包、工具、反编译输出或账号资料。

分支和 PR 运行离线检查；指向主分支的版本标签生成 GitHub 预发布。更多信息：[当前状态](docs/STATUS.md) · [来源](docs/SOURCES.md) · [发布范围](docs/MIGRATION.md) · [版本说明](docs/RELEASE-v0.1.0-alpha.2.md)
