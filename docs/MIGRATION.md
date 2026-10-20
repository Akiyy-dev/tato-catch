# 迁移记录与核验规则

源研究目录：`D:\TG-forwarder\tmp\tatotalk-research`。

目标工作目录：`D:\tato-catch`；远端为 [Akiyy-dev/tato-catch](https://github.com/Akiyy-dev/tato-catch)。迁移采用复制方式，保留源目录及其内容作为备份。迁移完成后的维护、构建和 Git 操作以新目录为准。

本文规定复制及验收范围。是否已完成复制、验证、push、merge 或 Release，应以实际命令输出与远端结果为准；本文件本身不构成完成证明。

## 版本管理范围

目标结构：

```text
tato-catch/
  README.md
  VERSION                         # 0.1.0-alpha.1
  requirements-analysis.txt
  scripts/
    bootstrap.py
    verify.py
    build_release.py
  docs/
    STATUS.md
    SOURCES.md
    MIGRATION.md
    RELEASE-v0.1.0-alpha.1.md
  research/
    *.py                          # 原研究根目录脚本
    *.ps1
    *.js
    *.md                          # 原阶段性分析报告
    ghidra-scripts/
    fixtures/                     # 下列 8 个历史结果 JSON
```

`research/fixtures/` 只收录以下历史证据，保留内容与实验时间语境：

1. `windows-text-probe-2.json`
2. `windows-post-probe-cleanup.json`
3. `windows-runtime-inspection.json`
4. `verified-result.json`
5. `windows-media-probe.json`
6. `windows-media-probe-2.json`
7. `windows-media-probe-3.json`
8. `windows-media-accessor-result.json`

原研究根目录中的其余生成 JSON、CSV 和日志留作本地研究资料，不进入源码发布。历史 Markdown 引用的部分原始输出需要在本地复现或从保留的研究资料中查看；这些引用不表示输出均已纳入仓库。`fixtures` 仅用于离线回归与记录历史结果，不表示当前客户端仍处于相同状态。

## 本地保留及忽略范围

- 客户端安装包、CAB、APK、EXE、DLL、图标等样本：`research/samples/`。
- 下载的 Frida、JADX、wheels、解压后的 Python 包与安装记录：`research/tools/`。
- Ghidra 的项目、home、settings、cache、temp：`research/ghidra-projects/`、`ghidra-home/`、`ghidra-settings/`、`ghidra-cache/`、`ghidra-temp/`。
- 第三方反编译结果：`research/decompiled/`、`research/ghidra-targeted-output/`。
- 除上述 8 个 fixtures 外的原始运行报告、静态分析生成 JSON/CSV、`*.log`、`*.output.txt`、下载残件、`__pycache__`、虚拟环境、发布构建目录。
- 本地环境变量、凭据、账号及会话资料、聊天数据库、运行数据。

不得从 `D:\ttt` 复制账号资料或将该目录当作迁移来源。探针脚本里的默认程序路径仅标识授权实验目标，不代表该目录内容属于项目。

## 复制核验

迁移验收应保存以下证据：

- 对源研究目录与目标本地副本建立相对路径、文件数量、字节数及 SHA-256 清单；逐项确认未改写的复制文件内容一致。
- 核验 8 个 fixtures 与源文件逐字节一致；保留固定测试文本及四轮媒体未命中的原始结论。
- 对必要的路径改动单独审查差异，避免将“迁移后修改过的脚本”与“原样复制的证据”混为一谈。源研究文件保持原样。
- 查看 Git 暂存清单及忽略匹配结果，确认样本、第三方工具、缓存、反编译物、运行数据和凭据未进入提交。
- 在目标目录执行离线验证；构建源码 ZIP 后检查文件清单并验证 `SHA256SUMS`。验证脚本与打包过程不应启动或附加 TatoTalk 进程。
- 完成远端操作后另行核实提交、分支、标签、合并结果及 Release 资产；只有实际成功的步骤才可报告为完成。

本地研究资料可能包含大型二进制与可重新生成的数据库，应核验完整性后保留在被忽略的目录中；无需通过 Git 或 Release 分发这些内容。迁移不删除源备份。

## 迁移后的行为约束

- PowerShell 脚本使用 `$PSScriptRoot` 定位研究目录；Ghidra 和 Java 路径由参数提供。
- 保留 `run_windows_module_probe.py` 的 `D:\ttt\Tatotalk.exe` 默认目标、指定 PID 校验、已知 SHA-256 绑定及候选代码字节校验。
- 保留限时、固定测试文本/caption 与卸载探针的实验设计，不将迁移描述为新增持续监听服务。
- 依赖与样本校验信息见 [SOURCES.md](SOURCES.md)；当前能力和未完成项见 [STATUS.md](STATUS.md)。
