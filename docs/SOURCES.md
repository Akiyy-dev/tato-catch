# 样本与工具来源

以下 URL、版本和哈希摘自 2026-10-20 的研究报告及下载脚本，用于复核历史样本。本清单没有重新联网确认下载地址可用性。下载后的文件应先核对 SHA-256；地址文件名与客户端内部版本可能不同。

## 客户端样本

| 样本 | 历史来源 | 字节数 | SHA-256 |
| --- | --- | ---: | --- |
| Windows MSI | [官方 Windows 下载链接](https://ttkdesk.shxcox.com/win/TatoTalk_3.01.200343.msi) | 46,138,880 | `5c29e10a2f917eed8638794f9164ce26788f57931db5e72801606b345fafcda3` |
| Windows 主程序 | 从上述 MSI 的内嵌 CAB 静态提取 `Tatotalk.exe` | 93,622,784 | `76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58` |
| Android APK | [当时官方页面提供的 Android 下载链接](https://downtato.ffvjei.com/android/TatoTalk-3.01.200106.apk) | 118,662,823 | `3769b604e4b7f66c9a44e00e9cab6e60d7723f4b6d2c357c396ae4bf198a54c4` |

Windows MSI 的 ProductVersion 是 `2.47.0324`，EXE 资源版本是 `2.22.0.0`；Android Manifest 为 `3.03.200105`、versionCode `30032`。这些值均与下载文件名存在差异，选取样本时以哈希为准。

样本及其提取物仅保存在本地 `research/samples/`，不纳入 Git 或源码 ZIP。源码包不授予这些第三方程序的再分发权。

## 固定工具下载

| 工具归档 | 官方发布链接 | 归档 SHA-256 |
| --- | --- | --- |
| Frida inject `17.24.3`，Windows x86_64 | [GitHub Release 的 EXE.XZ](https://github.com/frida/frida/releases/download/17.24.3/frida-inject-17.24.3-windows-x86_64.exe.xz) | `20e6f32ae69fa68d44fbdfcdf49c44219350e60447082b3389a29ec61a6dd996` |
| JADX `1.5.6` | [GitHub Release 的 ZIP](https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip) | `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974` |

上述哈希对应压缩归档。`fetch_frida_inject.py` 与 `fetch_jadx.py` 校验后只保留下载归档，使用工具还需解压；不能将归档哈希当作解压后 EXE/JAR 的哈希。

## Python 分析依赖

当前 `requirements-analysis.txt` 仅安装 `capstone==5.0.9` 和 `pefile==2024.8.26`。动态实验使用上文的 Frida CLI，不依赖 Python `frida` 包。`frida==17.24.3` 的 wheel 属于历史下载尝试，尚未安装成功；历史记录涉及的 Windows wheels 如下：

| 包及 wheel | 官方 PyPI 文件 | SHA-256 |
| --- | --- | --- |
| `frida-17.24.3-cp37-abi3-win_amd64.whl` | [下载](https://files.pythonhosted.org/packages/25/27/c7a6174982ccb0416d319374eacbc3a4ee9ed1f8864af97863199744a409/frida-17.24.3-cp37-abi3-win_amd64.whl) | `61f5a53b146e0e7755d6c2bfa5405e14fe2373818ae5d98105c4eeca3face7d1` |
| `capstone-5.0.9-py3-none-win_amd64.whl` | [下载](https://files.pythonhosted.org/packages/50/e6/6f06fdb6a9ed32b2f7cd9c036b92d5324112c3ef7080f2c71efc367d40dd/capstone-5.0.9-py3-none-win_amd64.whl) | `732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0` |
| `pefile-2024.8.26-py3-none-any.whl` | [下载](https://files.pythonhosted.org/packages/54/16/12b82f791c7f50ddec566873d5bdd245baa1491bac11d15ffb98aecc8f8b/pefile-2024.8.26-py3-none-any.whl) | `76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f` |

历史 `tools/wheels/` 中存在未完成的 `.whl.part`，且未形成 `sources.json`。应通过新的虚拟环境安装依赖，或重新下载并校验；不能将该残件作为已验证 wheel 使用。Python 包与本地工具不随源码 ZIP 发布。

Ghidra 历史使用版本为 `12.1.4`，JDK 为 `21.0.12.1`。它们由用户原先提供的本地安装使用，研究证据没有记录其安装归档的固定 SHA-256，因此不补造下载校验值。迁移后的 Ghidra 启动脚本通过参数接收 Ghidra 与 Java 路径。

## 证据与凭据边界

样本来源来自原研究的 `windows-triage.md`、`apk-findings.md` 及机器可读报告；工具来源来自 `fetch_frida_inject.py`、`fetch_jadx.py`、`fetch_python_tools.py` 和本地 pip 安装记录。原始生成报告与工具缓存按 [迁移规则](MIGRATION.md) 留在本地。

此处仅记录公开下载地址和固定校验值，不记录 GitHub token、账号、密码、会话密钥或聊天资料。上传仓库或 Release 时不应把本地认证配置加入发布清单。
