# TatoTalk Windows 静态初检

分析日期：2026-10-20。仅分析官方公开安装包；没有安装或启动样本，没有登录、注入进程、读取用户配置或会话内容。

## 样本来源与可复核标识

- 下载地址：https://ttkdesk.shxcox.com/win/TatoTalk_3.01.200343.msi
- 安装包：`samples/TatoTalk_3.01.200343.msi`
- 安装包大小：46,138,880 字节
- 安装包 SHA-256：`5c29e10a2f917eed8638794f9164ce26788f57931db5e72801606b345fafcda3`
- 主程序：`samples/windows-extracted/Tatotalk.exe`
- 主程序大小：93,622,784 字节
- 主程序 SHA-256：`76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58`

方法：WindowsInstaller COM `OpenDatabase(path, 0)` 只读查询 MSI 表；通过 `msi.dll` 的只读数据库与流读取函数导出内嵌 CAB；使用 Windows `expand.exe` 静态展开 CAB；Python 标准库解析 PE 头、导入目录和选定字符串。没有调用 msiexec，没有执行 MSI CustomAction。

## 文件和版本元数据

MSI ProductName 为 `TatoTalk`，ProductVersion 为 `2.47.0324`，Manufacturer 为 `TatoTalk`。主 EXE 文件资源的 FileVersion、ProductVersion 均为 `2.22.0.0`，ProductName、FileDescription 均为 `TatoTalk Desktop`，CompanyName 为 `Horsemen Technologies SA`。主 EXE 的 Authenticode 检查结果为 `NotSigned`。

下载名 `3.01.200343`、MSI 版本和 EXE 资源版本并不一致；这些只是各自读取到的元数据，不能仅据此确定实际界面版本或兼容性。

MSI File 表只有以下 5 个文件，没有发现 Electron 的 app.asar / chrome_elf.dll 或单独的 Qt DLL：

| 文件 | 大小（字节） |
| --- | ---: |
| Tatotalk.exe | 93,622,784 |
| Updater.exe | 159,232 |
| Uninstall.exe | 180,224 |
| VMProtectSDK64.dll | 119,296 |
| icon256.ico | 121,541 |

CustomAction 仅记录名称和类型：`DIRCA_TARGETDIR`（307）、`ERRCA_CANCELNEWERVERSION`（19）、`ERRCA_UIANDADVERTISED`（19）、`VSDCA_FolderForm_AllUsers`（51）。未执行这些动作。

## 框架判断与消息处理候选

主程序为 PE32+、Machine `0x8664`（x86_64）、Windows GUI 子系统。CLR Runtime 数据目录 RVA 和 size 均为 0。`.qtmimed` 节以及 `QCoreApplication`、`QApplication`、`QWidget`、`QObject` 字符串，支持其为原生 Qt/C++ 客户端的判断。没有证据支持把它按 .NET 或 Electron 程序分析。

导入表明确依赖 `VMProtectSDK64.dll`，同时存在 `VMProtect` 字符串。这只能确认依赖或 SDK 标记存在，尚未证明整个程序被加壳或哪些函数被保护。

以下位置是主 EXE 的**文件偏移**，不是可直接挂接的函数地址。它们为后续反汇编中的字符串交叉引用提供入口：

| 静态线索 | 文件偏移 | 可用于后续确认的方向 |
| --- | --- | --- |
| 带 `feedUpdate@MainWidget` 的 MSVC RTTI | `0x51febb0`、`0x552f2c0` | 更新分发及消息进入客户端数据层的位置 |
| `Unexpected: Type in applyUpdateNoPtsCheck()` | `0x4b74a60` | 单条更新处理分支 |
| `Unexpected: Type in applyUpdatesNoPtsCheck()` | `0x4b74ac8` | 更新集合处理分支 |
| `{ updateNewMessage` | `0x4aaf108` | 普通消息更新类型的诊断或序列化路径 |
| `{ updateNewChannelMessage` | `0x4aaf4d8` | 频道或超级群消息更新类型的诊断或序列化路径 |
| `{ updateShortMessage` | `0x4aae730` | 短消息更新类型 |
| `{ updateShortChatMessage` | `0x4aae7f8` | 群聊短消息更新类型 |
| `{ updates_getDifference` | `0x4ab9bd0` | 状态差量同步、补收相关处理 |

同时存在 `MTPDupdateNewMessage`、`MTPDupdateNewChannelMessage`、`MTPmessage`、`MTPupdates_difference` 类型字符串，以及 `SourceFiles/mtproto/connection.cpp`、`session.h`、`mainwidget.cpp`、`history/history_item.cpp` 等编译路径字符串。它们支持继续从更新处理层研究，但不能证明协议与 Telegram、旧 Potato 或 Telethon 兼容。

存在 SQLite 字符串，但这可能来自程序中的库；尚未确定消息保存于 SQLite，也没有查看任何本地数据库或账户文件。

## 下一步和最小工具需求

目前 PowerShell 和 Python 已完成获取、展开、PE 结构与字符串初检。未给用户安装任何工具。

Windows 分析下一步适合使用 **Ghidra**（现有 Java 21 可用）：导入主 EXE，围绕上述字符串做交叉引用，确定真实的更新分发函数和消息对象布局。不需要为该 Windows 样本先安装 ILSpy 或 Electron ASAR 工具。

动态验证时才考虑 Frida 或 x64dbg，并先用独立测试账户和带唯一标记的测试消息验证。本轮没有完成动态验证，因此尚不能声称能够接收、提取或完整补收消息。

机器可读完整证据见 `windows-triage.json`；PE 版本资源见 `windows-exe-metadata.json`；候选字符串及文件偏移见 `windows-selected-strings.json`。
