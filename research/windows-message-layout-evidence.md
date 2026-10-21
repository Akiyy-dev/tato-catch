# 消息类型与正文字段的静态证据

样本：`Tatotalk.exe`，SHA-256 为 `76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58`。本报告只分析安装包中提取的文件，没有动态注入或读取进程和会话。

## 类型名称已由本样本验证

下表不是仅按 Telegram ID 猜测：每个访问器都包含对 `[RCX+8]` 的具体常量比较，同时在失败路径引用相应的 `_type == mtpc_...` 断言字符串。类型匹配后返回 `[RCX]` 的非空指针。

| 类型值 | 本样本断言名称 | 访问器 RVA |
| --- | --- | --- |
| `0x914fbf11` | `updateShortMessage` | `0x3dd6b0` |
| `0x16812688` | `updateShortChatMessage` | `0x3dd700` |
| `0x11f1331c` | `updateShortSentMessage` | `0x3dd840` |
| `0x78d4dec1` | `updateShort` | `0x3dd750` |
| `0x725b04c3` | `updatesCombined` | `0x3dd7a0` |
| `0x74ae4240` | `updates` | `0x3dd7f0` |
| `0x1f2b0afd` | `updateNewMessage` | `0x3eb0d0` |
| `0x62ba04d9` | `updateNewChannelMessage` | `0x3eb9e0` |
| `0x81ff9c4a` | `message` | `0x3e09a0` |

`0x3ded6320` 出现在空媒体包装对象的构造器 `0x3e4c20`，不能作为普通 Message 的类型门控值。

官方 Telegram 的[更新说明](https://core.telegram.org/api/updates)和[Updates 类型](https://core.telegram.org/type/Updates)可用于对照其中稳定的更新/容器 ID；当前官方短消息类型 ID 已经变化。这些名称和结构相似性不证明 TatoTalk 的服务端、账号授权或网络协议兼容 Telegram 或旧 Potato。

## 正文字段候选：短私聊与群聊

对于入口第二个参数指向的 wrapper，样本显示首个 8 字节是 payload 指针，`+8` 是 32 位类型值，包装对象的容器步长为 16 字节。

仅对类型 `0x914fbf11` / `0x16812688`：

| payload 相对位置 | 静态观察 |
| --- | --- |
| `+0x20` | 24 字节共享数组对象的第一个指针，复制时对其指向的 int 引用计数加一 |
| `+0x28` | 该对象第二个 word，数据指针候选 |
| `+0x30` | 该对象第三个 word，元素数候选 |

直接证据来自 `candidate_db95a0.c`：群聊分支取得 `FUN_1403dd700(param_2)` 的返回值，并把它的第 4、5、6 个 8 字节 word（偏移 `0x20/0x28/0x30`）拷贝到合成普通消息的 `0x48/0x50/0x58`；私聊分支取得 `FUN_1403dd6b0(param_2)` 的返回值，并把 `payload+0x20` 交给普通消息构造函数。未把 `updateShortSentMessage` 作为带新收到正文的短消息类型处理。

## 正文字段候选：普通消息与频道消息

对于 `0x1f2b0afd` / `0x62ba04d9` 更新，C 和访问器显示 `updatePayload+0x10` 是内嵌 Message wrapper。该内嵌 wrapper 的类型必须确认是 `0x81ff9c4a`，其首个指针指向 Message payload。

| Message payload 相对位置 | 静态观察 |
| --- | --- |
| `+0x48` | 与短消息字段拷贝目标一致的 24 字节共享数组对象 |
| `+0x50` | 数据指针候选 |
| `+0x58` | 元素数候选 |

## 一字节数组与 Qt 版本证据

Message payload 的虚表指向删除析构器 `0x3e0690`，后者调用析构体 `0x3e06d0`。在 RVA `0x3e082d`，析构体对 `MessageData+0x48` 取址，并于 `0x3e0831` 调用 `0x387f80`。

`0x387f80` 对对象第一个指针所指向的 int 引用计数减一，释放路径传递 `EDX=1`、`R8D=8` 到通用数组释放函数。该函数的断言路径保留 `Libraries/win64/Qt-6.11.0/include/QtCore/qarraydataops.h` 编译路径，同时断言 `this->d` 和其引用计数。这支持 **Qt 6.11.0 的一字节共享数组形态**，与 QByteArray/UTF-8 MTP string 相符，支持先比较 ASCII 测试前缀。

这尚未替代运行验证：第二/第三 word 的数据指针和元素数含义，以及实际正文编码，仍需用唯一标记的测试正文确认。不能仅因三 word 形态相似，就把所有 24 字节对象都当文本。

## 容器布局与分发证据

- `updates` / `updatesCombined` payload 的向量首地址读取自 `+0x18`，元素数读取自 `+0x20`，以 16 字节为步长分发到单条更新候选 `0xe52c40`。
- `updateShort` 把 `payload+0x10` 内嵌更新 wrapper 交给 `0xe52c40`。
- 输入类型字段的控制流比较分别获得 3、14、7、72 个常量；完整的常量、位置及限制写入 `windows-message-layout-evidence.json`。统计只追踪最初从 `[RDX+8]` 进入 EAX 的值，遇到覆盖、调用或不可解析分支即停止，因此不是完整语义 switch 恢复。

首轮受控验证应只按认可的类型和上述固定字段链读取，校验地址可读性与较小长度；先匹配 `TATO-PROBE-` 前缀，命中后才保存指定测试正文。不得通过堆扫描扩大采集范围。

原始证据：`windows-payload-accessor-evidence.json`、`ghidra-targeted-output/candidate_db95a0.c`、`candidate_e52050.c`、`candidate_e52c40.c`。
