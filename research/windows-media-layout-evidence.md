# TatoTalk 媒体结构的样本内静态证据

仅分析安装包提取的 Windows EXE；没有读取进程、缓存、账号或会话数据。SHA-256 为 `76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58`。证据来自 .pdata 边界内完整 Capstone 反汇编，类型名称来自本 EXE 的断言字符串，不以 Telegram 公共类型值代替样本验证。

| wrapper 类型 | 本样本 tag | 访问器 RVA |
|---|---|---|
| messageMediaPhoto | `0xb5223b0f` | `0x3e4c90` |
| messageMediaDocument | `0x7c4414d3` | `0x3e4dc0` |
| photo | `0x9288dd29` | `0x3f1df0` |
| photoSize | `0x77bfb61b` | `0x3f2bb0` |
| photoCachedSize | `0xe9a734fa` | `0x3f2c00` |

上述访问器均比较 `[rcx+8]` 的 tag，成功后返回非空 `[rcx]`。失败路径通过 `_type == mtpc_...` 断言命名。

## 严格的照片识别链

1. 已验证的普通 Message payload `+0x60` 是媒体 wrapper 的首指针，`+0x68` 是 tag。构造器 `0x3e09f0` 的 `0x3e0a87..0x3e0aa4` 复制这两个字段。消费者 `0x8f2244` 直接对 Message payload `+0x60` 调用 `messageMediaPhoto` 访问器，确认媒体语义。
2. 仅当媒体 tag 是 `0xb5223b0f` 时，媒体 payload `+0x10` 为 flags，`+0x18` 是内嵌 Photo wrapper (`ptr,+8 tag`)。消费者 `0xdc1c3e..0xdc1c60` 在读取媒体后对 `+0x18` 验证 `photo` tag 并调用 `0x3f1df0`。
3. `photo` payload 的 `+0x30/+0x38/+0x40` 是三 word Qt vector，对应共享数据、元素首地址和数量。构造器 `0x3f1e40` 复制三个 word；序列化路径 `0x5952e0` 对 vector 以 16 字节 wrapper 步长遍历，按 `photoSize` 或 `photoCachedSize` tag 分发。
4. `photoSize` / `photoCachedSize` payload `+0x38` / `+0x3c` 是两项 32 位尺寸，多个消费函数作为尺寸相乘和传递；`photoSize+0x40` 为 32 位长度候选，`photoCachedSize+0x40` 是 Qt 一字节数组。缓存尺寸序列化在 `0x3f2a72` 对 `payload+0x40` 调用与 type 文本相同的一字节数组写函数 `0xb815c0`，可用于读取内嵌小图数据。它不保证存在，也不等于完整原图。

`photo` payload 的 `+0x18/+0x20` 是两个 64 位字段，`+0x28` 是 32 位字段，可能分别对应 id、access hash、date；本轮无需读取 access hash，语义也未通过运行验证。建议探针只读取 tag、尺寸、小图长度，首次发送测试图后再决定是否提取限长图片数据。

原始逐指令证据：`windows-media-layout-evidence.json`。可复现：`python tmp/tatotalk-research/inspect-windows-media-layout.py`。

## 图片说明 caption 的独立字段（媒体测试补充）

`messageMediaPhoto` payload 有独立的一字节数组字段 `+0x28/+0x30/+0x38`，受 `flags(+0x10)&2` 控制。它适合用于精确匹配用户给图片附加的 caption，不能仅检查 `MessageData+0x48`。

本样本生成解析器 `0x3e1920` 在 `0x3e1f8b` 比较 `0xb5223b0f`，命中跳往 `0x3e2124`，分配大小 `0x48`。随后：

- `0x3e21b5` 对 `payload+0x18` 读取 Photo wrapper，受 flags bit 0 控制。
- `0x3e21e2` 检查 flags bit 1；`0x3e21e8` 置 `r9d=0xb5286e24`，`0x3e21f4` 取 `payload+0x28`，`0x3e21f8` 调用已有正文路径使用的一字节 MTP string 读取器 `0xb81480`。
- 缺少 caption 标志时，`0x3e21ff..0x3e220b` 清零 `+0x28/+0x30/+0x38` 三 word。
- `0x3e2253` 检查 flags bit 2，并把可选 32 位值写到 `+0x40`（TTL 候选）。

原始 JSON 的 `construction_and_serialization` 追加了 `0x3e2124..0x3e2276` 的分支反汇编。

## 以文件发送图片时的 document caption

`messageMediaDocument` (`0x7c4414d3`) 与上述照片媒体的 caption 偏移一致：`payload+0x10` 为 flags，`+0x18` 为 Document wrapper，`+0x28/+0x30/+0x38` 是 caption QByteArray，由 `flags&2` 控制。

生成解析器 `0x3e1b6a` 比较 Document 媒体 tag，跳入 `0x3e1d36`。`0x3e1dea` 检查 flags bit 1，`0x3e1df0` 设置一字节 string 标记 `0xb5286e24`，`0x3e1dfc` 取 `payload+0x28`，`0x3e1e00` 调用 `0xb81480`。独立构造器 `0x3e5740` 将三个 word 写到 `+0x28/+0x30/+0x38`，并在 `0x3e57d9` 将外层 tag 写为 `0x7c4414d3`。原始 JSON 已追加两段逐指令证据。

## 媒体偏移的独立复核：从 Message tag 到 caption

媒体测试未命中后，重新检查完整函数 `0x8f2040..0x8f2518` 的寄存器流（逐指令已加入 JSON），不只依赖局部 `lea +0x60`：

1. `0x8f206f` 从 `[RDX+8]` 取 wrapper tag，`0x8f207a` 比较普通 Message 的 `0x81ff9c4a`。
2. 命中分支 `0x8f20ab` 把 `[RDX]` 读入 RDI，即 MessageData 指针，`0x8f20ae` 检查非空。
3. `0x8f20b7` 检查 `[RDI+0x10]&0x200`（媒体存在标志）。没有媒体时走 `0x8f23b3`，取 `MessageData+0x48` 正文。
4. 有媒体时 `0x8f20c4` 从 `[RDI+0x68]` 取 tag。Document 分支在 `0x8f20da` 对 `RDI+0x60` 调用 `0x3e4dc0`。Photo 分支经 `0x8f2239` 比较 `0xb5223b0f` 后，在 `0x8f2244` 对 `RDI+0x60` 调用 `0x3e4c90`。到 Photo 分支前 RDI 没有被覆盖。
5. Photo 访问器返回媒体 payload；`0x8f2259` 检查其 flags bit 1，`0x8f225f` 取 `payload+0x28` 作为 caption。

因此媒体偏移 `+0x60/+0x68` 与 caption 偏移 `+0x28` 的静态证据仍成立。当前运行事件媒体 tag 为 0 不能据此证明图片事件没有媒体，必须先确认这些事件实际对应用户发送的测试消息；可辅助记录普通 Message flags 的 `0x200` 位，而不读取额外聊天内容。
