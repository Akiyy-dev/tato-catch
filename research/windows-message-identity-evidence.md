# 消息身份字段静态证据

只适用于已支持的官方样本 SHA-256 `76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58`。以下为静态机器码、生成格式器和断言名称证据；不包含真实运行记录。

| 字段 | 普通 Message payload | 短私聊 / 群聊 payload |
| --- | --- | --- |
| flags | uint32 +0x10 | uint32 +0x10 |
| message id | uint32 +0x18 | uint32 +0x14 |
| sender | flags&0x100 时 uint32 +0x1c | 入站私聊及群聊 uint32 +0x18 |
| peer | wrapper +0x20 | 私聊 counterpart +0x18；群 ID +0x1c |
| native date | uint32 +0x40 | uint32 +0x40；未转换为 API 时间 |

`0x5811fe` 至 `0x581232` 将格式器 `0x448b20` 注册到 Message 构造器 `0x81ff9c4a`，格式器命名 flags、flags2、id、from_id、to_id。反序列化入口 `0x3df438` 在 `0x3df711` 写 id 到 +0x18；getter `0x79de90` 对同一类型读取 +0x18。短消息合成普通消息时将 +0x14 复制到该字段，证明两种形式应共享原生 ID。

Peer wrapper 首指针指向 payload，+8 为 tag，peer payload 的数字 ID 为 uint32 +0x10。断言名称和访问器如下：

| tag | 断言名称 | 访问器 RVA |
| --- | --- | --- |
| 0x9db1bc6d | mtpc_peerUser | 0x3d7c80 |
| 0xbad0e5bb | mtpc_peerChat | 0x3d7cd0 |
| 0xbddde532 | mtpc_peerChannel | 0x3d7d20 |

Resolver `0x725c00` 为三类 peer 增加不同 kind 位。Conversation resolver `0x79ddb0` 对 outgoing 使用 peer，对群 / 频道使用 peer，对入站 user peer 使用 flags&0x100 的 sender。入站私聊的 peer 可能代表接收账号自身，不能直接用作聊天对象。

生成格式器命名 bit1 为 out：普通 `0x448bc8`、短私聊 `0x442609`、短群聊 `0x443019`。短私聊 +0x18 命名 user_id (`0x4429c9`)，短群 +0x18 命名 from_id (`0x4433d9`)，+0x1c 命名 chat_id (`0x443414`)。

原生 date 虽有字段名，但 epoch 与时区语义尚未另行证明；推送时省略 timestamp，避免未经验证的时间转换。
