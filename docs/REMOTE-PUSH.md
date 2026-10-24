# 连续文本采集与远端推送

## 服务端准备

按 [TG-forwarder 消息接入 API](https://github.com/Akiyy-dev/TG-forwarder/blob/main/docs/api.md#4-消息接入-api) 创建接入来源，保存仅返回一次的 `tgfi_` Token。为来源配置 Telegram、SafeW 或对外 API 目标；默认审核模式需要人工发布。服务器须完成消息接入数据库迁移。

客户端向完整端点 `/api/ingest/v1/messages` 提交 JSON。`200/202` 与匹配的 `status=queued` 回执表示接入成功，不表示规则、审核或下游发布完成。请在服务器历史中核对最终结果。

## 配置

环境变量覆盖本地 JSON 配置。可复制 `docs/config.example.json` 为 `.local/config.json`，在本地填值，再执行：

```powershell
python -m tatocatch send-test --config .local/config.json
python -m tatocatch listen --config .local/config.json
```

| JSON 字段 | 环境变量 | 含义 |
| --- | --- | --- |
| target_exe | TATO_TARGET_EXE | 已支持的官方 EXE 路径，采集必填 |
| ingest_url | TATO_INGEST_URL | HTTPS 服务根地址或完整接入端点 |
| ingest_token | TATO_INGEST_TOKEN | 独立消息接入凭据，推送必填 |
| state_dir | TATO_STATE_DIR | 本地私有状态目录，默认 `.local/state` |
| conversation_id | TATO_CONVERSATION_ID | 原生身份不可用时的逻辑采集流，默认 `tatotalk-stream` |
| conversation_name | TATO_CONVERSATION_NAME | 可选静态显示标签，不能替代原生聊天名称 |
| http_timeout | TATO_HTTP_TIMEOUT | 请求超时，默认 30 秒，范围 1–120 |
| include_outgoing | TATO_INCLUDE_OUTGOING | 默认 false，只采集入站；设 true 也采集本账号发出的新文本 |

HTTPS 验证始终开启，不跟随重定向；URL 不接受内嵌凭据、查询参数或片段。HTTP 仅允许本机 loopback 测试。配置目录要保持私有；每个账号和接入来源使用独立状态目录，不要在同一队列上切换到另一个来源的 Token。

## 运行与恢复

```powershell
# 正常持续运行，自动发现匹配路径的进程并在断开后重试：
python -m tatocatch listen
# 仅本地采集，先不联网，稍后可补发：
python -m tatocatch listen --capture-only
# 查看本地队列计数，不访问客户端或网络：
python -m tatocatch status
# 补发当前到期的待发记录；尚在退避期的记录继续保留：
python -m tatocatch flush
# 修正配置后，显式重试保留的永久失败：
python -m tatocatch flush --retry-failed
```

这些命令都支持 `--config`。`listen --pid` 可锁定进程，但客户端重启后 PID 会变化；省略 PID 时按已配置的 EXE 路径重新发现。多个同路径进程需要明确选择。`--include-outgoing` 可覆盖配置启用发出消息采集。

消息在发出首个 HTTP 请求前先写入 SQLite。网络异常、429 和 5xx 使用完全相同的内容与幂等键重试，遵循 Retry-After 并采用有上限的指数退避。401 停止采集和发送、保留队列，修正 Token 后重新运行。409/422 等永久错误保留为失败，避免不断重发无效数据。

队列绑定接入端点，拒绝把已有队列静默改发到另一个地址。最多保存 100,000 条未完成记录（包括失败项）；磁盘或持久化异常会停止采集。状态目录中的消息未加密，应按本机私有数据保护。控制台仅打印状态和数量，不打印正文、Token 或服务端错误原文。

## 身份、幂等与范围

已验证的普通和短消息布局用于读取原生消息 ID；会话区分 `user:<id>`、`chat:<id>`、`channel:<id>`，入站私聊使用发送者而非接收者自身。发送者为数字 ID，不解析显示名称。

会话 ID 加上本地持久命名空间，消息 ID 使用原生 ID；重连和重试仍使用相同幂等键。同文但不同消息 ID 或不同会话的消息不会合并。字段缺失时退回配置的逻辑采集流和采集会话序号；此类记录不能保证跨重连去重。不要删除命名空间或状态目录来重试旧消息。

不发送未经证明时间语义的原生整数时间字段；省略 API timestamp，由服务器首次接收时确定，重试始终省略。编辑消息不在当前新消息更新类型范围内。

监听仍依赖固定版本的官方客户端、现有四个已校验候选入口和已识别的新文本更新。不能保证所有聊天、静音状态、补收或内部路径均被覆盖；客户端退出后程序会重新寻找进程，离线期间未触发 hook 的消息不会自动回填。媒体与图片说明尚未打通，Linux 只可作为远端 TG-forwarder 接收服务器。

## 实机验收

先运行 send-test，在远端确认出现测试记录；再运行 listen，发送两条不同文本、连续两条相同正文，以及不同私聊 / 群的文本。核对远端条数、会话和发送者。断开网络后查看 pending 增加，恢复后确认队列清空且无重复；检查最终下游发布结果。未配置真实地址和 Token 前，本仓库的本地测试不能替代这一步。
