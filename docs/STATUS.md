# 研究状态

版本：`0.1.0-alpha.1`。这是源码探针与静态分析工具的预发布，现有成果仍是受控研究验证。

## 已有证据

以下结果来自 2026-10-20 的历史实验；迁移、离线验证和打包不会自动重新执行客户端探针。

| 能力 | 结果 | 证据 |
| --- | --- | --- |
| Windows 固定测试文本提取 | 成功 1 次，匹配 `TATO-PROBE-20261020-你好`；UTF-8，26 字节 | [文本结果](../research/fixtures/windows-text-probe-2.json) |
| 文本实验收尾 | 历史报告记录探针卸载，4 处代码字节恢复，helper 正常退出 | [收尾检查](../research/fixtures/windows-post-probe-cleanup.json)、[汇总](../research/fixtures/verified-result.json) |
| 媒体探针第 1 轮 | 超时，`matched=false` | [结果](../research/fixtures/windows-media-probe.json) |
| 媒体探针第 2 轮 | 超时，`matched=false` | [结果](../research/fixtures/windows-media-probe-2.json) |
| 媒体探针第 3 轮 | 超时，`matched=false` | [结果](../research/fixtures/windows-media-probe-3.json) |
| 媒体访问器探针第 4 轮 | 超时，`matched=false`，`counts={}`；helper 正常退出，记录 `hooksDetached=true` | [结果](../research/fixtures/windows-media-accessor-result.json) |

第四轮已有完整落盘结果，运行区间为 UTC `2026-10-20T15:38:41.680Z` 至 `15:41:31.683Z`。四轮媒体实验均未证明图片、文件或缩略图捕获成功。

静态分析取得了 Windows 更新分发候选、正文与媒体对象字段的样本内证据；Android APK 已做 ZIP、AXML、DEX 初检。静态字段证据不能代替运行时能力验证，也不证明 TatoTalk 与 Telegram 的网络协议或账号授权兼容。

## 适用范围

- Windows 探针绑定历史样本 SHA-256：`76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58`。
- `run_windows_module_probe.py` 默认目标保留为 `D:\ttt\Tatotalk.exe`，并核验指定 PID 对应的进程路径、文件哈希及候选代码字节。它仍是限时探针；本次迁移没有新增通用消息监听器。
- 文本探针仅导出固定测试文本；媒体探针仅匹配固定测试 caption，并限制可能读取的小图数据量。
- 仓库及源码发布不包含客户端、账号目录、会话、聊天数据库或登录资料。历史 JSON 中的 PID、地址和本地路径属于实验上下文，不代表当前进程状态。

## 尚未实现或验证

- 长期运行服务、自动连接恢复、持续消息接收。
- 会话与消息标识、来源识别、消息路由、去重和补收。
- 媒体捕获成功及原图下载。
- Linux 部署与 Linux 客户端捕获；现有动态证据依赖 Windows 官方客户端。
- Android 运行时正文捕获。

`research/` 的历史 Markdown 报告保留各阶段的当时结论，其中“下一步”“尚未验证”等文字应按报告阶段理解。当前能力边界以本页为准。软件构建、Git 集成和发布进度必须以对应操作的实际输出为准，本页不将其视为已经完成。
