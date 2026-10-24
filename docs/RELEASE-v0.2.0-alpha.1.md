# Tato Catch v0.2.0-alpha.1

新增持续 Windows 新文本采集与 TG-forwarder 远端消息接入。

- 按已支持的更新类型读取任意新文本，不再要求固定测试标记。
- 使用已验证的原生会话 / 消息 ID，提供可用的发送者数字 ID；默认入站，可选包含发出消息。
- 持久 SQLite 队列，远端回执校验、幂等重试、429/网络/5xx 退避、401 停止和永久失败保留。
- 新增 listen、send-test、status 和 flush 命令。
- Token、消息、机器路径和运行状态仅保留本地；发布仍为经过隐私检查的源码包。

真实客户端到本机 HTTP 接收端的三条私聊验收通过，含两条独立的同文消息；退出后代码恢复。合成 Frida、子进程、持久队列与 HTTP 测试同时通过。更广的真实会话覆盖和远端部署仍需验收；不承诺覆盖所有内部消息路径，不回填离线历史。媒体、Linux 原生采集尚未实现。服务器入队回执不代表最终发布成功。

[使用指南](https://github.com/Akiyy-dev/tato-catch/blob/v0.2.0-alpha.1/docs/REMOTE-PUSH.md)
