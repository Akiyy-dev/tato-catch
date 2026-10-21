# Tato Catch v0.1.0-alpha.2

此研究预发布清理公开源码中的本地环境信息，并替代已撤回的早期版本。

- 移除原始运行报告和内部迁移工作记录。
- 客户端路径改为必填运行参数；工具位置通过参数或 PATH 提供。
- 保留目标文件哈希、PID 路径一致性和候选函数字节检查。
- 使用通用示例标记；原始实验记录只保留本地。
- 离线验证和构建都检查机器绝对路径，拒绝原始历史 fixtures。

发布附件为源码探针 ZIP 和 SHA256SUMS，不包含客户端、工具、账号资料、运行日志或反编译输出。

能力边界：Windows 文本提取曾在受控实验中成功；媒体、Linux 和持续消息服务尚未实现。此次修改没有重新执行动态捕获测试。

[使用说明](https://github.com/Akiyy-dev/tato-catch/blob/v0.1.0-alpha.2/README.md) · [研究状态](https://github.com/Akiyy-dev/tato-catch/blob/v0.1.0-alpha.2/docs/STATUS.md)
