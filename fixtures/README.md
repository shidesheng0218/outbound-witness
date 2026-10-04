# Outbound Witness benchmark fixtures

这些夹具只包含事件元数据、路径和哈希，不包含文件正文。

首批场景：

- `benign-git-push.json`：正常开发工具访问代码并连接已知远端。
- `sensitive-batch-upload.json`：读取 `.env`、`.git`，创建归档后连接新域名。
- `archive-upload-with-consent.json`：用户对指定目录和目标域名授予临时授权。授权绑定 `bin/example-ai-agent` 的文件内容 SHA-256（不是路径），请从仓库根目录运行 evaluate，以便解析到该文件。

测试目标不是判断某个工具“是否恶意”，而是验证它的出站行为是否透明、可解释、可阻断。

