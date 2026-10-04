# Session Agent fixture

仅用于验证受控 Session：

```bash
docker build -t outbound-witness/session-fixture:local fixtures/session-agent
ow session start --workspace ./demo-project --image outbound-witness/session-fixture:local -- /bin/sh -c 'test ! -e .env && printf changed > changed.txt && exit 7'
```

预期：容器退出码为 `7`；`.env` 没有进入隔离副本；`changed.txt` 只出现在 Session diff 中，直到用户执行 `ow session apply` 才会写回宿主。

