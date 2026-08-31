# Email Outbox Worker 健康与监控

本文档说明 Email outbox worker 参与 `GET /health/ready` 的语义，以及 SMTP 延迟或队列积压时的运维判定方式。

## Readiness 语义

关键 worker 必须处于运行状态，并同时满足 heartbeat、最近成功 pass、连续失败次数和显式 unready 状态。heartbeat 只证明任务仍存活并在执行或等待外部操作；success 表示最近完成了一个没有基础设施错误的有界 pass。

Email outbox 的 readiness 不表示队列已清空。持续积压但仍在正常投递的实例应保持可接收请求；队列深度和最老待处理事件年龄需要作为独立容量指标监控。反过来，heartbeat 也不会无限掩盖无法完成 pass 的 worker：最近 success 超出预算后，readiness 仍会返回 503。

单条邮件投递失败若已成功写回 retry/dead-letter 状态，属于 outbox 正常处理结果，不会把整个 worker 标记为基础设施失败。领取、状态写回或保留清理等数据库错误会记录一次 retryable failure；连续达到 worker 策略阈值后 readiness 变为 503，后续成功 pass 会清除该失败状态。

## 时间预算

| 边界 | 当前值 | 语义 |
| --- | ---: | --- |
| SMTP provider 调用上限 | 30 秒 | 单次 `EmailSender::send` 的最长等待时间 |
| 批处理 heartbeat 周期 | 5 秒 | 批处理和保留清理进行中持续刷新存活信号 |
| Heartbeat 预算 | 45 秒 | 超过后判定 worker 没有继续运行或调度 |
| Success 预算 | 120 秒 | 超过后判定 worker 长期无法完成一个有界 pass |
| 新条目启动时间预算 | 5 秒 | 达到后不再领取下一条，已领取条目正常完成 |
| 单 pass 条目上限 | 100 条 | 防止极快的大积压形成无界循环 |

生产 Compose 每 10 秒轮询 readiness。探针频率不应被用作 SMTP 操作超时或队列耗尽期限；worker 自己的 heartbeat 与 success 预算才定义后台任务健康边界。

## 积压监控

可以用以下只读查询观察可投递积压和最老事件年龄。不要输出 `recipient`、`encrypted_code`、`claim_token` 或 `last_error`，这些字段不是容量指标，并可能包含敏感或内部信息。

```sql
SELECT
    COUNT(*) AS pending_count,
    EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::bigint AS oldest_pending_age_seconds
FROM email_outbox
WHERE processed_at IS NULL
  AND cancelled_at IS NULL
  AND dead_lettered_at IS NULL;
```

`pending_count` 持续增长或 `oldest_pending_age_seconds` 长期上升表示投递容量不足或 provider 故障，即使 readiness 仍为 200 也应告警。readiness 为 503 且日志中的 `unready_workers` 包含 `email_outbox` 时，优先检查数据库可用性、worker panic/退出、连续基础设施错误和最近一次成功 pass 是否超时。
