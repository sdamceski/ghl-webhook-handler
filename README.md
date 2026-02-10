# StarAuto GHL Webhook Listener

Minimal AWS Lambda that verifies GHL webhook signatures, checks a Redis allowlist, and enqueues the payload for a worker.

## Environment variables

- `REDIS_URL` (required)
- `GHL_WEBHOOK_PUBLIC_KEY` (required, PEM)
- `GHL_WEBHOOK_ALLOWLIST_KEY` (optional, default: `ghl:webhook:allowlist`)
- `GHL_WEBHOOK_QUEUE_NAME` (optional, default: `ghl-inbound-contact-update`)
- `GHL_WEBHOOK_ANALYTICS_TTL_SECONDS` (optional, default: `86400`)
- `GHL_WEBHOOK_ANALYTICS_BUCKET_MINUTES` (optional, default: `360`)

## Build and deploy

```bash
sam build
sam deploy --guided
```

## Notes

- The allowlist is stored as Redis sets. The Lambda uses `SISMEMBER` on `${GHL_WEBHOOK_ALLOWLIST_KEY}:<appId>` with the `locationId`.
- The queue name should match the worker's BullMQ queue.
- Analytics counters are stored in hourly Redis hashes under `ghl:analytics:hour:YYYYMMDDHH` with `location:<locationId>:event:<eventType>:allowed|blocked` fields.
