# StarAuto GHL Webhook Listener

Minimal AWS Lambda that verifies GHL webhook signatures, checks a Redis allowlist, and enqueues the payload for a worker.

## Environment variables

- `REDIS_URL` (required)
- `GHL_WEBHOOK_PUBLIC_KEY` (required, PEM)
- `GHL_WEBHOOK_ALLOWLIST_KEY` (optional, default: `ghl:webhook:allowlist`)
- `GHL_WEBHOOK_QUEUE_NAME` (optional, default: `ghl-contact-update`)

## Build and deploy

```bash
sam build
sam deploy --guided
```

## Notes

- The allowlist is stored as a Redis set. The Lambda uses `SISMEMBER` on the allowlist key with the `locationId`.
- The queue name should match the worker's BullMQ queue.
