# StarAuto GHL Webhook Listener

Minimal AWS Lambda that verifies GHL webhook signatures, checks a Redis allowlist, and enqueues the payload for a worker.

## Environment variables

- `REDIS_URL` (required)
- `GHL_WEBHOOK_PUBLIC_KEY` (required, PEM)
- `GHL_WEBHOOK_ALLOWLIST_KEY` (optional, default: `ghl:webhook:allowlist`)
- `GHL_WEBHOOK_CONTACT_QUEUE_NAME` (optional, default: `ghl-inbound-contact-update`)
- `GHL_WEBHOOK_CONTACT_JOB_NAME` (optional, default: `ghl.contact.update`)
- `GHL_WEBHOOK_OPPORTUNITY_QUEUE_NAME` (optional, default: `ghl-opportunity-sync`)
- `GHL_WEBHOOK_OPPORTUNITY_JOB_NAME` (optional, default: `ghl.opportunity.sync`)
- `GHL_WEBHOOK_QUEUE_NAME` (legacy fallback for contact queue)
- `GHL_WEBHOOK_JOB_NAME` (legacy fallback for contact job)
- `GHL_WEBHOOK_CONTACT_DEBOUNCE_MS` (optional, default: `3500`)
- `GHL_WEBHOOK_JOB_ATTEMPTS` (optional, default: `5`)
- `GHL_WEBHOOK_JOB_BACKOFF_MS` (optional, default: `1000`)
- `GHL_WEBHOOK_ANALYTICS_TTL_SECONDS` (optional, default: `86400`)
- `GHL_WEBHOOK_ANALYTICS_BUCKET_MINUTES` (optional, default: `360`)

## Build and deploy

```bash
sam build
sam deploy --guided
```

### Staging VPC defaults

The staging Lambda uses the following VPC settings (also stored in `samconfig.toml`):

- Subnets: `subnet-0c3eb48074c9eb460`, `subnet-01f346da002897e45`
- Security group: `sg-0fd9f6b3c0ded8db2`

### Production deployment

- Uses the same private subnets as staging (`subnet-0c3eb48074c9eb460`, `subnet-01f346da002897e45`).
- Attaches to the production ECS security group `sg-08b80a28bdddf7270` so the Lambda can reach the production Redis cluster (`sg-0d8764f140bca583e` allows that SG).
- Secrets source: `arn:aws:secretsmanager:us-east-2:214046906223:secret:starauto-production-secrets-TjSyhm` (must expose `REDIS_URL` and `GHL_WEBHOOK_PUBLIC_KEY`).

Deploy with:

```bash
sam build
sam deploy --config-env production
```

## Notes

- Auth decisions are strict and fail-closed:
	- Lambda only queues when `SISMEMBER ${GHL_WEBHOOK_ALLOWLIST_KEY}:<appId> <locationId>` returns true.
	- Any missing/non-allowlisted `(appId, locationId)` pair is returned as `ignored/location_not_enabled`.
- The allowlist is stored as Redis sets under `${GHL_WEBHOOK_ALLOWLIST_KEY}:<appId>` with `locationId` members.
- Supported inbound event types: `ContactCreate`, `ContactUpdate`, `ContactTagUpdate`, `ContactDelete`, `OpportunityCreate`, `OpportunityUpdate`, `OpportunityDelete`, `OpportunityStageUpdate`.
- Queue names should match worker BullMQ queues (contact vs opportunity). Jobs are debounced by job id and removed on completion or failure.
- Contact events include rollup metadata (`rollupCount`, `rollupFirstSeenAt`, `rollupLastSeenAt`) so workers can persist one inbox row per coalesced burst.
- Analytics counters are stored in hourly Redis hashes under `ghl:analytics:hour:YYYYMMDDHH` with `location:<locationId>:event:<eventType>:allowed|blocked` fields.
- If `git push` fails with a permissions error in Codespaces, retry with `env -u GITHUB_TOKEN git -C /workspaces/ghl-webhook-handler push origin <branch>`.
