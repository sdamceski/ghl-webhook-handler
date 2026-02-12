import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import crypto from 'crypto';
import { Queue } from 'bullmq';
import IORedis from 'ioredis';

type WebhookEnvelope = Record<string, unknown>;

type WebhookIds = {
  locationId: string | null;
  appId: string | null;
  contactId: string | null;
};

type EnvConfig = {
  redisUrl: string;
  allowlistKey: string;
  queueName: string;
  jobName: string;
  publicKey: string;
  bullmqPrefix: string;
  debounceMs: number;
  jobAttempts: number;
  jobBackoffMs: number;
};

type AddJobOptions = NonNullable<Parameters<Queue['add']>[2]>;

type AnalyticsStatus = 'allowed' | 'blocked';

type RollupJobData = {
  source: 'ghl';
  eventType: string;
  inboundEventId: number | null;
  webhookId: string | null;
  locationId: string | null;
  appId: string | null;
  contactId: string | null;
  payloadHash: string;
  payload: Record<string, unknown>;
  rollupKey?: string;
  rollupJobId?: string;
};

type RollupRecord = {
  jobId: string;
  updatedAt: number;
  data: RollupJobData;
};

const ANALYTICS_KEY_PREFIX = 'ghl:analytics:hour';
const DEFAULT_ANALYTICS_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_ANALYTICS_BUCKET_MINUTES = 360;
const DEFAULT_BULLMQ_PREFIX = '{starauto-bull}';
const ROLLUP_TTL_MS = 60_000;
const CONTACT_EVENT_TYPES = new Set(['ContactCreate', 'ContactUpdate', 'ContactTagUpdate']);
const CONTACT_ROLLUP_PREFIX = 'ghl:contact-rollup';

const isRecord = (value: unknown): value is WebhookEnvelope =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const coerceString = (value: unknown): string | null => {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text.length ? text : null;
};

const parsePositiveIntEnv = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Invalid ${name}; expected a positive integer`);
  }
  return parsed;
};

const normalizeEventType = (value: string | null): string | null => {
  if (!value) return value;
  if (value === 'ContactUpdate') return value;
  const normalized = value.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  if (normalized === 'contactupdate' || normalized === 'contactupdated') {
    return 'ContactUpdate';
  }
  if (normalized === 'contactdelete' || normalized === 'contactdeleted') {
    return 'ContactDelete';
  }
  return value;
};

const extractWebhookIds = (payload: unknown): WebhookIds => {
  if (!isRecord(payload)) {
    return { locationId: null, appId: null, contactId: null };
  }
  return {
    locationId: coerceString(payload.locationId ?? payload.location_id ?? payload.companyId ?? payload.company_id),
    appId: coerceString(payload.appId ?? payload.app_id),
    contactId: coerceString(payload.contactId ?? payload.contact_id ?? payload.id)
  };
};

const extractWebhookId = (payload: unknown): string | null => {
  if (!isRecord(payload)) {
    return null;
  }
  return coerceString(payload.webhookId ?? payload.webhook_id ?? payload.eventId);
};

const getSignatureHeader = (headers: Record<string, string | undefined> | undefined): string | undefined => {
  if (!headers) return undefined;
  const direct = headers['x-wh-signature'] ?? headers['X-Wh-Signature'];
  if (direct) return direct;
  const key = Object.keys(headers).find((header) => header.toLowerCase() === 'x-wh-signature');
  return key ? headers[key] : undefined;
};

const decodeSignature = (signature: string | undefined): string | undefined => {
  if (!signature) return signature;
  if (!signature.includes('%')) return signature;
  try {
    return decodeURIComponent(signature);
  } catch {
    return signature;
  }
};

const verifyWebhookSignature = (rawBody: Buffer | null, signature: string | undefined, publicKey: string): boolean => {
  if (!rawBody || !signature) {
    return false;
  }

  try {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(rawBody);
    verifier.end();
    return verifier.verify(publicKey, signature, 'base64');
  } catch {
    return false;
  }
};

const parseBody = (body: string | null | undefined): WebhookEnvelope | null => {
  if (!body) return null;
  try {
    const parsed = JSON.parse(body) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const computePayloadHash = (payload: Record<string, unknown>): string =>
  crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');

const buildJobId = (appId: string | null, locationId: string | null, contactId: string): string => {
  const appSegment = appId ? appId.trim() : 'noapp';
  const locationSegment = locationId ? locationId.trim() : 'noloc';
  return `${appSegment}:${locationSegment}:${contactId}`;
};

const getEnvConfig = (): EnvConfig => {
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) {
    throw new Error('Missing REDIS_URL');
  }

  const publicKey = process.env.GHL_WEBHOOK_PUBLIC_KEY;
  if (!publicKey) {
    throw new Error('Missing GHL_WEBHOOK_PUBLIC_KEY');
  }

  const debounceRaw = process.env.GHL_WEBHOOK_CONTACT_DEBOUNCE_MS;
  const parsedDebounce = debounceRaw ? Number(debounceRaw) : Number.NaN;
  const debounceMs = Number.isFinite(parsedDebounce) && parsedDebounce > 0 ? parsedDebounce : 3500;

  return {
    redisUrl,
    publicKey,
    allowlistKey: process.env.GHL_WEBHOOK_ALLOWLIST_KEY ?? 'ghl:webhook:allowlist',
    queueName: process.env.GHL_WEBHOOK_QUEUE_NAME ?? 'ghl-inbound-contact-update',
    jobName: process.env.GHL_WEBHOOK_JOB_NAME ?? 'ghl.contact.update',
    bullmqPrefix: process.env.GHL_WEBHOOK_BULLMQ_PREFIX ?? DEFAULT_BULLMQ_PREFIX,
    debounceMs,
    jobAttempts: parsePositiveIntEnv('GHL_WEBHOOK_JOB_ATTEMPTS', 5),
    jobBackoffMs: parsePositiveIntEnv('GHL_WEBHOOK_JOB_BACKOFF_MS', 1000)
  };
};

const enqueueDebouncedJob = async (params: {
  queue: Queue;
  jobName: string;
  jobId: string;
  data: Record<string, unknown>;
  delayMs: number;
  addOptions?: Partial<AddJobOptions>;
}): Promise<void> => {
  const { queue, jobName, jobId, data, delayMs, addOptions } = params;
  const existing = await queue.getJob(jobId);
  if (existing) {
    const state = await existing.getState();
    if (state === 'delayed' || state === 'waiting') {
      await existing.updateData(data);
      await existing.changeDelay(delayMs);
      return;
    }
    if (state === 'completed' || state === 'failed') {
      try {
        await existing.remove();
      } catch {
        return;
      }
    }
  }

  await queue.add(jobName, data, {
    ...(addOptions ?? {}),
    jobId,
    delay: delayMs,
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 1000 }
  });
};

const buildRollupKey = (appId: string | null, locationId: string | null, contactId: string | null): string | null => {
  if (!appId || !locationId || !contactId) {
    return null;
  }
  return `${CONTACT_ROLLUP_PREFIX}:${appId}:${locationId}:${contactId}`;
};

const parseRollupRecord = (raw: string | null): RollupRecord | null => {
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as RollupRecord;
    if (!parsed || typeof parsed.jobId !== 'string' || !parsed.data) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
};

const writeRollupRecord = async (redis: IORedis, key: string, record: RollupRecord): Promise<void> => {
  await redis.set(key, JSON.stringify(record), 'PX', ROLLUP_TTL_MS);
};

const buildRollupJobId = (rollupKey: string): string => {
  const digest = crypto.createHash('sha256').update(rollupKey).digest('hex').slice(0, 16);
  return `ghl_contact_rollup_${digest}_${Date.now()}`;
};

const parseAnalyticsTtlSeconds = (): number => {
  const raw = process.env.GHL_WEBHOOK_ANALYTICS_TTL_SECONDS;
  if (!raw) return DEFAULT_ANALYTICS_TTL_SECONDS;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_ANALYTICS_TTL_SECONDS;
};

const parseAnalyticsBucketMinutes = (): number => {
  const raw = process.env.GHL_WEBHOOK_ANALYTICS_BUCKET_MINUTES;
  if (!raw) return DEFAULT_ANALYTICS_BUCKET_MINUTES;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_ANALYTICS_BUCKET_MINUTES;
};

const getAnalyticsKey = (date: Date): { key: string; expireAt: number } => {
  const bucketMs = parseAnalyticsBucketMinutes() * 60 * 1000;
  const bucketStartMs = Math.floor(date.getTime() / bucketMs) * bucketMs;
  const bucketStart = new Date(bucketStartMs);
  const year = bucketStart.getUTCFullYear();
  const month = String(bucketStart.getUTCMonth() + 1).padStart(2, '0');
  const day = String(bucketStart.getUTCDate()).padStart(2, '0');
  const hour = String(bucketStart.getUTCHours()).padStart(2, '0');
  const key = `${ANALYTICS_KEY_PREFIX}:${year}${month}${day}${hour}`;
  const expireAt = Math.floor(bucketStartMs / 1000) + parseAnalyticsTtlSeconds();
  return { key, expireAt };
};

const incrementAnalytics = async (
  redis: IORedis,
  status: AnalyticsStatus,
  locationId: string | null,
  eventType: string | null
): Promise<void> => {
  const normalizedLocation = locationId ?? 'invalid';
  const normalizedEvent = eventType ?? 'unknown';
  const { key, expireAt } = getAnalyticsKey(new Date());
  const field = `location:${normalizedLocation}:event:${normalizedEvent}:${status}`;

  try {
    const pipeline = redis.multi();
    pipeline.hincrby(key, field, 1);
    pipeline.expireat(key, expireAt);
    await pipeline.exec();
  } catch (error) {
    console.warn('[ghl-webhook] analytics increment failed', { error });
  }
};

const isAllowedLocation = async (
  redis: IORedis,
  allowlistKey: string,
  locationId: string | null,
  appId: string | null
): Promise<boolean> => {
  if (!locationId || !appId) {
    return false;
  }
  const scopedKey = `${allowlistKey}:${appId}`;
  const isMember = await redis.sismember(scopedKey, locationId);
  return isMember === 1;
};

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const {
    redisUrl,
    allowlistKey,
    queueName,
    jobName,
    publicKey,
    bullmqPrefix,
    debounceMs,
    jobAttempts,
    jobBackoffMs
  } = getEnvConfig();

  console.log('[ghl-webhook] request received', {
    requestId: event.requestContext?.requestId,
    hasBody: Boolean(event.body),
    isBase64Encoded: event.isBase64Encoded
  });

  const rawBody = event.body ? Buffer.from(event.body, event.isBase64Encoded ? 'base64' : 'utf8') : null;
  const payload = parseBody(rawBody ? rawBody.toString('utf8') : null);
  const rawEventType = payload ? coerceString(payload.type) ?? 'unknown' : 'unknown';
  const eventType = normalizeEventType(rawEventType) ?? rawEventType;
  const { locationId, appId, contactId } = extractWebhookIds(payload);

  const redis = new IORedis(redisUrl);
  let queue: Queue | null = null;

  try {
    if (!payload) {
      console.warn('[ghl-webhook] invalid payload');
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'error', reason: 'invalid_payload' })
      };
    }

    const signature = decodeSignature(getSignatureHeader(event.headers));
    if (!verifyWebhookSignature(rawBody, signature, publicKey)) {
      console.warn('[ghl-webhook] invalid signature');
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'error', reason: 'invalid_signature' })
      };
    }

    if (!CONTACT_EVENT_TYPES.has(eventType)) {
      console.log('[ghl-webhook] ignored unsupported event type', { eventType });
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 202,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ignored', reason: 'unsupported_event_type' })
      };
    }

    if (!contactId) {
      console.warn('[ghl-webhook] missing contact id');
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'error', reason: 'contact_id_required' })
      };
    }

    console.log('[ghl-webhook] extracted ids', { locationId, appId, contactId });

    const allowed = await isAllowedLocation(redis, allowlistKey, locationId, appId);
    if (!allowed) {
      console.log('[ghl-webhook] ignored location', { locationId, allowlistKey });
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 202,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ignored', reason: 'location_not_enabled' })
      };
    }

    queue = new Queue(queueName, { connection: redis, prefix: bullmqPrefix });

    const baseJobData: RollupJobData = {
      source: 'ghl',
      eventType,
      inboundEventId: null,
      webhookId: extractWebhookId(payload),
      locationId,
      appId,
      contactId,
      payloadHash: computePayloadHash(payload),
      payload
    };

    const retryOptions: Pick<AddJobOptions, 'attempts' | 'backoff' | 'removeOnComplete' | 'removeOnFail'> = {
      attempts: jobAttempts,
      backoff: { type: 'exponential', delay: jobBackoffMs },
      removeOnComplete: { count: 100 },
      removeOnFail: { count: 1000 }
    };

    const rollupKey = buildRollupKey(appId, locationId, contactId);
    if (rollupKey) {
      const existing = parseRollupRecord(await redis.get(rollupKey));
      const rollupJobId = buildRollupJobId(rollupKey);

      if (existing?.jobId) {
        try {
          const existingJob = await queue.getJob(existing.jobId);
          if (existingJob) {
            await existingJob.remove();
          }
        } catch (error) {
          console.warn('[ghl-webhook] failed to remove existing rollup job', {
            rollupKey,
            jobId: existing.jobId,
            error
          });
        }
      }

      const rolledUp: RollupJobData = { ...baseJobData, rollupKey, rollupJobId };
      await writeRollupRecord(redis, rollupKey, {
        jobId: rollupJobId,
        updatedAt: Date.now(),
        data: rolledUp
      });

      await queue.add(jobName, rolledUp, {
        ...retryOptions,
        jobId: rollupJobId,
        delay: debounceMs
      });
    } else {
      const jobId = buildJobId(appId, locationId, contactId);
      await enqueueDebouncedJob({
        queue,
        jobName,
        jobId,
        data: baseJobData,
        delayMs: debounceMs,
        addOptions: {
          attempts: jobAttempts,
          backoff: { type: 'exponential', delay: jobBackoffMs }
        }
      });
    }

    await incrementAnalytics(redis, 'allowed', locationId, eventType);

    console.log('[ghl-webhook] queued payload', { locationId, appId, queueName });

    return {
      statusCode: 202,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'queued' })
    };
  } finally {
    if (queue) {
      await queue.close();
    }
    await redis.quit();
  }
};
