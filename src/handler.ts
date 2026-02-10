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
  debounceMs: number;
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
    debounceMs
  };
};

const isRecord = (value: unknown): value is WebhookEnvelope =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const coerceString = (value: unknown): string | null => {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text.length ? text : null;
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

const extractEventType = (payload: unknown): string | null => {
  if (!isRecord(payload)) {
    return null;
  }
  return coerceString(payload.type);
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

const enqueueDebouncedJob = async (params: {
  queue: Queue;
  jobName: string;
  jobId: string;
  data: Record<string, unknown>;
  delayMs: number;
}): Promise<void> => {
  const { queue, jobName, jobId, data, delayMs } = params;
  const existing = await queue.getJob(jobId);
  if (existing) {
    const state = await existing.getState();
    if (state === 'delayed' || state === 'waiting') {
      await existing.update(data);
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
    jobId,
    delay: delayMs,
    removeOnComplete: true,
    removeOnFail: true
  });
};

const isAllowedLocation = async (redis: IORedis, allowlistKey: string, locationId: string | null): Promise<boolean> => {
  if (!locationId) {
    return false;
  }
  const isMember = await redis.sismember(allowlistKey, locationId);
  return isMember === 1;
};

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const { redisUrl, allowlistKey, queueName, jobName, publicKey, debounceMs } = getEnvConfig();

  const rawBody = event.body
    ? Buffer.from(event.body, event.isBase64Encoded ? 'base64' : 'utf8')
    : null;
  const payload = parseBody(rawBody ? rawBody.toString('utf8') : null);

  if (!payload) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'error', reason: 'invalid_payload' })
    };
  }

  const signature = getSignatureHeader(event.headers);
  if (!verifyWebhookSignature(rawBody, signature, publicKey)) {
    return {
      statusCode: 401,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'error', reason: 'invalid_signature' })
    };
  }

  const { locationId, appId, contactId } = extractWebhookIds(payload);
  const eventType = extractEventType(payload);
  if (!eventType) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'error', reason: 'event_type_required' })
    };
  }
  if (!contactId) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'error', reason: 'contact_id_required' })
    };
  }

  const redis = new IORedis(redisUrl);
  const queue = new Queue(queueName, { connection: redis });

  try {
    const allowed = await isAllowedLocation(redis, allowlistKey, locationId);
    if (!allowed) {
      return {
        statusCode: 202,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ignored', reason: 'location_not_enabled' })
      };
    }

    const jobId = buildJobId(appId, locationId, contactId);
    const jobPayload = {
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

    await enqueueDebouncedJob({
      queue,
      jobName,
      jobId,
      data: jobPayload,
      delayMs: debounceMs
    });

    return {
      statusCode: 202,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'queued' })
    };
  } finally {
    await queue.close();
    await redis.quit();
  }
};
