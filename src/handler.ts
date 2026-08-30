import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import crypto from 'crypto';
import { Queue } from 'bullmq';
import IORedis from 'ioredis';

type WebhookEnvelope = Record<string, unknown>;

type WebhookIds = {
  locationId: string | null;
  appId: string | null;
  contactId: string | null;
  opportunityId: string | null;
  appointmentId: string | null;
};

type EnvConfig = {
  redisUrl: string;
  contactQueueName: string;
  contactJobName: string;
  opportunityQueueName: string;
  opportunityJobName: string;
  appointmentQueueName: string;
  appointmentJobName: string;
  messageQueueName: string;
  messageJobName: string;
  appInstallQueueName: string;
  appInstallJobName: string;
  opportunityDeleteGuardSeconds: number;
  appointmentDeleteGuardSeconds: number;
  publicKey: string | null;
  ed25519PublicKey: string;
  bullmqPrefix: string;
  debounceMs: number;
  jobAttempts: number;
  jobBackoffMs: number;
  waitTtlMs: number;
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
  rollupCount?: number;
  rollupFirstSeenAt?: string | null;
  rollupLastSeenAt?: string | null;
  rollupKey?: string;
  rollupJobId?: string;
  authState?: 'allowed';
  authValidated?: boolean;
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
const DEFAULT_OPPORTUNITY_DELETE_GUARD_SECONDS = 30;
const DEFAULT_APPOINTMENT_DELETE_GUARD_SECONDS = 30;
const OPPORTUNITY_DELETE_GUARD_PREFIX = 'ghl:opportunity-delete-guard';
const APPOINTMENT_DELETE_GUARD_PREFIX = 'ghl:appointment-delete-guard';
const CONTACT_EVENT_TYPES = new Set(['ContactCreate', 'ContactUpdate', 'ContactTagUpdate', 'ContactDelete']);
const OPPORTUNITY_EVENT_TYPES = new Set([
  'OpportunityCreate',
  'OpportunityUpdate',
  'OpportunityDelete',
  'OpportunityStageUpdate'
]);
const APPOINTMENT_EVENT_TYPES = new Set(['AppointmentCreate', 'AppointmentUpdate', 'AppointmentDelete']);
const MESSAGE_EVENT_TYPES = new Set(['InboundMessage', 'OutboundMessage']);
const APP_LIFECYCLE_EVENT_TYPES = new Set(['INSTALL', 'UNINSTALL']);
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

const parseNonNegativeIntEnv = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`Invalid ${name}; expected a non-negative integer`);
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
  if (normalized === 'opportunitycreate' || normalized === 'opportunitycreated') {
    return 'OpportunityCreate';
  }
  if (normalized === 'opportunityupdate' || normalized === 'opportunityupdated') {
    return 'OpportunityUpdate';
  }
  if (normalized === 'opportunitydelete' || normalized === 'opportunitydeleted') {
    return 'OpportunityDelete';
  }
  if (normalized === 'opportunitystageupdate' || normalized === 'opportunitystageupdated') {
    return 'OpportunityStageUpdate';
  }
  if (normalized === 'appointmentcreate' || normalized === 'appointmentcreated') {
    return 'AppointmentCreate';
  }
  if (normalized === 'appointmentupdate' || normalized === 'appointmentupdated') {
    return 'AppointmentUpdate';
  }
  if (normalized === 'appointmentdelete' || normalized === 'appointmentdeleted') {
    return 'AppointmentDelete';
  }
  if (normalized === 'inboundmessage') {
    return 'InboundMessage';
  }
  if (normalized === 'outboundmessage') {
    return 'OutboundMessage';
  }
  if (normalized === 'install' || normalized === 'installed') {
    return 'INSTALL';
  }
  if (normalized === 'uninstall' || normalized === 'uninstalled') {
    return 'UNINSTALL';
  }
  return value;
};

const extractWebhookIds = (payload: unknown): WebhookIds => {
  if (!isRecord(payload)) {
    return { locationId: null, appId: null, contactId: null, opportunityId: null, appointmentId: null };
  }

  const appointmentPayload = isRecord(payload.appointment) ? payload.appointment : null;
  const eventPayload = isRecord(payload.event) ? payload.event : null;
  const commonId = coerceString(payload.id);
  const nestedId = coerceString(appointmentPayload?.id ?? eventPayload?.id);

  return {
    locationId: coerceString(payload.locationId ?? payload.location_id ?? payload.companyId ?? payload.company_id),
    appId: coerceString(payload.appId ?? payload.app_id),
    contactId: coerceString(payload.contactId ?? payload.contact_id ?? commonId),
    opportunityId: coerceString(payload.opportunityId ?? payload.opportunity_id ?? commonId),
    appointmentId: coerceString(payload.appointmentId ?? payload.appointment_id ?? nestedId ?? commonId)
  };
};

const extractWebhookId = (payload: unknown): string | null => {
  if (!isRecord(payload)) {
    return null;
  }
  return coerceString(payload.webhookId ?? payload.webhook_id ?? payload.eventId);
};

const extractMessageIds = (
  payload: unknown
): { messageId: string | null; conversationId: string | null } => {
  if (!isRecord(payload)) {
    return { messageId: null, conversationId: null };
  }
  return {
    messageId: coerceString(payload.messageId ?? payload.message_id ?? payload.emailMessageId ?? payload.email_message_id),
    conversationId: coerceString(payload.conversationId ?? payload.conversation_id)
  };
};

type AppLifecycleFields = {
  appId: string | null;
  companyId: string | null;
  locationId: string | null;
  userId: string | null;
  planId: string | null;
  trial: Record<string, unknown> | null;
  isWhitelabelCompany: boolean | null;
  whitelabelDetails: Record<string, unknown> | null;
  companyName: string | null;
};

// Unlike extractWebhookIds, we DO NOT let locationId fall back to companyId.
// INSTALL/UNINSTALL payloads use presence-of-locationId to differentiate a
// Location-level install from an Agency-level install — collapsing them would
// break routing decisions in the downstream worker.
const extractAppLifecycleFields = (payload: unknown): AppLifecycleFields => {
  if (!isRecord(payload)) {
    return {
      appId: null,
      companyId: null,
      locationId: null,
      userId: null,
      planId: null,
      trial: null,
      isWhitelabelCompany: null,
      whitelabelDetails: null,
      companyName: null
    };
  }
  const trial = isRecord(payload.trial) ? (payload.trial as Record<string, unknown>) : null;
  const whitelabelDetails = isRecord(payload.whitelabelDetails)
    ? (payload.whitelabelDetails as Record<string, unknown>)
    : null;
  const isWhitelabelCompanyRaw = payload.isWhitelabelCompany;
  return {
    appId: coerceString(payload.appId ?? payload.app_id),
    companyId: coerceString(payload.companyId ?? payload.company_id),
    locationId: coerceString(payload.locationId ?? payload.location_id),
    userId: coerceString(payload.userId ?? payload.user_id),
    planId: coerceString(payload.planId ?? payload.plan_id),
    trial,
    isWhitelabelCompany: typeof isWhitelabelCompanyRaw === 'boolean' ? isWhitelabelCompanyRaw : null,
    whitelabelDetails,
    companyName: coerceString(payload.companyName ?? payload.company_name)
  };
};

// GHL is deprecating the RSA X-Wh-Signature header on 2026-09-01 in favor of
// Ed25519 X-GHL-Signature. This public key is documented at
// https://marketplace.gohighlevel.com/docs/webhook/WebhookIntegrationGuide
// It is a stable global value; env override is supported for emergency rotation.
const DEFAULT_GHL_ED25519_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAi2HR1srL4o18O8BRa7gVJY7G7bupbN3H9AwJrHCDiOg=
-----END PUBLIC KEY-----`;

const getHeaderCaseInsensitive = (
  headers: Record<string, string | undefined> | undefined,
  name: string
): string | undefined => {
  if (!headers) return undefined;
  const direct = headers[name];
  if (direct) return direct;
  const lowered = name.toLowerCase();
  const key = Object.keys(headers).find((header) => header.toLowerCase() === lowered);
  return key ? headers[key] : undefined;
};

const getLegacyRsaSignatureHeader = (
  headers: Record<string, string | undefined> | undefined
): string | undefined => getHeaderCaseInsensitive(headers, 'x-wh-signature');

const getGhlSignatureHeader = (
  headers: Record<string, string | undefined> | undefined
): string | undefined => getHeaderCaseInsensitive(headers, 'x-ghl-signature');

const decodeSignature = (signature: string | undefined): string | undefined => {
  if (!signature) return signature;
  if (!signature.includes('%')) return signature;
  try {
    return decodeURIComponent(signature);
  } catch {
    return signature;
  }
};

const verifyRsaSignature = (rawBody: Buffer, signature: string, publicKey: string): boolean => {
  try {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(rawBody);
    verifier.end();
    return verifier.verify(publicKey, signature, 'base64');
  } catch {
    return false;
  }
};

const verifyEd25519Signature = (rawBody: Buffer, signature: string, publicKey: string): boolean => {
  try {
    const signatureBuffer = Buffer.from(signature, 'base64');
    return crypto.verify(null, rawBody, publicKey, signatureBuffer);
  } catch {
    return false;
  }
};

type SignatureVerification = {
  ok: boolean;
  scheme: 'ed25519' | 'rsa' | 'none';
  reason?: string;
};

// Prefer Ed25519 when present. Fall back to legacy RSA during transition
// (RSA header goes away 2026-09-01). Reject when neither is signed. If the
// legacy RSA public key is not configured (env var / secret unavailable), we
// still accept Ed25519 but reject RSA-only signatures — this keeps the
// Lambda bootable when the shared secret bundle omits the RSA key.
const verifyGhlWebhookSignature = (
  rawBody: Buffer | null,
  headers: Record<string, string | undefined> | undefined,
  legacyRsaPublicKey: string | null,
  ed25519PublicKey: string
): SignatureVerification => {
  if (!rawBody) {
    return { ok: false, scheme: 'none', reason: 'no_body' };
  }

  const ghlSignature = decodeSignature(getGhlSignatureHeader(headers));
  if (ghlSignature) {
    return {
      ok: verifyEd25519Signature(rawBody, ghlSignature, ed25519PublicKey),
      scheme: 'ed25519'
    };
  }

  const legacySignature = decodeSignature(getLegacyRsaSignatureHeader(headers));
  if (legacySignature) {
    if (!legacyRsaPublicKey) {
      return { ok: false, scheme: 'rsa', reason: 'rsa_key_unavailable' };
    }
    return {
      ok: verifyRsaSignature(rawBody, legacySignature, legacyRsaPublicKey),
      scheme: 'rsa'
    };
  }

  return { ok: false, scheme: 'none', reason: 'no_signature' };
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

const buildJobId = (appId: string | null, locationId: string | null, entityId: string): string => {
  const appSegment = appId ? appId.trim() : 'noapp';
  const locationSegment = locationId ? locationId.trim() : 'noloc';
  return `${appSegment}_${locationSegment}_${entityId}`;
};

const buildOpportunityDeleteGuardKey = (
  appId: string | null,
  locationId: string | null,
  opportunityId: string | null
): string | null => {
  if (!locationId || !opportunityId) {
    return null;
  }

  const appSegment = appId ? appId.trim() : 'noapp';
  const locationSegment = locationId.trim();
  const opportunitySegment = opportunityId.trim();

  if (!locationSegment || !opportunitySegment) {
    return null;
  }

  return `${OPPORTUNITY_DELETE_GUARD_PREFIX}:${appSegment}:${locationSegment}:${opportunitySegment}`;
};

const buildAppointmentDeleteGuardKey = (
  appId: string | null,
  locationId: string | null,
  appointmentId: string | null
): string | null => {
  if (!locationId || !appointmentId) {
    return null;
  }

  const appSegment = appId ? appId.trim() : 'noapp';
  const locationSegment = locationId.trim();
  const appointmentSegment = appointmentId.trim();

  if (!locationSegment || !appointmentSegment) {
    return null;
  }

  return `${APPOINTMENT_DELETE_GUARD_PREFIX}:${appSegment}:${locationSegment}:${appointmentSegment}`;
};

const buildOpportunityDeleteJobId = (params: {
  appId: string | null;
  locationId: string | null;
  opportunityId: string;
  webhookId: string | null;
  payloadHash: string;
}): string => {
  const base = buildJobId(params.appId, params.locationId, params.opportunityId).replace(/:/g, '_');
  const suffix = params.webhookId
    ? params.webhookId
    : params.payloadHash.slice(0, 16);
  return `delete_${base}_${suffix}`;
};

const buildAppointmentDeleteJobId = (params: {
  appId: string | null;
  locationId: string | null;
  appointmentId: string;
  webhookId: string | null;
  payloadHash: string;
}): string => {
  const base = buildJobId(params.appId, params.locationId, params.appointmentId).replace(/:/g, '_');
  const suffix = params.webhookId
    ? params.webhookId
    : params.payloadHash.slice(0, 16);
  return `delete_${base}_${suffix}`;
};

const getEnvConfig = (): EnvConfig => {
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) {
    throw new Error('Missing REDIS_URL');
  }

  const publicKey = process.env.GHL_WEBHOOK_PUBLIC_KEY?.trim() || null;

  const ed25519PublicKey = process.env.GHL_WEBHOOK_ED25519_PUBLIC_KEY?.trim() || DEFAULT_GHL_ED25519_PUBLIC_KEY_PEM;

  const debounceRaw = process.env.GHL_WEBHOOK_CONTACT_DEBOUNCE_MS;
  const parsedDebounce = debounceRaw ? Number(debounceRaw) : Number.NaN;
  const debounceMs = Number.isFinite(parsedDebounce) && parsedDebounce > 0 ? parsedDebounce : 3500;

  return {
    redisUrl,
    publicKey,
    ed25519PublicKey,
    contactQueueName: process.env.GHL_WEBHOOK_CONTACT_QUEUE_NAME
      ?? process.env.GHL_WEBHOOK_QUEUE_NAME
      ?? 'ghl-inbound-contact-update',
    contactJobName: process.env.GHL_WEBHOOK_CONTACT_JOB_NAME
      ?? process.env.GHL_WEBHOOK_JOB_NAME
      ?? 'ghl.contact.update',
    opportunityQueueName: process.env.GHL_WEBHOOK_OPPORTUNITY_QUEUE_NAME ?? 'ghl-opportunity-sync',
    opportunityJobName: process.env.GHL_WEBHOOK_OPPORTUNITY_JOB_NAME ?? 'ghl.opportunity.sync',
    appointmentQueueName: process.env.GHL_WEBHOOK_APPOINTMENT_QUEUE_NAME ?? 'ghl-appointment-sync',
    appointmentJobName: process.env.GHL_WEBHOOK_APPOINTMENT_JOB_NAME ?? 'ghl.appointment.sync',
    messageQueueName: process.env.GHL_WEBHOOK_MESSAGE_QUEUE_NAME ?? 'ghl-message-ingest',
    messageJobName: process.env.GHL_WEBHOOK_MESSAGE_JOB_NAME ?? 'ghl.message.ingest',
    appInstallQueueName: process.env.GHL_WEBHOOK_APP_INSTALL_QUEUE_NAME ?? 'ghl-app-install-events',
    appInstallJobName: process.env.GHL_WEBHOOK_APP_INSTALL_JOB_NAME ?? 'ghl.app-install-event',
    opportunityDeleteGuardSeconds: parsePositiveIntEnv(
      'GHL_WEBHOOK_OPPORTUNITY_DELETE_GUARD_SECONDS',
      DEFAULT_OPPORTUNITY_DELETE_GUARD_SECONDS
    ),
    appointmentDeleteGuardSeconds: parsePositiveIntEnv(
      'GHL_WEBHOOK_APPOINTMENT_DELETE_GUARD_SECONDS',
      DEFAULT_APPOINTMENT_DELETE_GUARD_SECONDS
    ),
    bullmqPrefix: process.env.GHL_WEBHOOK_BULLMQ_PREFIX ?? DEFAULT_BULLMQ_PREFIX,
    debounceMs,
    jobAttempts: parsePositiveIntEnv('GHL_WEBHOOK_JOB_ATTEMPTS', 5),
    jobBackoffMs: parsePositiveIntEnv('GHL_WEBHOOK_JOB_BACKOFF_MS', 1000),
    waitTtlMs: parseNonNegativeIntEnv('GHL_WEBHOOK_WAIT_TTL_MS', 0)
  };
};

const cleanStaleQueuedJobs = async (queue: Queue, ttlMs: number): Promise<void> => {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    return;
  }

  try {
    // Drop old, unprocessed jobs to prevent dev backlog growth when workers are offline.
    await queue.clean(ttlMs, 1000, 'wait');
    await queue.clean(ttlMs, 1000, 'delayed');
  } catch (error) {
    console.warn('[ghl-webhook] failed to clean stale queue jobs', {
      queue: queue.name,
      ttlMs,
      error
    });
  }
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

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const {
    redisUrl,
    contactQueueName,
    contactJobName,
    opportunityQueueName,
    opportunityJobName,
    opportunityDeleteGuardSeconds,
    appointmentQueueName,
    appointmentJobName,
    appointmentDeleteGuardSeconds,
    messageQueueName,
    messageJobName,
    appInstallQueueName,
    appInstallJobName,
    publicKey,
    ed25519PublicKey,
    bullmqPrefix,
    debounceMs,
    jobAttempts,
    jobBackoffMs,
    waitTtlMs
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
  const { locationId, appId, contactId, opportunityId, appointmentId } = extractWebhookIds(payload);

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

    const signatureVerification = verifyGhlWebhookSignature(rawBody, event.headers, publicKey, ed25519PublicKey);
    if (!signatureVerification.ok) {
      console.warn('[ghl-webhook] invalid signature', {
        scheme: signatureVerification.scheme,
        reason: signatureVerification.reason ?? 'verify_failed'
      });
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'error', reason: 'invalid_signature' })
      };
    }

    if (signatureVerification.scheme === 'rsa') {
      // Nudge to switch signers before the 2026-09-01 deprecation.
      console.info('[ghl-webhook] legacy RSA signature accepted (deprecated)', {
        appId,
        locationId,
        eventType
      });
    }

    const isContactEvent = CONTACT_EVENT_TYPES.has(eventType);
    const isOpportunityEvent = OPPORTUNITY_EVENT_TYPES.has(eventType);
    const isAppointmentEvent = APPOINTMENT_EVENT_TYPES.has(eventType);
    const isMessageEvent = MESSAGE_EVENT_TYPES.has(eventType);
    const isAppLifecycleEvent = APP_LIFECYCLE_EVENT_TYPES.has(eventType);
    const isOpportunityDeleteEvent = isOpportunityEvent && eventType === 'OpportunityDelete';
    const isAppointmentDeleteEvent = isAppointmentEvent && eventType === 'AppointmentDelete';

    if (
      !isContactEvent &&
      !isOpportunityEvent &&
      !isAppointmentEvent &&
      !isMessageEvent &&
      !isAppLifecycleEvent
    ) {
      console.log('[ghl-webhook] ignored unsupported event type', { eventType });
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 202,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ignored', reason: 'unsupported_event_type' })
      };
    }

    // App lifecycle events (INSTALL/UNINSTALL) use their own queue and don't need
    // the debounce/rollup infrastructure the CRM data-plane events share below.
    // Route + return early so the rest of the handler stays focused on those.
    if (isAppLifecycleEvent) {
      const appLifecycle = extractAppLifecycleFields(payload);
      // Accept the event if we have appId + (companyId OR locationId). Location-
      // level UNINSTALLs sometimes arrive with companyId=null — the backend
      // worker can resolve the agency by joining dealer_ghl_integration on
      // ghl_location_id. Fully-anonymous events (no company, no location) still
      // get rejected because we can't route them.
      if (!appLifecycle.appId || (!appLifecycle.companyId && !appLifecycle.locationId)) {
        console.warn('[ghl-webhook] app lifecycle missing appId and (companyId or locationId)', {
          eventType,
          appId: appLifecycle.appId,
          companyId: appLifecycle.companyId,
          locationId: appLifecycle.locationId
        });
        await incrementAnalytics(redis, 'blocked', locationId, eventType);
        return {
          statusCode: 400,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'error', reason: 'app_lifecycle_ids_required' })
        };
      }

      queue = new Queue(appInstallQueueName, { connection: redis, prefix: bullmqPrefix });
      await cleanStaleQueuedJobs(queue, waitTtlMs);

      const webhookId = extractWebhookId(payload);
      const payloadHash = computePayloadHash(payload);
      const dedupSegment = webhookId ?? payloadHash.slice(0, 16);
      const locSegment = appLifecycle.locationId ?? 'noloc';
      const companySegment = appLifecycle.companyId ?? 'nocompany';
      const jobId = `${eventType.toLowerCase()}_${appLifecycle.appId}_${companySegment}_${locSegment}_${dedupSegment}`
        .replace(/:/g, '_');

      const jobData = {
        source: 'ghl' as const,
        eventType,
        webhookId,
        appId: appLifecycle.appId,
        companyId: appLifecycle.companyId,
        locationId: appLifecycle.locationId,
        userId: appLifecycle.userId,
        planId: appLifecycle.planId,
        trial: appLifecycle.trial,
        isWhitelabelCompany: appLifecycle.isWhitelabelCompany,
        whitelabelDetails: appLifecycle.whitelabelDetails,
        companyName: appLifecycle.companyName,
        payloadHash,
        payload,
        authState: 'allowed' as const,
        authValidated: true
      };

      await queue.add(appInstallJobName, jobData, {
        jobId,
        attempts: jobAttempts,
        backoff: { type: 'exponential', delay: jobBackoffMs },
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 1000 }
      });

      await incrementAnalytics(redis, 'allowed', appLifecycle.locationId ?? appLifecycle.companyId, eventType);

      console.log('[ghl-webhook] queued app lifecycle event', {
        eventType,
        appId: appLifecycle.appId,
        companyId: appLifecycle.companyId,
        locationId: appLifecycle.locationId,
        installType: appLifecycle.locationId ? 'Location' : 'Agency',
        jobId
      });

      return {
        statusCode: 202,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'queued' })
      };
    }

    if (isContactEvent && !contactId) {
      console.warn('[ghl-webhook] missing contact id');
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'error', reason: 'contact_id_required' })
      };
    }

    if (isOpportunityEvent && !opportunityId) {
      console.warn('[ghl-webhook] missing opportunity id');
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'error', reason: 'opportunity_id_required' })
      };
    }

    if (isAppointmentEvent && !appointmentId) {
      console.warn('[ghl-webhook] missing appointment id');
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'error', reason: 'appointment_id_required' })
      };
    }

    const { messageId, conversationId } = isMessageEvent
      ? extractMessageIds(payload)
      : { messageId: null as string | null, conversationId: null as string | null };

    if (isMessageEvent && (!messageId || !conversationId)) {
      console.warn('[ghl-webhook] missing message identifiers', { messageId, conversationId });
      await incrementAnalytics(redis, 'blocked', locationId, eventType);
      return {
        statusCode: 400,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'error', reason: 'message_id_required' })
      };
    }

    const opportunityDeleteGuardKey = isOpportunityEvent
      ? buildOpportunityDeleteGuardKey(appId, locationId, opportunityId)
      : null;
    const appointmentDeleteGuardKey = isAppointmentEvent
      ? buildAppointmentDeleteGuardKey(appId, locationId, appointmentId)
      : null;

    if (isOpportunityEvent && !isOpportunityDeleteEvent && opportunityDeleteGuardKey) {
      const hasDeleteGuard = (await redis.exists(opportunityDeleteGuardKey)) === 1;
      if (hasDeleteGuard) {
        console.log('[ghl-webhook] ignored opportunity event due to active delete guard', {
          appId,
          locationId,
          opportunityId,
          eventType,
          guardKey: opportunityDeleteGuardKey
        });

        await incrementAnalytics(redis, 'blocked', locationId, eventType);
        return {
          statusCode: 202,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'ignored', reason: 'opportunity_delete_guard_active' })
        };
      }
    }

    if (isAppointmentEvent && !isAppointmentDeleteEvent && appointmentDeleteGuardKey) {
      const hasDeleteGuard = (await redis.exists(appointmentDeleteGuardKey)) === 1;
      if (hasDeleteGuard) {
        console.log('[ghl-webhook] ignored appointment event due to active delete guard', {
          appId,
          locationId,
          appointmentId,
          eventType,
          guardKey: appointmentDeleteGuardKey
        });

        await incrementAnalytics(redis, 'blocked', locationId, eventType);
        return {
          statusCode: 202,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'ignored', reason: 'appointment_delete_guard_active' })
        };
      }
    }

    console.log('[ghl-webhook] extracted ids', {
      locationId,
      appId,
      contactId,
      opportunityId,
      appointmentId,
      eventType
    });

    const queueName = isContactEvent
      ? contactQueueName
      : isOpportunityEvent
        ? opportunityQueueName
        : isAppointmentEvent
          ? appointmentQueueName
          : messageQueueName;
    const jobName = isContactEvent
      ? contactJobName
      : isOpportunityEvent
        ? opportunityJobName
        : isAppointmentEvent
          ? appointmentJobName
          : messageJobName;
    queue = new Queue(queueName, { connection: redis, prefix: bullmqPrefix });
    await cleanStaleQueuedJobs(queue, waitTtlMs);
    const webhookId = extractWebhookId(payload);
    const payloadHash = computePayloadHash(payload);

    const baseJobData: RollupJobData = {
      source: 'ghl',
      eventType,
      inboundEventId: null,
      webhookId,
      locationId,
      appId,
      contactId,
      payloadHash,
      payload,
      authState: 'allowed',
      authValidated: true
    };

    const retryOptions: Pick<AddJobOptions, 'attempts' | 'backoff' | 'removeOnComplete' | 'removeOnFail'> = {
      attempts: jobAttempts,
      backoff: { type: 'exponential', delay: jobBackoffMs },
      removeOnComplete: { count: 100 },
      removeOnFail: { count: 1000 }
    };

    const rollupKey = isContactEvent ? buildRollupKey(appId, locationId, contactId) : null;
    if (isMessageEvent) {
      const direction = coerceString((payload as Record<string, unknown>).direction);
      const messageType = coerceString((payload as Record<string, unknown>).messageType);
      const conversationProviderId = coerceString(
        (payload as Record<string, unknown>).conversationProviderId ??
          (payload as Record<string, unknown>).conversation_provider_id
      );
      const appSegment = appId ? appId.trim() : 'noapp';
      const locationSegment = locationId ? locationId.trim() : 'noloc';
      const messageJobId = `${appSegment}_${locationSegment}_msg_${messageId as string}`;
      const messageJobData = {
        source: 'ghl' as const,
        eventType,
        webhookId,
        appId,
        locationId,
        contactId,
        conversationId,
        messageId,
        direction,
        messageType,
        conversationProviderId,
        payloadHash,
        payload,
        authState: 'allowed' as const,
        authValidated: true
      };
      await queue.add(jobName, messageJobData, {
        ...retryOptions,
        jobId: messageJobId,
        delay: 0
      });
    } else if (rollupKey) {
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

      const nowIso = new Date().toISOString();
      const previousCount = Number(existing?.data?.rollupCount);
      const nextCount = Number.isFinite(previousCount) && previousCount > 0 ? Math.trunc(previousCount) + 1 : 1;
      const firstSeenAt = existing?.data?.rollupFirstSeenAt ?? nowIso;

      const rolledUp: RollupJobData = {
        ...baseJobData,
        rollupCount: nextCount,
        rollupFirstSeenAt: firstSeenAt,
        rollupLastSeenAt: nowIso,
        rollupKey,
        rollupJobId
      };
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
      const entityId = isContactEvent
        ? (contactId as string)
        : (isOpportunityEvent ? (opportunityId as string) : (appointmentId as string));
      const jobId = buildJobId(appId, locationId, entityId);
      const jobData = isContactEvent
        ? {
          ...baseJobData,
          rollupCount: 1,
          rollupFirstSeenAt: null,
          rollupLastSeenAt: null
        }
        : isOpportunityEvent ? {
          source: 'ghl',
          eventType,
          webhookId,
          locationId,
          appId,
          opportunityId,
          payloadHash,
          payload,
          direction: 'inbound',
          ghlLocationId: locationId,
          ghlOpportunityId: opportunityId,
          reason: 'webhook',
          authState: 'allowed',
          authValidated: true
        } : {
          source: 'ghl',
          eventType,
          webhookId,
          appId,
          payloadHash,
          payload,
          direction: 'inbound',
          ghlLocationId: locationId,
          ghlAppointmentId: appointmentId,
          reason: 'webhook',
          authState: 'allowed',
          authValidated: true
        };

      if (isOpportunityDeleteEvent || isAppointmentDeleteEvent) {
        if (isOpportunityDeleteEvent && opportunityDeleteGuardKey) {
          await redis.set(opportunityDeleteGuardKey, '1', 'EX', opportunityDeleteGuardSeconds);
        }
        if (isAppointmentDeleteEvent && appointmentDeleteGuardKey) {
          await redis.set(appointmentDeleteGuardKey, '1', 'EX', appointmentDeleteGuardSeconds);
        }

        const deleteJobId = isOpportunityDeleteEvent
          ? buildOpportunityDeleteJobId({
            appId,
            locationId,
            opportunityId: opportunityId as string,
            webhookId,
            payloadHash
          })
          : buildAppointmentDeleteJobId({
            appId,
            locationId,
            appointmentId: appointmentId as string,
            webhookId,
            payloadHash
          });

        const standardJob = await queue.getJob(jobId);
        if (standardJob) {
          const state = await standardJob.getState();
          if (state === 'waiting' || state === 'delayed') {
            try {
              await standardJob.remove();
            } catch (error) {
              console.warn('[ghl-webhook] failed to remove standard queued entity job before delete enqueue', {
                appId,
                locationId,
                opportunityId,
                appointmentId,
                jobId,
                error
              });
            }
          }
        }

        await queue.add(jobName, jobData, {
          ...retryOptions,
          jobId: deleteJobId,
          delay: 0,
          priority: 1
        });
      } else {
        await enqueueDebouncedJob({
          queue,
          jobName,
          jobId,
          data: jobData,
          delayMs: debounceMs,
          addOptions: {
            attempts: jobAttempts,
            backoff: { type: 'exponential', delay: jobBackoffMs }
          }
        });
      }
    }

    await incrementAnalytics(redis, 'allowed', locationId, eventType);

    console.log('[ghl-webhook] queued payload', {
      locationId,
      appId,
      queueName,
      eventType,
      entityId: isContactEvent
        ? contactId
        : isOpportunityEvent
          ? opportunityId
          : isAppointmentEvent
            ? appointmentId
            : messageId
    });

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
