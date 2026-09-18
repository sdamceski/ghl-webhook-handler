import { createHash } from 'node:crypto';

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, canonical(item)]));
  return value;
}
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

/** Keep this wire identity aligned with StarAuto's messageEventIdentity helper. */
export function messageEventJobId(data: {
  appId: string | null; locationId: string | null; eventType: string; webhookId: string | null;
  messageId: string | null; conversationId: string | null; payload: Record<string, unknown>;
}) {
  return `message_event_${hash([data.appId,data.locationId,data.eventType,data.webhookId,data.messageId,data.conversationId,hash(data.payload)])}`;
}
