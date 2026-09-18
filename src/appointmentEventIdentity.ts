import crypto from 'crypto';
import type { JobsOptions } from 'bullmq';

export function appointmentJobOptions(p: {
  appId: string | null; locationId: string | null; appointmentId: string;
  eventType: string; payloadHash: string; attempts: number; backoffMs: number;
}): JobsOptions {
  const key = crypto.createHash('sha256').update(JSON.stringify([
    p.appId,p.locationId,p.appointmentId,p.eventType,p.payloadHash
  ])).digest('hex');
  return { jobId: `appointment_${key}`, attempts:p.attempts,
    backoff:{type:'exponential',delay:p.backoffMs},removeOnFail:false,removeOnComplete:{count:1000} };
}

