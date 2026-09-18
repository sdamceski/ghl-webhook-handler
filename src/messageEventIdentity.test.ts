import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { messageEventJobId } from './messageEventIdentity';

const data = { appId: 'a', locationId: 'l', eventType: 'InboundMessage', webhookId: 'e',
  messageId: 'm', conversationId: 'c', payload: { body: 'Hi', status: 'sent' } };
test('message queue identity retains updates and distinguishes tenant scope', () => {
  assert.match(messageEventJobId(data), /^message_event_[a-f0-9]{64}$/);
  assert.equal(messageEventJobId(data), messageEventJobId({ ...data, payload: { status: 'sent', body: 'Hi' } }));
  assert.notEqual(messageEventJobId(data), messageEventJobId({ ...data, payload: { ...data.payload, status: 'delivered' } }));
  assert.notEqual(messageEventJobId(data), messageEventJobId({ ...data, locationId: 'other' }));
});


test('the live sent and delivered notifications produce distinct jobs while retries remain identical', () => {
  const sent = {...data, eventType:'OutboundMessage', messageId:'jl2LxztpSVwS3iUnN4Ly',
    webhookId:'cdddc6bf-e076-482c-9eb9-333da3eaad50', payload:{status:'sent',timestamp:'2026-09-18T01:20:11.542Z'}};
  const delivered = {...sent, webhookId:'993a0e55-1eb7-4986-963e-15a587bed043',
    payload:{status:'delivered',timestamp:'2026-09-18T01:20:12.477Z'}};
  assert.notEqual(messageEventJobId(sent),messageEventJobId(delivered));
  assert.equal(messageEventJobId(delivered),messageEventJobId({...delivered}));
  assert.notEqual(messageEventJobId({...sent,webhookId:null}),messageEventJobId({...delivered,webhookId:null}));
});
