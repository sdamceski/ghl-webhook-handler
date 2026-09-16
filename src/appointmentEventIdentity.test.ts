import {test} from 'node:test';
import assert from 'node:assert/strict';
import {appointmentJobOptions} from './appointmentEventIdentity';
const base = {appId:'app',locationId:'loc',appointmentId:'a',eventType:'AppointmentCreate',payloadHash:'h1',attempts:5,backoffMs:1000};
test('duplicates share an ID but distinct payloads and event types do not',()=>{
  assert.equal(appointmentJobOptions(base).jobId,appointmentJobOptions({...base}).jobId);
  for(const patch of [{payloadHash:'h2'},{eventType:'AppointmentDelete'},{locationId:'other'},{appId:'other'}]) {
    assert.notEqual(appointmentJobOptions(base).jobId,appointmentJobOptions({...base,...patch}).jobId);
  }
});
test('appointment work is retained after failures and is not debounced',()=>{
  const options=appointmentJobOptions(base);
  assert.equal(options.removeOnFail,false);assert.equal(options.delay,undefined);
  assert.equal(options.attempts,5);assert.ok(!options.jobId!.includes(':'));
});
