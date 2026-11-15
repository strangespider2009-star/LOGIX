import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateDemoAccess, validDate, validSlot } from '../server/rules.js';

const moment = new Date('2026-11-15T00:00:00.000Z');
const vehicle = { id: 'vehicle-1' };
const driver = { vehicleId: 'vehicle-1', approved: true, fingerprintEnrolled: true, licenceExpiry: '2099-12-31' };
const check = (changes = {}) => evaluateDemoAccess({ driver, vehicle, faceMatched: true, fingerprintMatched: true, ...changes }, moment);

test("approve only when all demo conditions pass", () => {
  assert.equal(check().accessGranted, true);
});

test("reject absent driver", () => {
  assert.equal(check({ driver: null }).accessGranted, false);
});

test("reject absent vehicle", () => {
  assert.equal(check({ vehicle: null }).accessGranted, false);
});

test("reject driver without linked vehicle", () => {
  assert.equal(check({ driver: { ...driver, vehicleId: '' } }).accessGranted, false);
});

test("reject driver linked to a different vehicle", () => {
  assert.equal(check({ driver: { ...driver, vehicleId: 'vehicle-2' } }).accessGranted, false);
});

test("reject explicit face mismatch", () => {
  assert.equal(check({ faceMatched: false }).accessGranted, false);
});

test("reject missing face result", () => {
  assert.equal(check({ faceMatched: undefined }).accessGranted, false);
});

test("reject string claiming a face match", () => {
  assert.equal(check({ faceMatched: 'true' }).accessGranted, false);
});

test("reject numeric face match flag", () => {
  assert.equal(check({ faceMatched: 1 }).accessGranted, false);
});

test("reject explicit fingerprint mismatch", () => {
  assert.equal(check({ fingerprintMatched: false }).accessGranted, false);
});

test("reject missing fingerprint result", () => {
  assert.equal(check({ fingerprintMatched: undefined }).accessGranted, false);
});

test("reject string claiming a fingerprint match", () => {
  assert.equal(check({ fingerprintMatched: 'true' }).accessGranted, false);
});

test("reject fingerprint not enrolled", () => {
  assert.equal(check({ driver: { ...driver, fingerprintEnrolled: false } }).accessGranted, false);
});

test("reject string enrollment flag", () => {
  assert.equal(check({ driver: { ...driver, fingerprintEnrolled: 'true' } }).accessGranted, false);
});

test("reject owner disapproval", () => {
  assert.equal(check({ driver: { ...driver, approved: false } }).accessGranted, false);
});

test("reject string approval flag", () => {
  assert.equal(check({ driver: { ...driver, approved: 'true' } }).accessGranted, false);
});

test("reject expired licence date", () => {
  assert.equal(check({ driver: { ...driver, licenceExpiry: '2026-11-14' } }).accessGranted, false);
});

test("accept expiry date on evaluation day", () => {
  assert.equal(check({ driver: { ...driver, licenceExpiry: '2026-11-15' } }).accessGranted, true);
});

test("reject nonexistent February 29", () => {
  assert.equal(validDate('2026-02-29'), false);
});

test("accept leap year February 29", () => {
  assert.equal(validDate('2028-02-29'), true);
});

test("reject non ISO date format", () => {
  assert.equal(validDate('11/15/2026'), false);
});

test("accept fingerprint sensor slots at boundaries", () => {
  assert.equal(validSlot(1), true); assert.equal(validSlot(127), true);
});

test("reject fractional fingerprint slot", () => {
  assert.equal(validSlot(3.5), false);
});

