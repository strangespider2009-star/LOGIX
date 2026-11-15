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

