import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { readStore, writeStore, makeId } from './store.js';
import { evaluateDemoAccess, validDate, validSlot } from './rules.js';

const app = express();
const production = process.env.NODE_ENV === 'production';
const secret = process.env.SESSION_SECRET || (production ? '' : 'local-development-only');
if (production && secret.length < 24) throw new Error('Set a long SESSION_SECRET (24+ characters) in production.');
app.disable('x-powered-by');
if (production) app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));
app.use(session({
  name: 'sdg.demo.sid', secret, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: production, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));

const errors = (res, code, message) => res.status(code).json({ error: message });
const publicUser = ({ id, name, email }) => ({ id, name, email });
const normalized = value => typeof value === 'string' ? value.trim() : '';
function userFor(req) {
  if (!req.session.userId) return null;
  return readStore().users.find(u => u.id === req.session.userId) || null;
}
function auth(req, res, next) {
  const user = userFor(req);
  if (!user) return errors(res, 401, 'Please sign in.');
  req.demoUser = user;
  next();
}
const saveSession = (req, res, body, status = 200) => req.session.save(err => {
  if (err) return errors(res, 500, 'Could not save session.');
  res.status(status).json(body);
});

app.get('/api/health', (_req, res) => res.json({ ok: true, mode: 'LED demonstration only' }));
app.get('/api/me', (req, res) => {
  const user = userFor(req);
  res.json({ user: user ? publicUser(user) : null });
});
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const name = normalized(req.body?.name).slice(0, 80);
    const email = normalized(req.body?.email).toLowerCase();
    const password = req.body?.password;
    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof password !== 'string' || password.length < 8 || password.length > 200)
      return errors(res, 400, 'Enter a name, valid email, and password of 8–200 characters.');
    const db = readStore();
    if (db.users.some(u => u.email === email)) return errors(res, 409, 'Email already registered.');
    const user = { id: makeId(), name, email, passwordHash: await bcrypt.hash(password, 12) };
    db.users.push(user); writeStore(db);
    req.session.userId = user.id;
    saveSession(req, res, { user: publicUser(user) }, 201);
  } catch (err) { next(err); }
});
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const db = readStore();
    const user = db.users.find(u => u.email === normalized(req.body?.email).toLowerCase());
    const password = req.body?.password;
    if (!user || typeof password !== 'string' || !(await bcrypt.compare(password, user.passwordHash)))
      return errors(res, 401, 'Incorrect email or password.');
    req.session.userId = user.id;
    saveSession(req, res, { user: publicUser(user) });
  } catch (err) { next(err); }
});
app.post('/api/auth/logout', (req, res) => req.session.destroy(err => {
  if (err) return errors(res, 500, 'Could not log out.');
  res.clearCookie('sdg.demo.sid', { httpOnly: true, secure: production, sameSite: 'lax' });
  res.json({ ok: true });
}));

app.get('/api/dashboard', auth, (req, res) => {
  const db = readStore(); const ownerId = req.demoUser.id;
  res.json({
    vehicles: db.vehicles.filter(x => x.ownerId === ownerId),
    drivers: db.drivers.filter(x => x.ownerId === ownerId),
    events: db.events.filter(x => x.ownerId === ownerId).slice(-80).reverse()
  });
});
app.post('/api/vehicles', auth, (req, res) => {
  const name = normalized(req.body?.name).slice(0, 100);
  const plate = normalized(req.body?.plate).slice(0, 32);
  if (!name) return errors(res, 400, 'Vehicle name is required.');
  const db = readStore();
  const vehicle = { id: makeId(), ownerId: req.demoUser.id, name, plate };
  db.vehicles.push(vehicle); writeStore(db); res.status(201).json({ vehicle });
});
app.delete('/api/vehicles/:id', auth, (req, res) => {
  const db = readStore();
  if (db.drivers.some(d => d.ownerId === req.demoUser.id && d.vehicleId === req.params.id))
    return errors(res, 409, 'Remove drivers associated with this vehicle first.');
  const before = db.vehicles.length;
  db.vehicles = db.vehicles.filter(v => !(v.id === req.params.id && v.ownerId === req.demoUser.id));
  if (db.vehicles.length === before) return errors(res, 404, 'Vehicle not found.');
  writeStore(db); res.json({ ok: true });
});
app.post('/api/drivers', auth, (req, res) => {
  const name = normalized(req.body?.name).slice(0, 100);
  const licenceExpiry = normalized(req.body?.licenceExpiry);
  const vehicleId = normalized(req.body?.vehicleId);
  const fingerprintSlot = Number(req.body?.fingerprintSlot);
  if (!name || !validDate(licenceExpiry) || !validSlot(fingerprintSlot))
    return errors(res, 400, 'Enter a driver name, real expiry date, and sensor slot 1–127.');
  const db = readStore();
  if (!db.vehicles.some(v => v.id === vehicleId && v.ownerId === req.demoUser.id))
    return errors(res, 400, 'Select one of your vehicles.');
  if (db.drivers.some(d => d.ownerId === req.demoUser.id && d.fingerprintSlot === fingerprintSlot))
    return errors(res, 409, 'Fingerprint slot already assigned. Choose a different slot.');
  const driver = { id: makeId(), ownerId: req.demoUser.id, name, licenceExpiry, vehicleId, fingerprintSlot, fingerprintEnrolled: false, approved: false, createdAt: new Date().toISOString() };
  db.drivers.push(driver); writeStore(db); res.status(201).json({ driver });
});
app.patch('/api/drivers/:id/approval', auth, (req, res) => {
  if (typeof req.body?.approved !== 'boolean') return errors(res, 400, 'approved must be boolean.');
  const db = readStore();
  const driver = db.drivers.find(d => d.id === req.params.id && d.ownerId === req.demoUser.id);
  if (!driver) return errors(res, 404, 'Driver not found.');
  driver.approved = req.body.approved; writeStore(db); res.json({ driver });
});
app.patch('/api/drivers/:id/fingerprint', auth, (req, res) => {
  if (typeof req.body?.enrolled !== 'boolean') return errors(res, 400, 'enrolled must be boolean.');
  const db = readStore();
  const driver = db.drivers.find(d => d.id === req.params.id && d.ownerId === req.demoUser.id);
  if (!driver) return errors(res, 404, 'Driver not found.');
  driver.fingerprintEnrolled = req.body.enrolled; writeStore(db); res.json({ driver });
});
app.delete('/api/drivers/:id', auth, (req, res) => {
  const db = readStore(); const before = db.drivers.length;
  db.drivers = db.drivers.filter(d => !(d.id === req.params.id && d.ownerId === req.demoUser.id));
  if (before === db.drivers.length) return errors(res, 404, 'Driver not found.');
  // This removes only a database record. Delete the sensor template before this step.
  writeStore(db); res.json({ ok: true });
});
app.post('/api/access/check', auth, (req, res) => {
  const db = readStore(); const ownerId = req.demoUser.id;
  const driver = db.drivers.find(d => d.id === req.body?.driverId && d.ownerId === ownerId);
  const vehicle = db.vehicles.find(v => v.id === req.body?.vehicleId && v.ownerId === ownerId);
  const decision = evaluateDemoAccess({ driver, vehicle, faceMatched: req.body?.faceMatched, fingerprintMatched: req.body?.fingerprintMatched });
  const event = { id: makeId(), ownerId, at: new Date().toISOString(), driverName: driver?.name || '(unknown)', vehicleName: vehicle?.name || '(unknown)', ...decision.checks, accessGranted: decision.accessGranted };
  db.events.push(event);
  db.events = db.events.slice(-3000);
  writeStore(db);
  res.json({ decision, event, warning: 'This is an on-screen / LED-only demonstration. Client results are not secure identity proof.' });
});

app.use('/api', (_req, res) => errors(res, 404, 'API endpoint not found.'));
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');
if (fs.existsSync(path.join(dist, 'index.html'))) {
  app.use(express.static(dist));
  app.get(/.*/, (_req, res) => res.sendFile(path.join(dist, 'index.html')));
}
app.use((err, _req, res, _next) => {
  console.error(err); errors(res, 500, 'An unexpected server error occurred. Check server logs.');
});
const port = Number(process.env.PORT || 3001);
app.listen(port, '0.0.0.0', () => console.log(`SMART DRIVE GUARD listening on :${port} (LED demo only)`));
