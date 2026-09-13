import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
app.use(cors());
app.use(express.json({ limit: '256kb' }));

const children = new Map();
const pairings = new Map();
// Parent tarafından silinen cihaz kimlikleri. Çocuk uygulaması tekrar bağlanıp
// aynı cihazı otomatik olarak yeniden oluşturamasın.
const deletedChildIds = new Set();

function parentAuth(req, res, next) {
  const token = String(req.header('x-api-key') || '').trim();
  const candidates = [
    process.env.API_KEY,
    process.env.PARENT_CONTROL_API_KEY,
    process.env.SETUP_KEY,
    process.env.PARENT_CONTROL_SETUP_KEY
  ].map(v => String(v || '').trim()).filter(Boolean);

  const matched = candidates.some(valid => {
    const a = Buffer.from(token);
    const b = Buffer.from(valid);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });

  if (!matched) {
    return res.status(401).json({ error: 'unauthorized', message: 'API_KEY eşleşmedi' });
  }
  req.authRole = 'parent';
  next();
}

// Child APK bootstrap authentication. This key is used only to obtain a per-device token.
function bootstrapAuth(req, res, next) {
  // Render environment variables sometimes contain accidental whitespace after paste.
  // Normalize both the incoming header and the configured value before comparing.
  const token = String(req.header('x-setup-key') || req.header('x-api-key') || '').trim();
  const candidates = [
    process.env.SETUP_KEY,
    process.env.PARENT_CONTROL_SETUP_KEY,
    process.env.API_KEY
  ].map(v => String(v || '').trim()).filter(Boolean);

  const matched = candidates.some(valid => {
    const a = Buffer.from(token);
    const b = Buffer.from(valid);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });

  if (!matched) {
    return res.status(401).json({
      error: 'unauthorized_bootstrap',
      message: 'SETUP_KEY eşleşmedi'
    });
  }
  req.authRole = 'bootstrap';
  next();
}

function childAuth(req, res, next) {
  const childId = String(req.body?.childId || req.params?.childId || '');
  const token = req.header('x-device-token');
  const child = children.get(childId);
  if (!child || !token || token.length !== child.deviceToken.length || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(child.deviceToken))) {
    return res.status(401).json({ error: 'unauthorized_device' });
  }
  req.child = child;
  req.authRole = 'child';
  next();
}


function pairingAuth(req, res, next) {
  // Child pairing is authenticated by the per-device token returned by /register.
  // Check it first so the pairing endpoint never accidentally requires the
  // parent's API_KEY when called from the child device.
  const childId = String(req.body?.childId || '').trim();
  const deviceToken = String(req.header('x-device-token') || '').trim();
  const child = children.get(childId);
  if (child && deviceToken && deviceToken.length === child.deviceToken.length &&
      crypto.timingSafeEqual(Buffer.from(deviceToken), Buffer.from(child.deviceToken))) {
    req.child = child;
    req.authRole = 'child';
    return next();
  }

  // Keep parent API-key compatibility for older clients.
  const parentToken = String(req.header('x-api-key') || '').trim();
  const parentCandidates = [
    process.env.API_KEY,
    process.env.PARENT_CONTROL_API_KEY
  ].map(v => String(v || '').trim()).filter(Boolean);
  const matched = parentCandidates.some(valid => {
    const a = Buffer.from(parentToken);
    const b = Buffer.from(valid);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
  if (matched) return parentAuth(req, res, next);

  return res.status(401).json({ error: 'unauthorized_pairing' });
}

function createChild(childId, name = 'Çocuk') {
  return {
    childId,
    name,
    usage: [],
    installedApps: [],
    location: null,
    locationHistory: [],
    battery: null,
    network: 'Bilinmiyor',
    notificationEvents: [],
    policy: { blocked: [], limits: {} },
    commands: [],
    deviceToken: crypto.randomBytes(32).toString('hex'),
    lastSeen: Date.now()
  };
}

app.get('/health', (req, res) => res.json({ ok: true }));

// Safe diagnostic endpoint: reveals only whether server secrets are configured.
app.get('/config-status', (req, res) => {
  res.json({
    ok: true,
    apiKeyConfigured: Boolean(String(process.env.API_KEY || '').trim()),
    setupKeyConfigured: Boolean(String(process.env.SETUP_KEY || process.env.PARENT_CONTROL_SETUP_KEY || '').trim())
  });
});

// Bootstrap endpoint: only the parent API key may provision/refresh a device token.
app.post('/register', bootstrapAuth, (req, res) => {
  const { childId, name } = req.body || {};
  if (!childId) return res.status(400).json({ error: 'childId' });
  // Ebeveyn cihazı silmiş olsa bile aynı fiziksel cihaz SETUP_KEY ile yeniden kayıt olabilir.
  // Eski v36 davranışındaki 410 burada yeniden eşleştirmeyi engelliyordu.
  deletedChildIds.delete(String(childId));

  let child = children.get(childId);
  if (!child) {
    child = createChild(childId, name || 'Çocuk');
    children.set(childId, child);
  } else {
    if (name) child.name = String(name).slice(0, 80);
    child.lastSeen = Date.now();
  }
  res.json({ childId: child.childId, name: child.name, deviceToken: child.deviceToken });
});

app.post('/pairing/start', pairingAuth, (req, res) => {
  const { childId, name } = req.body || {};
  if (!childId) return res.status(400).json({ error: 'childId' });
  let child = children.get(childId);
  if (!child) {
    child = createChild(childId, name || 'Çocuk');
    children.set(childId, child);
  } else {
    if (name) child.name = String(name).slice(0, 80);
    child.lastSeen = Date.now();
  }
  let code;
  do { code = String(Math.floor(100000 + Math.random() * 900000)); } while (pairings.has(code));
  const expiresAt = Date.now() + 10 * 60 * 1000;
  pairings.set(code, { childId, expiresAt });
  res.json({ code, expiresAt, childId, name: child.name });
});

app.post('/pairing/claim', parentAuth, (req, res) => {
  const code = String(req.body?.code || '').trim();
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'invalid_code' });
  const pairing = pairings.get(code);
  if (!pairing) return res.status(404).json({ error: 'code_not_found' });
  if (pairing.expiresAt < Date.now()) {
    pairings.delete(code);
    return res.status(410).json({ error: 'code_expired' });
  }
  const child = children.get(pairing.childId);
  pairings.delete(code);
  if (!child) return res.status(404).json({ error: 'child_not_found' });
  res.json({ childId: child.childId, name: child.name, location: child.location, lastSeen: child.lastSeen });
});

app.post('/telemetry', childAuth, (req, res) => {
  const { usage, installedApps, location, battery, network, notificationEvents } = req.body || {};
  const c = req.child;
  if (Array.isArray(usage)) c.usage = usage;
  if (Array.isArray(notificationEvents)) c.notificationEvents = notificationEvents.map(e => ({
    app: String(e?.app || '').slice(0, 120),
    person: String(e?.person || '').slice(0, 160),
    type: String(e?.type || 'Bildirim').slice(0, 80),
    time: Number(e?.time) || Date.now()
  })).filter(e => e.app).slice(-100);
  if (Array.isArray(installedApps)) c.installedApps = installedApps.map(a => ({
    package: String(a?.package || ''),
    name: String(a?.name || a?.package || '').slice(0, 160),
    minutes: Number(a?.minutes) || 0
  })).filter(a => a.package);
  if (location && Number.isFinite(Number(location.lat)) && Number.isFinite(Number(location.lon))) {
    c.location = { lat: Number(location.lat), lon: Number(location.lon), time: Number(location.time) || Date.now() };
    c.locationHistory.push(c.location);
    if (c.locationHistory.length > 100) c.locationHistory.shift();
  }
  if (Number.isFinite(Number(battery))) c.battery = Math.max(0, Math.min(100, Number(battery)));
  if (network) c.network = String(network).slice(0, 40);
  c.lastSeen = Date.now();

  const commands = c.commands.splice(0, 10);
  res.json({ ...c.policy, commands });
});

app.post('/children/:childId/name', parentAuth, (req, res) => {
  const childId = String(req.params.childId || '');
  const name = String(req.body?.name || '').trim();
  const c = children.get(childId);
  if (!c) return res.status(404).json({ error: 'child_not_found' });
  if (!name) return res.status(400).json({ error: 'name_required' });
  c.name = name.slice(0, 80);
  c.lastSeen = Date.now();
  res.json({ childId: c.childId, name: c.name });
});

app.get('/children', parentAuth, (req, res) => {
  res.json([...children.values()].map(({ childId, name, usage, installedApps, notificationEvents, location, locationHistory, battery, network, policy, lastSeen }) => ({
    childId, name, usage, installedApps, notificationEvents, location, locationHistory, battery, network, policy, lastSeen
  })));
});

app.delete('/children/:childId', parentAuth, (req, res) => {
  const childId = String(req.params.childId || '').trim();
  if (!childId) return res.status(400).json({ error: 'childId' });

  // Silme idempotent olsun: kayıt zaten yoksa bile ebeveyn tarafı başarı kabul edebilir.
  children.delete(childId);
  deletedChildIds.add(childId);
  for (const [code, pairing] of pairings.entries()) {
    if (pairing.childId === childId) pairings.delete(code);
  }
  res.json({ ok: true, childId, removed: true });
});

app.get('/children/:childId/history', parentAuth, (req, res) => {
  const c = children.get(String(req.params.childId || ''));
  if (!c) return res.status(404).json({ error: 'child_not_found' });
  res.json({ history: c.locationHistory || [] });
});

app.post('/policy', parentAuth, (req, res) => {
  const { childId, policy } = req.body || {};
  const c = children.get(childId);
  if (!c) return res.status(404).json({ error: 'child_not_found' });

  c.policy = {
    blocked: Array.isArray(policy?.blocked) ? policy.blocked : [],
    limits: policy?.limits && typeof policy.limits === 'object' ? policy.limits : {}
  };
  if (Number.isFinite(Number(policy?.globalLimit))) c.policy.globalLimit = Number(policy.globalLimit);
  res.json({ ok: true, policy: c.policy });
});

app.post('/children/:childId/ring', parentAuth, (req, res) => {
  const childId = String(req.params.childId || '');
  const c = children.get(childId);
  if (!c) return res.status(404).json({ error: 'child_not_found' });
  c.commands.push({ id: crypto.randomUUID(), type: 'ring', createdAt: Date.now() });
  res.json({ ok: true });
});

// Backward-compatible aliases for older parent APKs / reverse proxies.
app.post('/ring/:childId', parentAuth, (req, res) => {
  const childId = String(req.params.childId || '');
  const c = children.get(childId);
  if (!c) return res.status(404).json({ error: 'child_not_found' });
  c.commands.push({ id: crypto.randomUUID(), type: 'ring', createdAt: Date.now() });
  res.json({ ok: true });
});

app.post('/children/:childId/command/ring', parentAuth, (req, res) => {
  const childId = String(req.params.childId || '');
  const c = children.get(childId);
  if (!c) return res.status(404).json({ error: 'child_not_found' });
  c.commands.push({ id: crypto.randomUUID(), type: 'ring', createdAt: Date.now() });
  res.json({ ok: true });
});

app.listen(process.env.PORT || 8080, () => {
  console.log('Parent Control server running');
});
