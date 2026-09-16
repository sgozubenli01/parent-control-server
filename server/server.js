import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import pg from 'pg';

const { Pool } = pg;

const app = express();
app.use(cors());
app.use(express.json({ limit: '256kb' }));

const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();
if (!DATABASE_URL) {
  console.error('DATABASE_URL is missing. Render PostgreSQL bağlantısını ekleyin.');
}

const pool = new Pool({
  connectionString: DATABASE_URL || undefined,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: Number(process.env.DB_POOL_MAX || 5),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => console.error('PostgreSQL pool error:', err));

function dayKey() {
  return new Date().toISOString().slice(0, 10);
}

function safeJson(value, fallback) {
  return value == null ? fallback : value;
}

function createChildObject(row) {
  return {
    childId: row.child_id,
    name: row.name,
    profileId: row.profile_id || row.child_id,
    deviceName: row.device_name || 'Çocuk cihazı',
    usage: safeJson(row.usage, []),
    usageHistory: safeJson(row.usage_history, {}),
    installedApps: safeJson(row.installed_apps, []),
    location: safeJson(row.location, null),
    locationHistory: safeJson(row.location_history, []),
    battery: row.battery == null ? null : Number(row.battery),
    network: row.network || 'Bilinmiyor',
    notificationEvents: safeJson(row.notification_events, []),
    policy: safeJson(row.policy, { blocked: [], limits: {} }),
    extraMinutes: Number(row.extra_minutes || 0),
    extraMinutesDate: row.extra_minutes_date ? String(row.extra_minutes_date).slice(0, 10) : dayKey(),
    extraTimeRequest: safeJson(row.extra_time_request, null),
    uninstallRequest: safeJson(row.uninstall_request, null),
    manualLocked: Boolean(row.manual_locked),
    lastSeen: Number(row.last_seen || Date.now())
  };
}

function rowToChild(row) {
  return createChildObject(row);
}

async function getChild(childId) {
  const { rows } = await pool.query('SELECT * FROM children WHERE child_id = $1', [String(childId)]);
  return rows[0] || null;
}

async function ensureExtraTimeDay(child) {
  const today = dayKey();
  if (String(child.extraMinutesDate || '').slice(0, 10) !== today) {
    child.extraMinutesDate = today;
    child.extraMinutes = 0;
    await pool.query(
      'UPDATE children SET extra_minutes = 0, extra_minutes_date = $2, extra_time_request = NULL WHERE child_id = $1',
      [child.childId, today]
    );
  }
}

async function saveChild(child) {
  await pool.query(`
    UPDATE children SET
      name = $2,
      usage = $3::jsonb,
      usage_history = $4::jsonb,
      installed_apps = $5::jsonb,
      location = $6::jsonb,
      location_history = $7::jsonb,
      battery = $8,
      network = $9,
      notification_events = $10::jsonb,
      policy = $11::jsonb,
      extra_minutes = $12,
      extra_minutes_date = $13,
      extra_time_request = $14::jsonb,
      manual_locked = $15,
      last_seen = $16
    WHERE child_id = $1
  `, [
    child.childId,
    child.name,
    JSON.stringify(child.usage || []),
    JSON.stringify(child.usageHistory || {}),
    JSON.stringify(child.installedApps || []),
    child.location == null ? null : JSON.stringify(child.location),
    JSON.stringify(child.locationHistory || []),
    child.battery == null ? null : Number(child.battery),
    child.network || 'Bilinmiyor',
    JSON.stringify(child.notificationEvents || []),
    JSON.stringify(child.policy || { blocked: [], limits: {} }),
    Number(child.extraMinutes || 0),
    child.extraMinutesDate || dayKey(),
    child.extraTimeRequest == null ? null : JSON.stringify(child.extraTimeRequest),
    Boolean(child.manualLocked),
    Number(child.lastSeen || Date.now())
  ]);
}

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

  if (!matched) return res.status(401).json({ error: 'unauthorized', message: 'API_KEY eşleşmedi' });
  req.authRole = 'parent';
  next();
}

function bootstrapAuth(req, res, next) {
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

  if (!matched) return res.status(401).json({ error: 'unauthorized_bootstrap', message: 'SETUP_KEY eşleşmedi' });
  req.authRole = 'bootstrap';
  next();
}

async function childAuth(req, res, next) {
  try {
    const childId = String(req.body?.childId || req.params?.childId || '').trim();
    const token = String(req.header('x-device-token') || '').trim();
    const child = await getChild(childId);
    if (!child || !token) return res.status(401).json({ error: 'unauthorized_device' });
    const valid = String(child.device_token || '');
    if (token.length !== valid.length || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(valid))) {
      return res.status(401).json({ error: 'unauthorized_device' });
    }
    req.child = rowToChild(child);
    req.childRow = child;
    req.authRole = 'child';
    next();
  } catch (err) {
    console.error('childAuth error:', err);
    res.status(500).json({ error: 'database_error' });
  }
}

async function pairingAuth(req, res, next) {
  try {
    const childId = String(req.body?.childId || '').trim();
    const deviceToken = String(req.header('x-device-token') || '').trim();
    if (childId && deviceToken) {
      const child = await getChild(childId);
      const valid = child?.device_token || '';
      if (child && deviceToken.length === valid.length && crypto.timingSafeEqual(Buffer.from(deviceToken), Buffer.from(valid))) {
        req.child = rowToChild(child);
        req.childRow = child;
        req.authRole = 'child';
        return next();
      }
    }

    const parentToken = String(req.header('x-api-key') || '').trim();
    const parentCandidates = [process.env.API_KEY, process.env.PARENT_CONTROL_API_KEY]
      .map(v => String(v || '').trim()).filter(Boolean);
    const matched = parentCandidates.some(valid => {
      const a = Buffer.from(parentToken);
      const b = Buffer.from(valid);
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    });
    if (matched) return parentAuth(req, res, next);
    return res.status(401).json({ error: 'unauthorized_pairing' });
  } catch (err) {
    console.error('pairingAuth error:', err);
    res.status(500).json({ error: 'database_error' });
  }
}

async function createChild(childId, name = 'Çocuk', deviceName = 'Android cihaz') {
  const id = String(childId).trim();
  const childName = String(name || 'Çocuk').slice(0, 80);
  const deviceLabel = String(deviceName || 'Android cihaz').slice(0, 120);
  const deviceToken = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const today = dayKey();
  const { rows } = await pool.query(`
    INSERT INTO children (
      child_id, name, profile_id, device_name, usage, installed_apps, location, location_history,
      battery, network, notification_events, policy, extra_minutes,
      extra_minutes_date, extra_time_request, manual_locked, device_token, last_seen
    ) VALUES ($1, $2, $1, $3, '[]'::jsonb, '[]'::jsonb, NULL, '[]'::jsonb,
              NULL, 'Bilinmiyor', '[]'::jsonb, $4::jsonb, 0, $5, NULL, false, $6, $7)
    ON CONFLICT (child_id) DO UPDATE SET
      name = EXCLUDED.name,
      device_name = EXCLUDED.device_name,
      last_seen = EXCLUDED.last_seen
    RETURNING *
  `, [id, childName, deviceLabel, JSON.stringify({ blocked: [], limits: {} }), today, deviceToken, now]);
  return rows[0];
}

app.get('/health', async (req, res) => {
  try {
    const r = await pool.query('SELECT 1 AS ok');
    res.json({ ok: true, database: r.rows[0]?.ok === 1 });
  } catch (err) {
    console.error('health database error:', err);
    res.status(503).json({ ok: false, database: false });
  }
});

app.get('/config-status', (req, res) => {
  res.json({
    ok: true,
    apiKeyConfigured: Boolean(String(process.env.API_KEY || '').trim()),
    setupKeyConfigured: Boolean(String(process.env.SETUP_KEY || process.env.PARENT_CONTROL_SETUP_KEY || '').trim()),
    databaseConfigured: Boolean(DATABASE_URL)
  });
});

app.post('/register', bootstrapAuth, async (req, res) => {
  try {
    const { childId, name } = req.body || {};
    if (!childId) return res.status(400).json({ error: 'childId' });
    const id = String(childId).trim();
    await pool.query('DELETE FROM deleted_child_ids WHERE child_id = $1', [id]);
    let child = await getChild(id);
    if (!child) child = await createChild(id, name || 'Çocuk', req.body?.deviceName || 'Android cihaz');
    else {
      if (name) await pool.query('UPDATE children SET name = $2, device_name = $3, last_seen = $4 WHERE child_id = $1', [id, String(name).slice(0, 80), String(req.body?.deviceName || child.device_name || 'Android cihaz').slice(0, 120), Date.now()]);
      else await pool.query('UPDATE children SET last_seen = $2 WHERE child_id = $1', [id, Date.now()]);
      child = await getChild(id);
    }
    res.json({ childId: child.child_id, name: child.name, deviceToken: child.device_token });
  } catch (err) {
    console.error('/register error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/pairing/start', pairingAuth, async (req, res) => {
  try {
    const { childId, name } = req.body || {};
    if (!childId) return res.status(400).json({ error: 'childId' });
    const id = String(childId).trim();
    let child = await getChild(id);
    if (!child) child = await createChild(id, name || 'Çocuk', req.body?.deviceName || 'Android cihaz');
    else {
      if (name) await pool.query('UPDATE children SET name = $2, device_name = $3, last_seen = $4 WHERE child_id = $1', [id, String(name).slice(0, 80), String(req.body?.deviceName || child.device_name || 'Android cihaz').slice(0, 120), Date.now()]);
      child = await getChild(id);
    }

    let code;
    do { code = String(Math.floor(100000 + Math.random() * 900000)); }
    while ((await pool.query('SELECT 1 FROM pairings WHERE code = $1', [code])).rowCount > 0);
    const expiresAt = Date.now() + 10 * 60 * 1000;
    await pool.query('INSERT INTO pairings (code, child_id, expires_at) VALUES ($1, $2, $3)', [code, id, expiresAt]);
    res.json({ code, expiresAt, childId: id, name: child.name });
  } catch (err) {
    console.error('/pairing/start error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/pairing/claim', parentAuth, async (req, res) => {
  try {
    const code = String(req.body?.code || '').trim();
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'invalid_code' });
    const { rows } = await pool.query('SELECT * FROM pairings WHERE code = $1', [code]);
    const pairing = rows[0];
    if (!pairing) return res.status(404).json({ error: 'code_not_found' });
    if (Number(pairing.expires_at) < Date.now()) {
      await pool.query('DELETE FROM pairings WHERE code = $1', [code]);
      return res.status(410).json({ error: 'code_expired' });
    }
    await pool.query('DELETE FROM pairings WHERE code = $1', [code]);
    const child = await getChild(pairing.child_id);
    if (!child) return res.status(404).json({ error: 'child_not_found' });
    res.json({ childId: child.child_id, name: child.name, profileId: child.profile_id || child.child_id, deviceName: child.device_name || 'Çocuk cihazı', location: safeJson(child.location, null), lastSeen: Number(child.last_seen || Date.now()) });
  } catch (err) {
    console.error('/pairing/claim error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/telemetry', childAuth, async (req, res) => {
  const c = req.child;
  try {
    const { usage, installedApps, location, battery, network, notificationEvents } = req.body || {};
    if (Array.isArray(usage)) {
      c.usage = usage;
      c.usageHistory = { ...(c.usageHistory || {}), [dayKey()]: usage };
      const keys = Object.keys(c.usageHistory).sort();
      while (keys.length > 14) delete c.usageHistory[keys.shift()];
    }
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
    await ensureExtraTimeDay(c);

    await saveChild(c);

    const client = await pool.connect();
    let commands = [];
    try {
      await client.query('BEGIN');
      // Komutları telemetry yanıtında göster ama burada silme.
      // Çocuk komutu gerçekten uyguladıktan sonra /commands/:id/ack ile siler.
      // Böylece ağ yanıtı kaybolursa komut kaybolmaz.
      const picked = await client.query(`
        SELECT id, type, minutes, created_at
        FROM commands
        WHERE child_id = $1
        ORDER BY created_at ASC
        LIMIT 10
      `, [c.childId]);
      await client.query('COMMIT');
      commands = picked.rows.map(r => ({ id: r.id, type: r.type, minutes: r.minutes == null ? undefined : Number(r.minutes), createdAt: Number(r.created_at) }));
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    const effectivePolicy = { ...c.policy };
    if (Number.isFinite(Number(effectivePolicy.globalLimit))) {
      effectivePolicy.globalLimit = Number(effectivePolicy.globalLimit) + Number(c.extraMinutes || 0);
    }
    res.json({ ...effectivePolicy, extraMinutes: Number(c.extraMinutes || 0), extraTimeRequest: c.extraTimeRequest, manualLocked: Boolean(c.manualLocked), commands });
  } catch (err) {
    console.error('/telemetry error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/children/:childId/name', parentAuth, async (req, res) => {
  try {
    const childId = String(req.params.childId || '').trim();
    const name = String(req.body?.name || '').trim();
    if (!name) return res.status(400).json({ error: 'name_required' });
    const r = await pool.query('UPDATE children SET name = $2, last_seen = $3 WHERE child_id = $1 RETURNING child_id, name', [childId, name.slice(0, 80), Date.now()]);
    if (!r.rowCount) return res.status(404).json({ error: 'child_not_found' });
    res.json({ childId: r.rows[0].child_id, name: r.rows[0].name });
  } catch (err) {
    console.error('/children/:childId/name error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.get('/children', parentAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM children ORDER BY child_id');
    const result = [];
    for (const row of rows) {
      const c = rowToChild(row);
      if (c.extraMinutesDate !== dayKey()) await ensureExtraTimeDay(c);
      result.push({
        childId: c.childId,
        name: c.name,
        profileId: c.profileId,
        deviceName: c.deviceName,
        usage: c.usage,
        usageHistory: c.usageHistory,
        installedApps: c.installedApps,
        notificationEvents: c.notificationEvents,
        location: c.location,
        locationHistory: c.locationHistory,
        battery: c.battery,
        network: c.network,
        policy: c.policy,
        extraMinutes: Number(c.extraMinutes || 0),
        extraTimeRequest: c.extraTimeRequest,
        uninstallRequest: c.uninstallRequest,
        manualLocked: Boolean(c.manualLocked),
        lastSeen: c.lastSeen
      });
    }
    res.json(result);
  } catch (err) {
    console.error('/children error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/children/:childId/profile', parentAuth, async (req, res) => {
  try {
    const childId = String(req.params.childId || '').trim();
    const profileId = String(req.body?.profileId || '').trim().slice(0, 120);
    if (!profileId) return res.status(400).json({ error: 'profileId_required' });
    const r = await pool.query('UPDATE children SET profile_id = $2 WHERE child_id = $1 RETURNING child_id, profile_id', [childId, profileId]);
    if (!r.rowCount) return res.status(404).json({ error: 'child_not_found' });
    res.json({ ok: true, childId: r.rows[0].child_id, profileId: r.rows[0].profile_id });
  } catch (err) { console.error('/profile error:', err); res.status(500).json({ error: 'database_error' }); }
});

app.get('/children/:childId/report', parentAuth, async (req, res) => {
  try {
    const child = await getChild(String(req.params.childId || '').trim());
    if (!child) return res.status(404).json({ error: 'child_not_found' });
    const days = Math.max(1, Math.min(14, Number(req.query?.days) || 7));
    const history = safeJson(child.usage_history, {});
    const keys = Object.keys(history).sort().slice(-days);
    const result = keys.map(date => {
      const usage = Array.isArray(history[date]) ? history[date] : [];
      const apps = usage.map(x => ({ package: String(x?.package || ''), name: String(x?.name || x?.package || ''), minutes: Number(x?.minutes || 0) })).filter(x => x.package);
      return { date, totalMinutes: apps.reduce((a,b)=>a+b.minutes,0), apps: apps.sort((a,b)=>b.minutes-a.minutes) };
    });
    res.json({ childId: child.child_id, profileId: child.profile_id || child.child_id, days: result });
  } catch (err) { console.error('/report error:', err); res.status(500).json({ error: 'database_error' }); }
});

app.delete('/children/:childId', parentAuth, async (req, res) => {
  try {
    const childId = String(req.params.childId || '').trim();
    if (!childId) return res.status(400).json({ error: 'childId' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM pairings WHERE child_id = $1', [childId]);
      await client.query('DELETE FROM commands WHERE child_id = $1', [childId]);
      await client.query('DELETE FROM children WHERE child_id = $1', [childId]);
      await client.query('INSERT INTO deleted_child_ids (child_id, deleted_at) VALUES ($1, $2) ON CONFLICT (child_id) DO UPDATE SET deleted_at = EXCLUDED.deleted_at', [childId, Date.now()]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    res.json({ ok: true, childId, removed: true });
  } catch (err) {
    console.error('/children/:childId delete error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.get('/children/:childId/history', parentAuth, async (req, res) => {
  try {
    const child = await getChild(String(req.params.childId || '').trim());
    if (!child) return res.status(404).json({ error: 'child_not_found' });
    res.json({ history: safeJson(child.location_history, []) });
  } catch (err) {
    console.error('/history error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/policy', parentAuth, async (req, res) => {
  try {
    const { childId, policy } = req.body || {};
    const c = await getChild(childId);
    if (!c) return res.status(404).json({ error: 'child_not_found' });
    const nextPolicy = {
      blocked: Array.isArray(policy?.blocked) ? policy.blocked : [],
      limits: policy?.limits && typeof policy.limits === 'object' ? policy.limits : {}
    };
    if (Number.isFinite(Number(policy?.globalLimit))) nextPolicy.globalLimit = Number(policy.globalLimit);
    await pool.query('UPDATE children SET policy = $2::jsonb WHERE child_id = $1', [String(childId), JSON.stringify(nextPolicy)]);
    res.json({ ok: true, policy: nextPolicy });
  } catch (err) {
    console.error('/policy error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/uninstall-request', childAuth, async (req, res) => {
  try {
    const c = req.child;
    const now = Date.now();
    const current = safeJson(c.uninstall_request, null);
    // Do not spam the parent with repeated requests while the same attempt is visible.
    if (current?.pending && now - Number(current.requestedAt || 0) < 60 * 60 * 1000) {
      return res.json({ ok: true, request: current, duplicate: true });
    }
    const request = { pending: true, requestedAt: now, reason: 'uninstall_attempt' };
    await pool.query('UPDATE children SET uninstall_request = $2::jsonb WHERE child_id = $1', [c.childId, JSON.stringify(request)]);
    res.json({ ok: true, request });
  } catch (err) {
    console.error('/uninstall-request error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/extra-time/request', childAuth, async (req, res) => {
  try {
    const c = req.child;
    await ensureExtraTimeDay(c);
    c.extraTimeRequest = { pending: true, requestedAt: Date.now() };
    await pool.query('UPDATE children SET extra_time_request = $2::jsonb WHERE child_id = $1', [c.childId, JSON.stringify(c.extraTimeRequest)]);
    res.json({ ok: true, request: c.extraTimeRequest });
  } catch (err) {
    console.error('/extra-time/request error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

async function pushCommand(childId, type, minutes = null) {
  await pool.query(
    'INSERT INTO commands (id, child_id, type, minutes, created_at) VALUES ($1, $2, $3, $4, $5)',
    [crypto.randomUUID(), String(childId), type, minutes == null ? null : Number(minutes), Date.now()]
  );
}

app.post('/children/:childId/uninstall/approve', parentAuth, async (req, res) => {
  try {
    const childId = String(req.params.childId || '').trim();
    const c = await getChild(childId);
    if (!c) return res.status(404).json({ error: 'child_not_found' });
    const request = safeJson(c.uninstall_request, null);
    if (!request?.pending) return res.status(409).json({ error: 'no_pending_uninstall_request' });
    const approved = { pending: false, approved: true, approvedAt: Date.now() };
    await pool.query('UPDATE children SET uninstall_request = $2::jsonb WHERE child_id = $1', [childId, JSON.stringify(approved)]);
    await pushCommand(childId, 'approve_uninstall');
    res.json({ ok: true, command: 'approve_uninstall' });
  } catch (err) {
    console.error('/uninstall/approve error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/children/:childId/uninstall/reject', parentAuth, async (req, res) => {
  try {
    const childId = String(req.params.childId || '').trim();
    const c = await getChild(childId);
    if (!c) return res.status(404).json({ error: 'child_not_found' });
    const rejected = { pending: false, approved: false, rejectedAt: Date.now() };
    await pool.query('UPDATE children SET uninstall_request = $2::jsonb WHERE child_id = $1', [childId, JSON.stringify(rejected)]);
    res.json({ ok: true, rejected: true });
  } catch (err) {
    console.error('/uninstall/reject error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/children/:childId/extra-time/approve', parentAuth, async (req, res) => {
  try {
    const childId = String(req.params.childId || '').trim();
    const minutes = Math.max(5, Math.min(240, Number(req.body?.minutes) || 0));
    const c = await getChild(childId);
    if (!c) return res.status(404).json({ error: 'child_not_found' });
    const extraDate = c.extra_minutes_date ? String(c.extra_minutes_date).slice(0, 10) : dayKey();
    let extraMinutes = Number(c.extra_minutes || 0);
    if (extraDate !== dayKey()) extraMinutes = 0;
    const request = safeJson(c.extra_time_request, null);
    if (!request?.pending) return res.status(409).json({ error: 'no_pending_request' });
    extraMinutes += minutes;
    const approved = { pending: false, approvedMinutes: minutes, approvedAt: Date.now() };
    await pool.query('UPDATE children SET extra_minutes = $2, extra_minutes_date = $3, extra_time_request = $4::jsonb WHERE child_id = $1', [childId, extraMinutes, dayKey(), JSON.stringify(approved)]);
    await pushCommand(childId, 'extra_time', minutes);
    res.json({ ok: true, minutes, extraMinutes });
  } catch (err) {
    console.error('/extra-time/approve error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/children/:childId/lock', parentAuth, async (req, res) => {
  try {
    const childId = String(req.params.childId || '').trim();
    const r = await pool.query('UPDATE children SET manual_locked = true WHERE child_id = $1 RETURNING child_id', [childId]);
    if (!r.rowCount) return res.status(404).json({ error: 'child_not_found' });
    await pushCommand(childId, 'lock');
    res.json({ ok: true, manualLocked: true });
  } catch (err) {
    console.error('/lock error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

app.post('/commands/:commandId/ack', childAuth, async (req, res) => {
  try {
    const commandId = String(req.params.commandId || '').trim();
    if (!commandId) return res.status(400).json({ error: 'command_id_required' });
    const r = await pool.query(
      'DELETE FROM commands WHERE id = $1 AND child_id = $2 RETURNING id',
      [commandId, req.child.childId]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'command_not_found' });
    res.json({ ok: true, commandId });
  } catch (err) {
    console.error('/commands/:commandId/ack error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

function serviceCommandHandler(type, label) {
  return async (req, res) => {
    try {
      const childId = String(req.params.childId || '').trim();
      const c = await getChild(childId);
      if (!c) return res.status(404).json({ error: 'child_not_found' });
      await pushCommand(childId, type);
      res.json({ ok: true, command: type });
    } catch (err) {
      console.error(`/children/:childId/${label} error:`, err);
      res.status(500).json({ error: 'database_error' });
    }
  };
}

app.post('/children/:childId/refresh-services', parentAuth, serviceCommandHandler('refresh_services', 'refresh-services'));
app.post('/children/:childId/restart-services', parentAuth, serviceCommandHandler('restart_services', 'restart-services'));

// Tek ve kararlı komut endpoint'i. Ebeveyn APK'sı bundan sonra komutu
// { type: 'refresh_services' | 'restart_services' } gövdesiyle gönderir.
// Eski endpoint'ler geriye dönük uyumluluk için korunur.
app.post('/children/:childId/command', parentAuth, async (req, res) => {
  const type = String(req.body?.type || '').trim();
  const aliases = new Map([
    ['refresh', 'refresh_services'],
    ['refresh-services', 'refresh_services'],
    ['refresh_services', 'refresh_services'],
    ['restart', 'restart_services'],
    ['restart-services', 'restart_services'],
    ['restart_services', 'restart_services']
  ]);
  const command = aliases.get(type);
  if (!command) return res.status(400).json({ error: 'unknown_command', allowed: ['refresh_services', 'restart_services'] });
  return serviceCommandHandler(command, 'command')(req, res);
});

// Komut endpoint'leri için geriye dönük uyumluluk. Bazı eski ebeveyn APK'ları
// /command/:type veya /services/:type yolunu kullanabilir.
app.post('/children/:childId/command/:type', parentAuth, async (req, res) => {
  const type = String(req.params.type || '').trim();
  const allowed = new Map([['refresh', 'refresh_services'], ['refresh-services', 'refresh_services'], ['restart', 'restart_services'], ['restart-services', 'restart_services']]);
  const command = allowed.get(type);
  if (!command) return res.status(400).json({ error: 'unknown_command' });
  return serviceCommandHandler(command, `command-${type}`)(req, res);
});
app.post('/children/:childId/services/:type', parentAuth, async (req, res) => {
  const type = String(req.params.type || '').trim();
  const allowed = new Map([['refresh', 'refresh_services'], ['refresh-services', 'refresh_services'], ['restart', 'restart_services'], ['restart-services', 'restart_services']]);
  const command = allowed.get(type);
  if (!command) return res.status(400).json({ error: 'unknown_command' });
  return serviceCommandHandler(command, `services-${type}`)(req, res);
});

app.post('/children/:childId/unlock', parentAuth, async (req, res) => {
  try {
    const childId = String(req.params.childId || '').trim();
    const r = await pool.query('UPDATE children SET manual_locked = false WHERE child_id = $1 RETURNING child_id', [childId]);
    if (!r.rowCount) return res.status(404).json({ error: 'child_not_found' });
    await pushCommand(childId, 'unlock');
    res.json({ ok: true, manualLocked: false });
  } catch (err) {
    console.error('/unlock error:', err);
    res.status(500).json({ error: 'database_error' });
  }
});

async function ringHandler(req, res) {
  try {
    const childId = String(req.params.childId || '').trim();
    const c = await getChild(childId);
    if (!c) return res.status(404).json({ error: 'child_not_found' });
    await pushCommand(childId, 'ring');
    res.json({ ok: true });
  } catch (err) {
    console.error('/ring error:', err);
    res.status(500).json({ error: 'database_error' });
  }
}

app.post('/children/:childId/ring', parentAuth, ringHandler);
app.post('/ring/:childId', parentAuth, ringHandler);
app.post('/children/:childId/command/ring', parentAuth, ringHandler);

async function initDb() {
  if (!DATABASE_URL) throw new Error('DATABASE_URL missing');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS children (
      child_id TEXT PRIMARY KEY,
      name TEXT NOT NULL DEFAULT 'Çocuk',
      profile_id TEXT NOT NULL DEFAULT '',
      device_name TEXT NOT NULL DEFAULT 'Çocuk cihazı',
      usage JSONB NOT NULL DEFAULT '[]'::jsonb,
      usage_history JSONB NOT NULL DEFAULT '{}'::jsonb,
      installed_apps JSONB NOT NULL DEFAULT '[]'::jsonb,
      location JSONB,
      location_history JSONB NOT NULL DEFAULT '[]'::jsonb,
      battery DOUBLE PRECISION,
      network TEXT NOT NULL DEFAULT 'Bilinmiyor',
      notification_events JSONB NOT NULL DEFAULT '[]'::jsonb,
      policy JSONB NOT NULL DEFAULT '{"blocked":[],"limits":{}}'::jsonb,
      extra_minutes INTEGER NOT NULL DEFAULT 0,
      extra_minutes_date DATE NOT NULL DEFAULT CURRENT_DATE,
      extra_time_request JSONB,
      uninstall_request JSONB,
      manual_locked BOOLEAN NOT NULL DEFAULT false,
      device_token TEXT NOT NULL,
      last_seen BIGINT NOT NULL DEFAULT 0
    );
    ALTER TABLE children ADD COLUMN IF NOT EXISTS profile_id TEXT NOT NULL DEFAULT '';
    ALTER TABLE children ADD COLUMN IF NOT EXISTS device_name TEXT NOT NULL DEFAULT 'Çocuk cihazı';
    ALTER TABLE children ADD COLUMN IF NOT EXISTS usage_history JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE children ADD COLUMN IF NOT EXISTS uninstall_request JSONB;
    UPDATE children SET profile_id = child_id WHERE profile_id = '';

    CREATE TABLE IF NOT EXISTS pairings (
      code TEXT PRIMARY KEY,
      child_id TEXT NOT NULL REFERENCES children(child_id) ON DELETE CASCADE,
      expires_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS commands (
      id TEXT PRIMARY KEY,
      child_id TEXT NOT NULL REFERENCES children(child_id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      minutes INTEGER,
      created_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS commands_child_created_idx ON commands(child_id, created_at);
    CREATE TABLE IF NOT EXISTS deleted_child_ids (
      child_id TEXT PRIMARY KEY,
      deleted_at BIGINT NOT NULL DEFAULT 0
    );
  `);
  console.log('PostgreSQL database ready');
}

async function start() {
  await initDb();
  app.listen(process.env.PORT || 8080, () => {
    console.log('Parent Control server running');
  });
}

start().catch((err) => {
  console.error('Server startup failed:', err);
  process.exit(1);
});
