const JWT_SECRET = 'ega-prod-jwt-2024-secure';
const TOKEN_EXPIRY = 24 * 60 * 60 * 1000;

async function sha256(text) {
  const d = new TextEncoder().encode(text);
  const h = await crypto.subtle.digest('SHA-256', d);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64e(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64d(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function signToken(payload) {
  const h = { alg: 'HS256', typ: 'JWT' };
  const hb = b64e(new TextEncoder().encode(JSON.stringify(h)));
  const pb = b64e(new TextEncoder().encode(JSON.stringify(payload)));
  const msg = hb + '.' + pb;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return msg + '.' + b64e(sig);
}

async function verifyToken(token) {
  try {
    const [hb, pb, sb] = token.split('.');
    if (!hb || !pb || !sb) return null;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, b64d(sb), new TextEncoder().encode(hb + '.' + pb));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64d(pb)));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400'
};

function json(data, status) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json', ...CORS } });
}

function err(msg, status) {
  return json({ error: msg }, status || 400);
}

async function getUser(request) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return await verifyToken(auth.slice(7));
}

async function getBody(request) {
  try { return await request.json(); } catch { return {}; }
}

async function deviceFingerprint(request) {
  const ua = request.headers.get('User-Agent') || '';
  const platform = request.headers.get('Sec-Ch-Ua-Platform') || '';
  return sha256(ua + platform);
}

async function ensureTables(db) {
  await db.prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, phone TEXT DEFAULT '', institution TEXT DEFAULT '', role TEXT DEFAULT 'student', is_approved INTEGER DEFAULT 0, is_blocked INTEGER DEFAULT 0, device_fingerprint TEXT, token_version INTEGER DEFAULT 1, spam_count INTEGER DEFAULT 0, spam_until TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS courses (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT DEFAULT '', subject_area TEXT DEFAULT '', difficulty TEXT DEFAULT 'All Levels', thumbnail_url TEXT DEFAULT '', thumbnail_icon TEXT DEFAULT 'book-open', badge TEXT DEFAULT '', price REAL DEFAULT 0, tree TEXT DEFAULT '[]', resources TEXT DEFAULT '[]', is_featured INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS enrollments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, course_id INTEGER NOT NULL, payment_method TEXT, trx_id TEXT, sender_phone TEXT, status TEXT DEFAULT 'pending', expires_at TEXT, created_at TEXT DEFAULT (datetime('now')), FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (course_id) REFERENCES courses(id))").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)").run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_enrollments_status ON enrollments(status)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_enrollments_user ON enrollments(user_id)').run();
  const adminHash = await sha256('admin123');
  await db.prepare("INSERT OR IGNORE INTO users (name, email, password, role, is_approved) VALUES ('Admin', 'admin@ega.com', ?, 'admin', 1)").bind(adminHash).run();
  await db.prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('bkash_number', '')").run();
  await db.prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('nagad_number', '')").run();
  await db.prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('show_numbers', 'true')").run();
}

export async function onRequest(context) {
  const { request, env } = context;
  const db = env.EGA_DB;
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname.replace('/api', '');
  const body = (method !== 'GET' && method !== 'OPTIONS') ? await getBody(request) : {};

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  if (!globalThis.__egaTablesReady) {
    await ensureTables(db);
    globalThis.__egaTablesReady = true;
  }

  // ─── DEBUG ROUTE ───
  if (method === 'GET' && path === '/debug') {
    try {
      const usersCount = await db.prepare('SELECT COUNT(*) as c FROM users').first();
      const coursesCount = await db.prepare('SELECT COUNT(*) as c FROM courses').first();
      const enrollmentsRaw = await db.prepare('SELECT * FROM enrollments').all();
      const enrollmentsList = enrollmentsRaw.results || [];
      
      // Enrich with names
      const enriched = [];
      for (const e of enrollmentsList) {
        let un = '', ct = '';
        try { const u = await db.prepare('SELECT name FROM users WHERE id=?').bind(e.user_id).first(); if(u) un = u.name; } catch {}
        try { const c = await db.prepare('SELECT title FROM courses WHERE id=?').bind(e.course_id).first(); if(c) ct = c.title; } catch {}
        enriched.push({ ...e, user_name: un || '?', course_title: ct || '?' });
      }
      
      return json({
        users: usersCount?.c || 0,
        courses: coursesCount?.c || 0,
        enrollments_count: enrollmentsList.length,
        enrollments: enriched
      });
    } catch(e) {
      return json({ error: e.message });
    }
  }

  const user = await getUser(request);

  // ─── AUTH ───
  if (method === 'POST' && path === '/auth/signup') {
    const { name, email, password, phone, institution } = body;
    if (!name || !email || !password) return err('Name, email, and password required');
    if (password.length < 6) return err('Password must be at least 6 characters');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('Invalid email format');
    const fp = await deviceFingerprint(request);
    const dc = await db.prepare('SELECT COUNT(*) as c FROM users WHERE device_fingerprint = ?').bind(fp).first();
    if (dc && dc.c >= 3) return err('Maximum accounts reached on this device', 403);
    const ex = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (ex) return err('Email already registered', 409);
    const hash = await sha256(password);
    await db.prepare("INSERT INTO users (name, email, password, phone, institution, device_fingerprint) VALUES (?, ?, ?, ?, ?, ?)").bind(name, email, hash, phone || '', institution || '', fp).run();
    return json({ message: 'Account created. You can now log in.' }, 201);
  }

  if (method === 'POST' && path === '/auth/login') {
    const { email, password } = body;
    if (!email || !password) return err('Email and password required');
    const hash = await sha256(password);
    const u = await db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').bind(email, hash).first();
    if (!u) return err('Invalid credentials', 401);
    if (u.is_blocked) return err('Account blocked', 403);
    const nv = (u.token_version || 1) + 1;
    await db.prepare('UPDATE users SET token_version = ? WHERE id = ?').bind(nv, u.id).run();
    const token = await signToken({ id: u.id, email: u.email, name: u.name, role: u.role, token_version: nv, exp: Date.now() + TOKEN_EXPIRY });
    return json({ token, user: { id: u.id, name: u.name, email: u.email, phone: u.phone, institution: u.institution, role: u.role, is_approved: u.is_approved } });
  }

  if (method === 'POST' && path === '/auth/logout') {
    const u = await getUser(request);
    if (!u) return err('Unauthorized', 401);
    await db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').bind(u.id).run();
    return json({ message: 'Logged out' });
  }

  // ─── PUBLIC ───
  if (method === 'GET' && path === '/courses') {
    const subject = url.searchParams.get('subject');
    const limit = parseInt(url.searchParams.get('limit') || '50');
    let q = 'SELECT * FROM courses WHERE is_active = 1';
    const p = [];
    if (subject) { q += ' AND subject_area = ?'; p.push(subject); }
    q += ' ORDER BY is_featured DESC, created_at DESC LIMIT ?';
    p.push(limit);
    const r = await db.prepare(q).bind(...p).all();
    return json(r.results);
  }

  if (method === 'GET' && path.match(/^\/courses\/\d+$/)) {
    const id = parseInt(path.split('/')[2]);
    const c = await db.prepare('SELECT * FROM courses WHERE id = ? AND is_active = 1').bind(id).first();
    if (!c) return err('Course not found', 404);
    try { c.tree = JSON.parse(c.tree || '[]'); } catch { c.tree = []; }
    try { c.resources = JSON.parse(c.resources || '[]'); } catch { c.resources = []; }
    return json(c);
  }

  if (method === 'GET' && path === '/stats') {
    const courses = await db.prepare('SELECT COUNT(*) as c FROM courses WHERE is_active = 1').first();
    const users = await db.prepare('SELECT COUNT(*) as c FROM users').first();
    const enrollments = await db.prepare("SELECT COUNT(*) as c FROM enrollments WHERE status = 'approved'").first();
    return json({ courses: courses?.c || 0, students: users?.c || 0, enrollments: enrollments?.c || 0 });
  }

  if (method === 'GET' && path === '/meta/payment-info') {
    const bkash = await db.prepare("SELECT value FROM meta WHERE key = 'bkash_number'").first();
    const nagad = await db.prepare("SELECT value FROM meta WHERE key = 'nagad_number'").first();
    const show = await db.prepare("SELECT value FROM meta WHERE key = 'show_numbers'").first();
    return json({ bkash: bkash?.value || '', nagad: nagad?.value || '', show: show?.value !== 'false' });
  }

  if (method === 'POST' && path === '/contact') {
    const { name, email, subject, message } = body;
    if (!name || !email || !message) return err('Name, email, and message required');
    const row = await db.prepare("SELECT value FROM meta WHERE key = 'support_tickets'").first();
    const list = row ? JSON.parse(row.value) : [];
    list.push({ id: Date.now(), name, email, subject, message, status: 'open', created_at: new Date().toISOString() });
    await db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES ('support_tickets', ?)").bind(JSON.stringify(list)).run();
    return json({ message: 'Message sent' }, 201);
  }

  if (!user) return err('Unauthorized', 401);

  // ─── STUDENT ───
  if (method === 'GET' && path === '/user/profile') {
    const u = await db.prepare('SELECT id, name, email, phone, institution, role, is_approved, created_at FROM users WHERE id = ?').bind(user.id).first();
    return u ? json(u) : err('Not found', 404);
  }

  if (method === 'GET' && path === '/user/enrollments') {
    const r = await db.prepare("SELECT e.*, c.title as course_title, c.subject_area, c.thumbnail_url, c.thumbnail_icon, c.difficulty FROM enrollments e JOIN courses c ON e.course_id = c.id WHERE e.user_id = ? AND e.status = 'approved' ORDER BY e.created_at DESC").bind(user.id).all();
    return json(r.results);
  }

  if (method === 'POST' && path === '/payment/submit') {
    const { course_id, method: payMethod, trx_id, phone } = body;
    if (!course_id || !payMethod || !trx_id || !phone) return err('All payment fields required');
    if (!['bkash', 'nagad'].includes(payMethod)) return err('Invalid payment method');
    if (!/^01\d{9}$/.test(phone)) return err('Invalid phone format');
    const course = await db.prepare('SELECT id FROM courses WHERE id = ? AND is_active = 1').bind(course_id).first();
    if (!course) return err('Course not found', 404);
    const spamCount = await db.prepare("SELECT COUNT(*) as c FROM enrollments WHERE user_id = ? AND status = 'spam'").bind(user.id).first();
    if (spamCount && spamCount.c >= 3) return err('Account flagged', 403);
    const existing = await db.prepare("SELECT id FROM enrollments WHERE user_id = ? AND course_id = ? AND status = 'pending'").bind(user.id, course_id).first();
    if (existing) return err('Already have pending payment for this course', 409);
    const result = await db.prepare("INSERT INTO enrollments (user_id, course_id, payment_method, trx_id, sender_phone, status) VALUES (?, ?, ?, ?, ?, 'pending')").bind(user.id, course_id, payMethod, trx_id, phone).run();
    if (!result.success) return err('Database error', 500);
    return json({ message: 'Payment submitted. Admin will verify.' }, 201);
  }

  if (user.role !== 'admin') return err('Forbidden', 403);

  // ─── ADMIN ───
  if (method === 'GET' && path === '/admin/stats') {
    const users = await db.prepare('SELECT COUNT(*) as c FROM users').first();
    const courses = await db.prepare('SELECT COUNT(*) as c FROM courses WHERE is_active = 1').first();
    const pendingPayments = await db.prepare("SELECT COUNT(*) as c FROM enrollments WHERE status = 'pending'").first();
    const activeMembers = await db.prepare("SELECT COUNT(*) as c FROM enrollments WHERE status = 'approved'").first();
    return json({ users: users?.c || 0, courses: courses?.c || 0, pendingPayments: pendingPayments?.c || 0, activeMembers: activeMembers?.c || 0 });
  }

  if (method === 'GET' && path === '/admin/users') {
    const r = await db.prepare('SELECT id, name, email, phone, institution, role, is_approved, is_blocked, created_at FROM users ORDER BY created_at DESC').all();
    return json(r.results);
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/approve$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare("UPDATE users SET is_approved = 1 WHERE id = ?").bind(id).run();
    return json({ message: 'Approved' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/block$/)) {
    const id = parseInt(path.split('/')[3]);
    const u = await db.prepare('SELECT is_blocked FROM users WHERE id = ?').bind(id).first();
    if (!u) return err('Not found', 404);
    await db.prepare('UPDATE users SET is_blocked = ? WHERE id = ?').bind(u.is_blocked ? 0 : 1, id).run();
    return json({ message: u.is_blocked ? 'Unblocked' : 'Blocked' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/clear-device$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET device_fingerprint = NULL WHERE id = ?').bind(id).run();
    return json({ message: 'Cleared' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/users\/\d+$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM enrollments WHERE user_id = ?').bind(id).run();
    await db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
    return json({ message: 'Deleted' });
  }

  if (method === 'GET' && path === '/admin/courses') {
    const r = await db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all();
    return json(r.results);
  }

  if (method === 'POST' && path === '/admin/courses') {
    const { title, description, subject_area, difficulty, thumbnail_url, badge, price, is_featured } = body;
    if (!title) return err('Title required');
    await db.prepare("INSERT INTO courses (title, description, subject_area, difficulty, thumbnail_url, badge, price, is_featured) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(title, description || '', subject_area || '', difficulty || 'All Levels', thumbnail_url || '', badge || '', price || 0, is_featured || 0).run();
    return json({ message: 'Created' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/admin\/courses\/\d+$/)) {
    const id = parseInt(path.split('/')[3]);
    const { title, description, subject_area, difficulty, thumbnail_url, badge, price, is_featured, is_active } = body;
    await db.prepare("UPDATE courses SET title=?, description=?, subject_area=?, difficulty=?, thumbnail_url=?, badge=?, price=?, is_featured=?, is_active=? WHERE id=?").bind(title, description, subject_area, difficulty, thumbnail_url, badge, price, is_featured || 0, is_active !== undefined ? is_active : 1, id).run();
    return json({ message: 'Updated' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/courses\/\d+$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM enrollments WHERE course_id = ?').bind(id).run();
    await db.prepare('DELETE FROM courses WHERE id = ?').bind(id).run();
    return json({ message: 'Deleted' });
  }

  if (method === 'GET' && path === '/admin/enrollments') {
    const r = await db.prepare('SELECT * FROM enrollments ORDER BY created_at DESC LIMIT 500').all();
    const rows = r.results || [];
    const out = [];
    for (const e of rows) {
      let un = '', ue = '', ct = '';
      try { const u = await db.prepare('SELECT name, email FROM users WHERE id = ?').bind(e.user_id).first(); if(u) { un = u.name; ue = u.email; } } catch {}
      try { const c = await db.prepare('SELECT title FROM courses WHERE id = ?').bind(e.course_id).first(); if(c) { ct = c.title; } } catch {}
      out.push({ id: e.id, user_id: e.user_id, course_id: e.course_id, payment_method: e.payment_method, trx_id: e.trx_id, sender_phone: e.sender_phone, status: e.status, expires_at: e.expires_at, created_at: e.created_at, user_name: un || ('User#' + e.user_id), user_email: ue, course_title: ct || ('Course#' + e.course_id) });
    }
    return json(out);
  }

  if (method === 'PUT' && path.match(/^\/admin\/enrollments\/\d+\/verify$/)) {
    const id = parseInt(path.split('/')[3]);
    const e = await db.prepare('SELECT * FROM enrollments WHERE id = ?').bind(id).first();
    if (!e) return err('Not found', 404);
    const expiry = new Date(); expiry.setFullYear(expiry.getFullYear() + 1);
    await db.prepare("UPDATE enrollments SET status = 'approved', expires_at = ? WHERE id = ?").bind(expiry.toISOString(), id).run();
    return json({ message: 'Verified' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/enrollments\/\d+\/spam$/)) {
    const id = parseInt(path.split('/')[3]);
    const e = await db.prepare('SELECT * FROM enrollments WHERE id = ?').bind(id).first();
    if (!e) return err('Not found', 404);
    await db.prepare("UPDATE enrollments SET status = 'spam' WHERE id = ?").bind(id).run();
    await db.prepare('UPDATE users SET spam_count = spam_count + 1 WHERE id = ?').bind(e.user_id).run();
    const u = await db.prepare('SELECT spam_count FROM users WHERE id = ?').bind(e.user_id).first();
    if (u && u.spam_count >= 5) { await db.prepare("UPDATE users SET is_blocked = 1 WHERE id = ?").bind(e.user_id).run(); }
    return json({ message: 'Marked spam' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/enrollments\/\d+$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM enrollments WHERE id = ?').bind(id).run();
    return json({ message: 'Deleted' });
  }

  if (method === 'GET' && path === '/admin/meta') {
    const rows = await db.prepare("SELECT * FROM meta WHERE key NOT LIKE 'notif_%' AND key != 'support_tickets'").all();
    const result = {}; (rows.results || []).forEach(r => { result[r.key] = r.value; });
    return json(result);
  }

  if (method === 'PUT' && path === '/admin/meta') {
    for (const [key, value] of Object.entries(body)) {
      await db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').bind(key, String(value)).run();
    }
    return json({ message: 'Saved' });
  }

  return err('Not found', 404);
}
