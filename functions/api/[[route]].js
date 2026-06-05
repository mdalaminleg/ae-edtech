// ═══════════════════════════════════════
// Excellence Gateway Academy — API
// Cloudflare Pages Functions — Single File
// ═══════════════════════════════════════

const JWT_SECRET = 'ega-prod-jwt-2024-secure';
const TOKEN_EXPIRY = 24 * 60 * 60 * 1000;
const IMGBB_API_KEY = '32006c4775fab8a5ff2fae9d23b9f863';

// ─── Crypto ───
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

// ─── Helpers ───
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function getUser(request) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return await verifyToken(auth.slice(7));
}

async function getBody(request) {
  try { return await request.json(); } catch { return {}; }
}

function deviceFingerprint(request) {
  const ua = request.headers.get('User-Agent') || '';
  const platform = request.headers.get('Sec-Ch-Ua-Platform') || '';
  return sha256(ua + platform);
}

// ─── DB Setup ───
async function ensureTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    phone TEXT DEFAULT '',
    institution TEXT DEFAULT '',
    role TEXT DEFAULT 'student',
    is_approved INTEGER DEFAULT 0,
    is_blocked INTEGER DEFAULT 0,
    device_fingerprint TEXT,
    token_version INTEGER DEFAULT 1,
    spam_count INTEGER DEFAULT 0,
    spam_until TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    subject_area TEXT,
    difficulty TEXT DEFAULT 'All Levels',
    thumbnail_url TEXT,
    thumbnail_icon TEXT DEFAULT '📚',
    badge TEXT,
    price REAL DEFAULT 0,
    tree TEXT DEFAULT '[]',
    resources TEXT DEFAULT '[]',
    is_featured INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    payment_method TEXT,
    trx_id TEXT,
    sender_phone TEXT,
    status TEXT DEFAULT 'pending',
    expires_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (course_id) REFERENCES courses(id)
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
  )`).run();

  // Indexes
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_users_device ON users(device_fingerprint)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_courses_active ON courses(is_active)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_enrollments_user ON enrollments(user_id)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_enrollments_status ON enrollments(status)').run();

  // Seed admin
  const adminHash = await sha256('admin123');
  await db.prepare(`INSERT OR IGNORE INTO users (name, email, password, role, is_approved)
    VALUES ('Admin', 'admin@ega.com', ?, 'admin', 1)`).bind(adminHash).run();

  // Seed default meta
  await db.prepare(`INSERT OR IGNORE INTO meta (key, value) VALUES ('bkash_number', '')`).run();
  await db.prepare(`INSERT OR IGNORE INTO meta (key, value) VALUES ('nagad_number', '')`).run();
  await db.prepare(`INSERT OR IGNORE INTO meta (key, value) VALUES ('show_numbers', 'true')`).run();
  await db.prepare(`INSERT OR IGNORE INTO meta (key, value) VALUES ('site_name', 'Excellence Gateway Academy')`).run();

  // Seed sample courses
  const sampleCourses = [
    {
      title: 'Physics Masterclass — JEE Foundation',
      description: 'Master mechanics, waves, and thermodynamics with structured video lectures. From basics to advanced problem-solving.',
      subject_area: 'Physics',
      difficulty: 'Intermediate',
      thumbnail_icon: '⚛️',
      badge: 'Bestseller',
      price: 500,
      is_featured: 1,
      tree: JSON.stringify([
        {
          id: 'subj1', name: 'Mechanics', papers: [
            { id: 'pap1', name: 'Kinematics', chapters: [
              { id: 'ch1', title: 'Motion in 1D', lectures: [
                { id: 'lec1', title: 'Introduction to Motion', yt_video_id: 'dQw4w9WgXcQ', pdfs: [] },
                { id: 'lec2', title: 'Velocity & Acceleration', yt_video_id: 'dQw4w9WgXcQ', pdfs: [] }
              ]},
              { id: 'ch2', title: 'Motion in 2D', lectures: [
                { id: 'lec3', title: 'Projectile Motion Basics', yt_video_id: 'dQw4w9WgXcQ', pdfs: [] }
              ]}
            ]},
            { id: 'pap2', name: 'Newton Laws', chapters: [
              { id: 'ch3', title: 'First & Second Law', lectures: [
                { id: 'lec4', title: 'Understanding Force', yt_video_id: 'dQw4w9WgXcQ', pdfs: [] }
              ]}
            ]}
          ]
        }
      ]),
      resources: JSON.stringify([])
    },
    {
      title: 'Organic Chemistry Complete',
      description: 'GOC, reaction mechanisms, and named reactions — taught with clarity for NEET and JEE.',
      subject_area: 'Chemistry',
      difficulty: 'Beginner',
      thumbnail_icon: '🧪',
      badge: 'Free',
      price: 0,
      is_featured: 1,
      tree: JSON.stringify([
        {
          id: 'subj1', name: 'General Organic Chemistry', papers: [
            { id: 'pap1', name: 'Bonding & Structure', chapters: [
              { id: 'ch1', title: 'Hybridization', lectures: [
                { id: 'lec1', title: 'sp3 Hybridization', yt_video_id: 'dQw4w9WgXcQ', pdfs: [] }
              ]}
            ]}
          ]
        }
      ]),
      resources: JSON.stringify([])
    },
    {
      title: 'Calculus for JEE — Zero to Advanced',
      description: 'Limits, derivatives, integration — rigorous foundations with problem-solving sessions.',
      subject_area: 'Mathematics',
      difficulty: 'Advanced',
      thumbnail_icon: '∫',
      badge: 'New',
      price: 800,
      is_featured: 1,
      tree: JSON.stringify([
        {
          id: 'subj1', name: 'Differential Calculus', papers: [
            { id: 'pap1', name: 'Limits & Continuity', chapters: [
              { id: 'ch1', title: 'Understanding Limits', lectures: [
                { id: 'lec1', title: 'Intuitive Limits', yt_video_id: 'dQw4w9WgXcQ', pdfs: [] }
              ]}
            ]}
          ]
        }
      ]),
      resources: JSON.stringify([])
    }
  ];

  for (const c of sampleCourses) {
    await db.prepare(`INSERT OR IGNORE INTO courses (title, description, subject_area, difficulty, thumbnail_icon, badge, price, is_featured, tree, resources)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(c.title, c.description, c.subject_area, c.difficulty, c.thumbnail_icon, c.badge, c.price, c.is_featured, c.tree, c.resources).run();
  }
}

// ─── Migrations ───
const migrations = [];
async function runMigrations(db) {
  for (const sql of migrations) {
    try { await db.prepare(sql).run(); } catch {}
  }
}

// ─── Route Handlers ───

async function handleAuth(method, path, body, db, request) {
  // POST /api/auth/signup
  if (method === 'POST' && path === '/auth/signup') {
    const { name, email, password, phone, institution } = body;
    if (!name || !email || !password) return err('Name, email, and password required', 400);
    if (password.length < 6) return err('Password must be at least 6 characters', 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('Invalid email format', 400);

    const fp = await deviceFingerprint(request);

    // Max 3 accounts per device
    const deviceCount = await db.prepare('SELECT COUNT(*) as c FROM users WHERE device_fingerprint = ?').bind(fp).first();
    if (deviceCount && deviceCount.c >= 3) return err('Maximum accounts reached on this device', 403);

    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing) return err('Email already registered', 409);

    const hash = await sha256(password);
    await db.prepare(`INSERT INTO users (name, email, password, phone, institution, device_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?)`).bind(name, email, hash, phone || '', institution || '', fp).run();

    return json({ message: 'Account created. You can now log in.' }, 201);
  }

  // POST /api/auth/login
  if (method === 'POST' && path === '/auth/login') {
    const { email, password } = body;
    if (!email || !password) return err('Email and password required', 400);

    const hash = await sha256(password);
    const user = await db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').bind(email, hash).first();
    if (!user) return err('Invalid credentials', 401);
    if (user.is_blocked) return err('Account blocked. Contact support.', 403);

    // Increment token version to invalidate old sessions
    const newVersion = (user.token_version || 1) + 1;
    await db.prepare('UPDATE users SET token_version = ? WHERE id = ?').bind(newVersion, user.id).run();

    const token = await signToken({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      token_version: newVersion,
      exp: Date.now() + TOKEN_EXPIRY
    });

    return json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        institution: user.institution,
        role: user.role,
        is_approved: user.is_approved
      }
    });
  }

  // POST /api/auth/logout
  if (method === 'POST' && path === '/auth/logout') {
    const user = await getUser(request);
    if (!user) return err('Unauthorized', 401);
    await db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').bind(user.id).run();
    return json({ message: 'Logged out' });
  }

  return null;
}

async function handlePublic(method, path, body, db, request) {
  // GET /api/courses
  if (method === 'GET' && path === '/courses') {
    const url = new URL(request.url);
    const subject = url.searchParams.get('subject');
    const limit = parseInt(url.searchParams.get('limit') || '50');
    let query = 'SELECT * FROM courses WHERE is_active = 1';
    const params = [];
    if (subject) { query += ' AND subject_area = ?'; params.push(subject); }
    query += ' ORDER BY is_featured DESC, created_at DESC LIMIT ?';
    params.push(limit);
    const result = await db.prepare(query).bind(...params).all();
    return json(result.results);
  }

  // GET /api/courses/:id
  if (method === 'GET' && path.match(/^\/courses\/\d+$/)) {
    const id = parseInt(path.split('/')[2]);
    const course = await db.prepare('SELECT * FROM courses WHERE id = ? AND is_active = 1').bind(id).first();
    if (!course) return err('Course not found', 404);
    course.tree = JSON.parse(course.tree || '[]');
    course.resources = JSON.parse(course.resources || '[]');
    return json(course);
  }

  // GET /api/stats
  if (method === 'GET' && path === '/stats') {
    const courses = await db.prepare('SELECT COUNT(*) as c FROM courses WHERE is_active = 1').first();
    const users = await db.prepare('SELECT COUNT(*) as c FROM users').first();
    const enrollments = await db.prepare('SELECT COUNT(*) as c FROM enrollments WHERE status = "approved"').first();
    return json({
      courses: courses?.c || 0,
      students: users?.c || 0,
      enrollments: enrollments?.c || 0
    });
  }

  // GET /api/meta/payment-info
  if (method === 'GET' && path === '/meta/payment-info') {
    const bkash = await db.prepare("SELECT value FROM meta WHERE key = 'bkash_number'").first();
    const nagad = await db.prepare("SELECT value FROM meta WHERE key = 'nagad_number'").first();
    const show = await db.prepare("SELECT value FROM meta WHERE key = 'show_numbers'").first();
    return json({
      bkash: bkash?.value || '',
      nagad: nagad?.value || '',
      show: show?.value !== 'false'
    });
  }

  // POST /api/contact
  if (method === 'POST' && path === '/contact') {
    const { name, email, subject, message } = body;
    if (!name || !email || !message) return err('Name, email, and message required', 400);
    // Store in meta as support ticket (simple approach)
    const tickets = await db.prepare("SELECT value FROM meta WHERE key = 'support_tickets'").first();
    const list = tickets ? JSON.parse(tickets.value) : [];
    list.push({ id: Date.now(), name, email, subject, message, status: 'open', created_at: new Date().toISOString() });
    await db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES ('support_tickets', ?)").bind(JSON.stringify(list)).run();
    return json({ message: 'Message sent. We will respond soon.' }, 201);
  }

  return null;
}

async function handleStudent(method, path, body, db, user) {
  // GET /api/user/profile
  if (method === 'GET' && path === '/user/profile') {
    const u = await db.prepare('SELECT id, name, email, phone, institution, role, is_approved, created_at FROM users WHERE id = ?').bind(user.id).first();
    if (!u) return err('User not found', 404);
    return json(u);
  }

  // GET /api/user/enrollments
  if (method === 'GET' && path === '/user/enrollments') {
    const result = await db.prepare(`
      SELECT e.*, c.title as course_title, c.subject_area, c.thumbnail_url, c.thumbnail_icon, c.difficulty
      FROM enrollments e
      JOIN courses c ON e.course_id = c.id
      WHERE e.user_id = ? AND e.status = 'approved'
      ORDER BY e.created_at DESC
    `).bind(user.id).all();
    return json(result.results);
  }

  // POST /api/payment/submit
  if (method === 'POST' && path === '/payment/submit') {
    const { course_id, method: payMethod, trx_id, phone } = body;
    if (!course_id || !payMethod || !trx_id || !phone) return err('All payment fields required', 400);
    if (!['bkash', 'nagad'].includes(payMethod)) return err('Invalid payment method', 400);
    if (!/^01\d{9}$/.test(phone)) return err('Invalid phone format (01XXXXXXXXX)', 400);

    // Check spam
    const spamCount = await db.prepare(
      "SELECT COUNT(*) as c FROM enrollments WHERE user_id = ? AND status = 'spam'"
    ).bind(user.id).first();
    if (spamCount && spamCount.c >= 3) return err('Your account has been flagged for suspicious activity. Contact support.', 403);

    const existing = await db.prepare(
      "SELECT id FROM enrollments WHERE user_id = ? AND course_id = ? AND status = 'pending'"
    ).bind(user.id, course_id).first();
    if (existing) return err('You already have a pending payment for this course', 409);

    await db.prepare(
      'INSERT INTO enrollments (user_id, course_id, payment_method, trx_id, sender_phone, status) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(user.id, course_id, payMethod, trx_id, phone, 'pending').run();

    return json({ message: 'Payment submitted. Admin will verify and approve your access.' }, 201);
  }

  // GET /api/user/notifications
  if (method === 'GET' && path === '/user/notifications') {
    const notifs = await db.prepare("SELECT value FROM meta WHERE key = ?").bind('notif_' + user.id).first();
    return json(notifs ? JSON.parse(notifs.value) : []);
  }

  // PUT /api/user/notifications/read
  if (method === 'PUT' && path === '/user/notifications/read') {
    const notifs = await db.prepare("SELECT value FROM meta WHERE key = ?").bind('notif_' + user.id).first();
    if (notifs) {
      const list = JSON.parse(notifs.value);
      list.forEach(n => n.read = true);
      await db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)").bind('notif_' + user.id, JSON.stringify(list)).run();
    }
    return json({ message: 'Marked as read' });
  }

  return null;
}

async function handleAdmin(method, path, body, db, user) {
  if (user.role !== 'admin') return err('Forbidden', 403);

  // GET /api/admin/stats
  if (method === 'GET' && path === '/admin/stats') {
    const users = await db.prepare('SELECT COUNT(*) as c FROM users').first();
    const pendingUsers = await db.prepare('SELECT COUNT(*) as c FROM users WHERE is_approved = 0').first();
    const courses = await db.prepare('SELECT COUNT(*) as c FROM courses WHERE is_active = 1').first();
    const pendingPayments = await db.prepare("SELECT COUNT(*) as c FROM enrollments WHERE status = 'pending'").first();
    const activeMembers = await db.prepare("SELECT COUNT(*) as c FROM enrollments WHERE status = 'approved'").first();
    return json({
      users: users?.c || 0,
      pendingUsers: pendingUsers?.c || 0,
      courses: courses?.c || 0,
      pendingPayments: pendingPayments?.c || 0,
      activeMembers: activeMembers?.c || 0
    });
  }

  // GET /api/admin/users
  if (method === 'GET' && path === '/admin/users') {
    const result = await db.prepare('SELECT id, name, email, phone, institution, role, is_approved, is_blocked, device_fingerprint, spam_count, created_at FROM users ORDER BY created_at DESC').all();
    return json(result.results);
  }

  // PUT /api/admin/users/:id/approve
  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/approve$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET is_approved = 1, updated_at = datetime("now") WHERE id = ?').bind(id).run();
    return json({ message: 'User approved' });
  }

  // PUT /api/admin/users/:id/block
  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/block$/)) {
    const id = parseInt(path.split('/')[3]);
    const u = await db.prepare('SELECT is_blocked FROM users WHERE id = ?').bind(id).first();
    if (!u) return err('User not found', 404);
    await db.prepare('UPDATE users SET is_blocked = ?, updated_at = datetime("now") WHERE id = ?').bind(u.is_blocked ? 0 : 1, id).run();
    return json({ message: u.is_blocked ? 'User unblocked' : 'User blocked' });
  }

  // PUT /api/admin/users/:id/clear-device
  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/clear-device$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET device_fingerprint = NULL, updated_at = datetime("now") WHERE id = ?').bind(id).run();
    return json({ message: 'Device cleared' });
  }

  // DELETE /api/admin/users/:id
  if (method === 'DELETE' && path.match(/^\/admin\/users\/\d+$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM enrollments WHERE user_id = ?').bind(id).run();
    await db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
    return json({ message: 'User deleted' });
  }

  // GET /api/admin/courses
  if (method === 'GET' && path === '/admin/courses') {
    const result = await db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all();
    return json(result.results);
  }

  // POST /api/admin/courses
  if (method === 'POST' && path === '/admin/courses') {
    const { title, description, subject_area, difficulty, thumbnail_icon, badge, price, tree, resources, is_featured } = body;
    if (!title) return err('Title required', 400);
    await db.prepare(`INSERT INTO courses (title, description, subject_area, difficulty, thumbnail_icon, badge, price, tree, resources, is_featured)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(title, description || '', subject_area || '', difficulty || 'All Levels', thumbnail_icon || '📚', badge || '', price || 0, JSON.stringify(tree || []), JSON.stringify(resources || []), is_featured || 0).run();
    return json({ message: 'Course created' }, 201);
  }

  // PUT /api/admin/courses/:id
  if (method === 'PUT' && path.match(/^\/admin\/courses\/\d+$/)) {
    const id = parseInt(path.split('/')[3]);
    const { title, description, subject_area, difficulty, thumbnail_url, thumbnail_icon, badge, price, tree, resources, is_featured, is_active } = body;
    await db.prepare(`UPDATE courses SET title=?, description=?, subject_area=?, difficulty=?, thumbnail_url=?, thumbnail_icon=?, badge=?, price=?, tree=?, resources=?, is_featured=?, is_active=?, updated_at=datetime('now') WHERE id=?`)
      .bind(title, description, subject_area, difficulty, thumbnail_url, thumbnail_icon, badge, price, JSON.stringify(tree || []), JSON.stringify(resources || []), is_featured || 0, is_active !== undefined ? is_active : 1, id).run();
    return json({ message: 'Course updated' });
  }

  // DELETE /api/admin/courses/:id
  if (method === 'DELETE' && path.match(/^\/admin\/courses\/\d+$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM enrollments WHERE course_id = ?').bind(id).run();
    await db.prepare('DELETE FROM courses WHERE id = ?').bind(id).run();
    return json({ message: 'Course deleted' });
  }

  // GET /api/admin/enrollments
  if (method === 'GET' && path === '/admin/enrollments') {
    const url = new URL(request.url);
    const status = url.searchParams.get('status');
    let query = `SELECT e.*, u.name as user_name, u.email as user_email, c.title as course_title
      FROM enrollments e JOIN users u ON e.user_id = u.id JOIN courses c ON e.course_id = c.id`;
    const params = [];
    if (status) { query += ' WHERE e.status = ?'; params.push(status); }
    query += ' ORDER BY e.created_at DESC';
    const result = await db.prepare(query).bind(...params).all();
    return json(result.results);
  }

  // PUT /api/admin/enrollments/:id/verify
  if (method === 'PUT' && path.match(/^\/admin\/enrollments\/\d+\/verify$/)) {
    const id = parseInt(path.split('/')[3]);
    const enrollment = await db.prepare('SELECT * FROM enrollments WHERE id = ?').bind(id).first();
    if (!enrollment) return err('Not found', 404);
    const expiry = new Date();
    expiry.setFullYear(expiry.getFullYear() + 1);
    await db.prepare("UPDATE enrollments SET status = 'approved', expires_at = ? WHERE id = ?").bind(expiry.toISOString(), id).run();
    // Notify user
    const notifKey = 'notif_' + enrollment.user_id;
    const notifs = await db.prepare("SELECT value FROM meta WHERE key = ?").bind(notifKey).first();
    const list = notifs ? JSON.parse(notifs.value) : [];
    const course = await db.prepare('SELECT title FROM courses WHERE id = ?').bind(enrollment.course_id).first();
    list.unshift({ id: Date.now(), title: 'Payment Approved', message: `Your payment for "${course?.title}" has been verified. Start learning now!`, type: 'success', read: false, created_at: new Date().toISOString() });
    await db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)").bind(notifKey, JSON.stringify(list)).run();
    return json({ message: 'Payment verified, user granted access' });
  }

  // PUT /api/admin/enrollments/:id/spam
  if (method === 'PUT' && path.match(/^\/admin\/enrollments\/\d+\/spam$/)) {
    const id = parseInt(path.split('/')[3]);
    const enrollment = await db.prepare('SELECT * FROM enrollments WHERE id = ?').bind(id).first();
    if (!enrollment) return err('Not found', 404);
    await db.prepare("UPDATE enrollments SET status = 'spam' WHERE id = ?").bind(id).run();
    // Increment user spam count
    await db.prepare('UPDATE users SET spam_count = spam_count + 1 WHERE id = ?').bind(enrollment.user_id).run();
    // Check for auto-block
    const user = await db.prepare('SELECT spam_count FROM users WHERE id = ?').bind(enrollment.user_id).first();
    if (user && user.spam_count >= 5) {
      await db.prepare("UPDATE users SET is_blocked = 1, spam_until = datetime('now', '+24 hours') WHERE id = ?").bind(enrollment.user_id).run();
    }
    return json({ message: 'Marked as spam' });
  }

  // DELETE /api/admin/enrollments/:id
  if (method === 'DELETE' && path.match(/^\/admin\/enrollments\/\d+$/)) {
    const id = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM enrollments WHERE id = ?').bind(id).run();
    return json({ message: 'Enrollment deleted' });
  }

  // GET /api/admin/meta
  if (method === 'GET' && path === '/admin/meta') {
    const rows = await db.prepare("SELECT * FROM meta WHERE key NOT LIKE 'notif_%' AND key != 'support_tickets'").all();
    const result = {};
    rows.results.forEach(r => result[r.key] = r.value);
    return json(result);
  }

  // PUT /api/admin/meta
  if (method === 'PUT' && path === '/admin/meta') {
    const updates = body;
    for (const [key, value] of Object.entries(updates)) {
      await db.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').bind(key, String(value)).run();
    }
    return json({ message: 'Settings updated' });
  }

  // GET /api/admin/support-tickets
  if (method === 'GET' && path === '/admin/support-tickets') {
    const tickets = await db.prepare("SELECT value FROM meta WHERE key = 'support_tickets'").first();
    return json(tickets ? JSON.parse(tickets.value) : []);
  }

  // PUT /api/admin/support-tickets/:id/resolve
  if (method === 'PUT' && path.match(/^\/admin\/support-tickets\/\d+\/resolve$/)) {
    const id = parseInt(path.split('/')[3]);
    const tickets = await db.prepare("SELECT value FROM meta WHERE key = 'support_tickets'").first();
    const list = tickets ? JSON.parse(tickets.value) : [];
    const idx = list.findIndex(t => t.id === id);
    if (idx === -1) return err('Ticket not found', 404);
    list[idx].status = 'resolved';
    await db.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES ('support_tickets', ?)").bind(JSON.stringify(list)).run();
    return json({ message: 'Ticket resolved' });
  }

  return null;
}

// ─── Image Upload (IMGbb) ───
async function handleUpload(method, path, body, db, user) {
  if (method === 'POST' && path === '/upload/thumbnail') {
    if (!user || user.role !== 'admin') return err('Forbidden', 403);
    // Parse form data
    const contentType = body?.__contentType || '';
    if (!body || !body.image) return err('No image provided', 400);

    const formData = new FormData();
    formData.append('image', body.image);

    const res = await fetch(`https://api.imgbb.com/1/upload?key=${IMGBB_API_KEY}`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      return json({ url: data.data.url, display_url: data.data.display_url });
    }
    return err('Upload failed', 500);
  }
  return null;
}

// ─── Main Handler ───
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.EGA_DB;
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname.replace('/api', '');
  const body = method !== 'GET' && method !== 'OPTIONS' ? await getBody(request) : {};

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  // Initialize DB once
  if (!globalThis.__egaTablesReady) {
    await ensureTables(db);
    await runMigrations(db);
    globalThis.__egaTablesReady = true;
  }

  const user = await getUser(request);

  // Route
  let response;

  response = await handleAuth(method, path, body, db, request);
  if (response) return response;

  response = await handlePublic(method, path, body, db, request);
  if (response) return response;

  response = await handleUpload(method, path, body, db, user);
  if (response) return response;

  if (!user) return err('Unauthorized', 401);

  response = await handleStudent(method, path, body, db, user);
  if (response) return response;

  response = await handleAdmin(method, path, body, db, user);
  if (response) return response;

  return err('Not found', 404);
}
