// AutoCaptio backend — the ONLY place your API key ever lives.
// Users never see this key. Their browser sends audio here; this server
// forwards it to Groq (free Whisper transcription, no credit card needed)
// using YOUR key, kept in an environment variable (Render "Secret"), never
// written into this file or sent to the browser.
//
// This also stores orders (UTR submissions), admin settings (UPI ID / QR /
// prices), and simple accounts in a JSON file on disk, so admin approvals
// and settings changes are REAL and visible from any device — not just
// stuck in one browser's memory.
//
// ⚠️ Note: Render's free tier has no persistent disk, so this file resets
// whenever the server redeploys or restarts (not on every request — it
// survives normal usage, including free-tier sleep/wake). For a permanent
// production database, upgrade to a paid Render disk or a real database
// later. This is a solid, real, working setup to launch and test with.

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fetch = require('node-fetch');
const FormData = require('form-data');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(cors()); // allows your website (on a different domain) to call this server
app.use(express.json());

const upload = multer({ limits: { fileSize: 30 * 1024 * 1024 } }); // 30MB safety cap
const PROJECT_VIDEOS_DIR = './project-videos';
if(!fs.existsSync(PROJECT_VIDEOS_DIR)) fs.mkdirSync(PROJECT_VIDEOS_DIR);
const uploadProjectVideo = multer({
  storage: multer.diskStorage({
    destination: PROJECT_VIDEOS_DIR,
    filename: (req, file, cb) => cb(null, crypto.randomBytes(12).toString('hex') + '.webm')
  }),
  limits: { fileSize: 60 * 1024 * 1024 } // 60MB cap — keeps this workable on a free server
});

// ============ SIMPLE JSON FILE "DATABASE" ============
const DB_PATH = './db.json';
function loadDB(){
  try{
    const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    if(!db.projects) db.projects = []; // backward-compat with db.json files saved before this field existed
    if(!db.activityLog) db.activityLog = [];
    if(!db.settings.currency) db.settings.currency = 'INR';
    return db;
  }
  catch(_e){
    return {
      orders: [],
      projects: [],
      users: [],
      promoCodes: [],
      callbackRequests: [],
      activityLog: [],
      settings: { upiId: 'autocaptio@upi', currency: 'INR', prices: { single: 10, weekly: 39, monthly: 114, yearly: 900 } }
    };
  }
}
function saveDB(db){ fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }
// Keeps a rolling "recent activity" feed for the admin dashboard — not a
// full audit log, just the last 50 notable actions.
function logActivity(message){
  const db = loadDB();
  db.activityLog.unshift({ message, date: new Date().toISOString() });
  db.activityLog = db.activityLog.slice(0, 50);
  saveDB(db);
}

function hashPassword(password, salt){
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}
function isPlanActive(user){
  if(!user) return false;
  if(user.forceWatermark === 'off') return true;  // admin emergency override: force NO watermark
  if(user.forceWatermark === 'on') return false;  // admin emergency override: force watermark ON
  if(user.exportCredits > 0) return true; // unused single-video credit
  if(user.planExpiresAt && new Date(user.planExpiresAt) > new Date()) return true; // active weekly/monthly/yearly
  return false;
}
function applyApprovedPlanToUser(email, planName){
  const db = loadDB();
  let user = db.users.find(u => u.email === email);
  if(!user){
    // Payment was made under an email with no signed-up account yet — create
    // a lightweight record so the plan still gets tracked correctly.
    user = { email, salt: null, passwordHash: null, plan: 'Free', planExpiresAt: null, exportCredits: 0, createdAt: new Date().toISOString() };
    db.users.push(user);
  }
  const now = Date.now();
  const DAY = 24 * 60 * 60 * 1000;
  if(planName === 'Single Video'){
    user.exportCredits = (user.exportCredits || 0) + 1;
  } else if(planName === 'Weekly'){
    user.planExpiresAt = new Date(Math.max(now, new Date(user.planExpiresAt||0).getTime()) + 7*DAY).toISOString();
  } else if(planName === 'Monthly'){
    user.planExpiresAt = new Date(Math.max(now, new Date(user.planExpiresAt||0).getTime()) + 30*DAY).toISOString();
  } else if(planName === 'Yearly'){
    user.planExpiresAt = new Date(Math.max(now, new Date(user.planExpiresAt||0).getTime()) + 365*DAY).toISOString();
  }
  user.plan = planName;
  saveDB(db);
}

// ============ REAL ADMIN AUTH ============
// The admin username/password live ONLY here, as environment variables on
// the server (set in Render → Environment, never committed to GitHub, never
// sent to the browser). The password is checked here on the server; the
// browser only ever gets back a random, meaningless session token — never
// the password itself. Viewing the website's HTML/JS source reveals nothing,
// because the real check never runs in the browser at all.
const adminSessions = new Set(); // simple in-memory session tokens
function requireAdmin(req, res, next){
  const token = req.headers['x-admin-token'] || req.query.token; // query fallback for plain download links
  if(!token || !adminSessions.has(token)){
    return res.status(401).json({ error: 'Not authorized — please log in as admin again' });
  }
  next();
}

// ============ 🔒 SECURITY FIX: REAL USER SESSIONS ============
// BEFORE this fix, endpoints like /projects, /me, and /me/consume-credit
// simply trusted whatever "email" the browser sent — with no password/token
// check at all. That meant anyone who knew (or guessed) another user's email
// could view their saved projects, download their saved videos, or drain
// their export credits, without ever knowing their password. This is a real,
// serious vulnerability (an "IDOR" / broken-authentication bug), not
// theoretical — now fixed the same way admin auth already worked: login
// returns a random session token, and every user-specific request must prove
// it owns that token.
const userSessions = new Map(); // token -> email
function issueUserSession(email){
  const token = crypto.randomBytes(24).toString('hex');
  userSessions.set(token, email);
  return token;
}
function requireUser(req, res, next){
  const token = req.headers['x-user-token'] || req.query.token; // query fallback for plain download links
  const email = token && userSessions.get(token);
  if(!email) return res.status(401).json({ error: 'Please log in again' });
  req.verifiedEmail = email; // the ONLY email endpoints should trust from here on
  next();
}

// ============ 🔒 SECURITY FIX: RATE LIMITING ON LOGIN ENDPOINTS ============
// BEFORE this fix, /login and /admin/login had zero protection against
// someone (or a bot) simply trying thousands of passwords per second — a
// classic brute-force attack. Now each IP gets max 8 attempts per 10 minutes.
const loginAttempts = new Map(); // "ip:endpoint" -> { count, resetAt }
function rateLimitLogin(endpointName){
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const key = `${ip}:${endpointName}`;
    const now = Date.now();
    const entry = loginAttempts.get(key);
    if(entry && now < entry.resetAt){
      if(entry.count >= 8){
        return res.status(429).json({ error: 'Too many attempts — please wait 10 minutes and try again' });
      }
      entry.count++;
    } else {
      loginAttempts.set(key, { count: 1, resetAt: now + 10*60*1000 });
    }
    next();
  };
}
app.post('/admin/login', rateLimitLogin('admin-login'), (req, res) => {
  const { username, password } = req.body;
  const realUser = process.env.ADMIN_USERNAME;
  const realPass = process.env.ADMIN_PASSWORD;
  // Optional co-admin/backup account (set CO_ADMIN_USERNAME/CO_ADMIN_PASSWORD
  // in Render if you want a trusted second person to help approve orders).
  const coUser = process.env.CO_ADMIN_USERNAME;
  const coPass = process.env.CO_ADMIN_PASSWORD;
  if(!realUser || !realPass){
    return res.status(500).json({ error: 'Server is missing ADMIN_USERNAME/ADMIN_PASSWORD environment variables' });
  }
  const isMainAdmin = username === realUser && password === realPass;
  const isCoAdmin = coUser && coPass && username === coUser && password === coPass;
  if(!isMainAdmin && !isCoAdmin){
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  adminSessions.add(token);
  logActivity(isCoAdmin ? `Co-admin ${username} logged in` : 'Admin logged in');
  res.json({ token, isCoAdmin });
});
app.post('/admin/logout', requireAdmin, (req, res) => {
  adminSessions.delete(req.headers['x-admin-token']);
  res.json({ ok: true });
});

app.get('/', (req, res) => {
  res.send('AutoCaptio backend is running ✓');
});

// ============ TRANSCRIPTION ============
app.post('/transcribe', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file received' });
    }
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Server is missing GROQ_API_KEY — add it in your hosting dashboard\'s environment variables' });
    }

    const form = new FormData();
    form.append('file', req.file.buffer, { filename: req.file.originalname || 'audio.webm' });
    form.append('model', 'whisper-large-v3-turbo'); // Groq's fast, free-tier Whisper model
    form.append('response_format', 'verbose_json');
    form.append('timestamp_granularities[]', 'word');
    if(req.body.language) form.append('language', req.body.language); // e.g. 'hi', 'en' — improves accuracy when known

    const whisperRes = await fetch('https://api.groq.com/openai/v1/audio/transcriptions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, ...form.getHeaders() },
      body: form
    });

    const data = await whisperRes.json();
    if (!whisperRes.ok) {
      return res.status(whisperRes.status).json({ error: data.error?.message || 'Transcription API error' });
    }
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Transcription failed on the server' });
  }
});

// ============ SETTINGS (UPI ID, QR, prices) — admin-only to change ============
app.get('/settings', (req, res) => {
  const db = loadDB();
  res.json(db.settings);
});
app.post('/settings', requireAdmin, (req, res) => {
  const db = loadDB();
  db.settings = { ...db.settings, ...req.body };
  saveDB(db);
  res.json(db.settings);
});

// ============ ORDERS (UTR submissions + approvals) ============
app.get('/orders', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.orders);
});
app.post('/orders', (req, res) => {
  const db = loadDB();
  const order = {
    id: 'AC-' + Math.floor(Math.random() * 9000 + 1000),
    user: req.body.user || 'guest',
    email: req.body.email || '',
    plan: req.body.plan,
    amount: req.body.amount,
    utr: req.body.utr,
    date: new Date().toISOString(),
    status: 'pending'
  };
  db.orders.unshift(order);
  saveDB(db);
  res.json(order);
});
app.post('/orders/:id/approve', requireAdmin, (req, res) => {
  const db = loadDB();
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  order.status = 'approved';
  saveDB(db);
  if(order.email) applyApprovedPlanToUser(order.email, order.plan); // unlocks real exports for that account
  logActivity(`Approved ${order.plan} (₹${order.amount}) for ${order.email || order.user}`);
  // NOTE: real email confirmation to the user needs an email-sending service
  // (Resend/SendGrid) wired up — not done yet, see project notes. The
  // in-app status (checkMembership()/GET /me) already reflects the unlock
  // immediately, so the user sees it next time they check, just no email.
  res.json(order);
});
app.post('/orders/:id/reject', requireAdmin, (req, res) => {
  const db = loadDB();
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  order.status = 'rejected';
  saveDB(db);
  logActivity(`Rejected order for ${order.email || order.user}`);
  res.json(order);
});

// ============ PROMO CODES ============
app.get('/promo/list', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.promoCodes);
});
app.post('/promo/create', requireAdmin, (req, res) => {
  const db = loadDB();
  const code = {
    code: (req.body.code || crypto.randomBytes(4).toString('hex')).toUpperCase(),
    description: req.body.description || '',
    freeVideosGranted: Number(req.body.freeVideosGranted) || 0,
    maxUses: Number(req.body.maxUses) || 1,
    uses: 0,
    createdAt: new Date().toISOString()
  };
  db.promoCodes.push(code);
  saveDB(db);
  res.json(code);
});
app.post('/promo/redeem', (req, res) => {
  const db = loadDB();
  const code = db.promoCodes.find(c => c.code === (req.body.code || '').toUpperCase());
  if(!code) return res.status(404).json({ error: 'Invalid promo code' });
  if(code.uses >= code.maxUses) return res.status(400).json({ error: 'This promo code has already been fully used' });
  code.uses += 1;
  saveDB(db);
  res.json({ success: true, freeVideosGranted: code.freeVideosGranted, description: code.description });
});

// ============ MY PROJECTS ============
// Saves a project's captions/style always. If a rendered video is attached
// (under the 60MB cap) it's stored on disk and can be re-downloaded later;
// larger exports still save the captions/style so the work isn't lost, but
// the video itself must be re-exported (see note in the API response).
// ⚠️ Render's free tier disk is NOT persistent across redeploys/restarts —
// saved videos can disappear then. Fine for launching/testing; upgrade to a
// paid disk or real object storage (e.g. S3) before relying on this long-term.
app.post('/projects', requireUser, uploadProjectVideo.single('video'), (req, res) => {
  try{
    const email = req.verifiedEmail; // 🔒 was previously trusted straight from req.body — anyone could save under any email
    const { title, captionsJson, presetKey } = req.body;
    const db = loadDB();
    const project = {
      id: 'PRJ-' + crypto.randomBytes(6).toString('hex'),
      email,
      title: title || 'Untitled project',
      captions: JSON.parse(captionsJson || '[]'),
      presetKey: presetKey || null,
      videoFile: req.file ? req.file.filename : null,
      createdAt: new Date().toISOString()
    };
    db.projects.unshift(project);
    saveDB(db);
    res.json(project);
  }catch(err){
    console.error(err);
    res.status(500).json({ error: err.message || 'Could not save project' });
  }
});
app.get('/projects', requireUser, (req, res) => {
  const db = loadDB();
  const mine = db.projects.filter(p => p.email === req.verifiedEmail); // 🔒 was req.query.email — anyone could list anyone's projects
  res.json(mine.map(p => ({ ...p, hasVideo: !!p.videoFile })));
});
app.get('/projects/:id/video', requireUser, (req, res) => {
  const db = loadDB();
  const project = db.projects.find(p => p.id === req.params.id);
  if(!project || !project.videoFile) return res.status(404).json({ error: 'No saved video for this project' });
  // 🔒 CRITICAL FIX: this endpoint previously had NO ownership check at all —
  // anyone who guessed/saw a project ID could download ANY user's saved
  // video. Now it verifies the requester's session actually owns it.
  if(project.email !== req.verifiedEmail) return res.status(403).json({ error: 'Not your project' });
  res.sendFile(project.videoFile, { root: PROJECT_VIDEOS_DIR });
});
app.delete('/projects/:id', requireUser, (req, res) => {
  const db = loadDB();
  const project = db.projects.find(p => p.id === req.params.id);
  if(!project) return res.status(404).json({ error: 'Not found' });
  if(project.email !== req.verifiedEmail) return res.status(403).json({ error: 'Not your project' }); // 🔒 was req.body.email
  if(project.videoFile){
    try{ fs.unlinkSync(`${PROJECT_VIDEOS_DIR}/${project.videoFile}`); }catch(_e){}
  }
  db.projects = db.projects.filter(p => p.id !== req.params.id);
  saveDB(db);
  res.json({ success: true });
});

// ============ CALLBACK REQUESTS (phone support) ============
app.post('/callback-request', (req, res) => {
  const { phone, name } = req.body;
  if(!phone) return res.status(400).json({ error: 'Phone number required' });
  const db = loadDB();
  db.callbackRequests.unshift({ phone, name: name || '', date: new Date().toISOString(), called: false });
  saveDB(db);
  res.json({ success: true });
});
app.get('/callback-requests', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.callbackRequests);
});
app.post('/callback-requests/:index/mark-called', requireAdmin, (req, res) => {
  const db = loadDB();
  const r = db.callbackRequests[req.params.index];
  if(!r) return res.status(404).json({ error: 'Not found' });
  r.called = true;
  saveDB(db);
  res.json(r);
});

// ============ SIMPLE EMAIL/PASSWORD SIGNUP (no Google OAuth yet) ============
// Real "Sign in with Google" needs a Google Cloud OAuth client set up
// separately — this is a genuine, working email+password account system in
// the meantime, with passwords properly hashed (never stored in plain text).
// ============ ADMIN: view all signed-up users (with optional search) ============
app.get('/admin/users', requireAdmin, (req, res) => {
  const db = loadDB();
  let users = db.users;
  if(req.query.search){
    const q = req.query.search.toLowerCase();
    users = users.filter(u => u.email.toLowerCase().includes(q));
  }
  // Never send password hashes/salts to the browser, even to the admin.
  res.json(users.map(u => ({
    email: u.email, plan: u.plan, planExpiresAt: u.planExpiresAt || null,
    exportCredits: u.exportCredits || 0, viaGoogle: !!u.viaGoogle, createdAt: u.createdAt,
    forceWatermark: u.forceWatermark || null
  })));
});

// ============ ADMIN: manual override (fix human errors without waiting on code) ============
app.post('/admin/users/:email/adjust-credits', requireAdmin, (req, res) => {
  const delta = Number(req.body.delta); // e.g. +1, +5, -1
  const db = loadDB();
  const user = db.users.find(u => u.email === req.params.email);
  if(!user) return res.status(404).json({ error: 'User not found' });
  user.exportCredits = Math.max(0, (user.exportCredits || 0) + delta);
  saveDB(db);
  logActivity(`Admin adjusted credits for ${user.email} by ${delta > 0 ? '+' : ''}${delta}`);
  res.json({ exportCredits: user.exportCredits });
});
app.post('/admin/users/:email/adjust-expiry', requireAdmin, (req, res) => {
  const days = Number(req.body.days); // e.g. +7, +30, or 0 to revoke immediately
  const db = loadDB();
  const user = db.users.find(u => u.email === req.params.email);
  if(!user) return res.status(404).json({ error: 'User not found' });
  if(days === 0){
    user.planExpiresAt = null; // revoke immediately
  } else {
    const base = Math.max(Date.now(), new Date(user.planExpiresAt || 0).getTime());
    user.planExpiresAt = new Date(base + days*24*60*60*1000).toISOString();
  }
  saveDB(db);
  logActivity(`Admin ${days === 0 ? 'revoked' : 'extended (' + days + 'd)'} plan for ${user.email}`);
  res.json({ planExpiresAt: user.planExpiresAt });
});
app.post('/admin/users/:email/force-watermark', requireAdmin, (req, res) => {
  const { mode } = req.body; // 'on' | 'off' | 'auto'
  const db = loadDB();
  const user = db.users.find(u => u.email === req.params.email);
  if(!user) return res.status(404).json({ error: 'User not found' });
  user.forceWatermark = mode === 'auto' ? null : mode; // null = use normal plan-based logic
  saveDB(db);
  logActivity(`Admin set watermark override to "${mode}" for ${user.email}`);
  res.json({ forceWatermark: user.forceWatermark });
});

// ============ ADMIN: dashboard stats + recent activity ============
app.get('/admin/dashboard', requireAdmin, (req, res) => {
  const db = loadDB();
  const now = new Date();
  const todayStr = now.toDateString();
  const thisMonth = now.getMonth(), thisYear = now.getFullYear();

  const approvedOrders = db.orders.filter(o => o.status === 'approved');
  const monthlyRevenue = approvedOrders
    .filter(o => { const d = new Date(o.date); return d.getMonth()===thisMonth && d.getFullYear()===thisYear; })
    .reduce((sum,o) => sum + (Number(o.amount)||0), 0);

  // Simple day-by-day revenue for the current month, for the dashboard graph.
  const dailyRevenue = {};
  approvedOrders.forEach(o => {
    const d = new Date(o.date);
    if(d.getMonth()===thisMonth && d.getFullYear()===thisYear){
      const key = d.getDate();
      dailyRevenue[key] = (dailyRevenue[key]||0) + (Number(o.amount)||0);
    }
  });

  res.json({
    totalUsers: db.users.length,
    totalProjects: db.projects.length,
    todaysProjects: db.projects.filter(p => new Date(p.createdAt||p.date||0).toDateString() === todayStr).length,
    monthlyRevenue,
    activePlans: db.users.filter(u => isPlanActive(u)).length,
    pendingOrders: db.orders.filter(o => o.status === 'pending').length,
    dailyRevenue, // { "1": 114, "5": 39, ... } day-of-month -> rupees
    recentActivity: db.activityLog.slice(0, 5)
  });
});

// ============ ADMIN: automatic backup ============
// Simple, no-cron-library approach: a setInterval inside this same process
// backs up db.json every 6 hours while the server is awake. On Render's free
// tier the server sleeps after inactivity, so this isn't a guaranteed clock —
// but it runs reliably whenever there's real traffic keeping it awake, and
// the "Download Latest Backup" button always works on demand regardless.
const BACKUP_DIR = './backups';
if(!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);
function runBackup(){
  try{
    const filename = `backup-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
    fs.copyFileSync(DB_PATH, `${BACKUP_DIR}/${filename}`);
    // Keep only the 10 most recent backups so disk doesn't fill up.
    const files = fs.readdirSync(BACKUP_DIR).sort();
    while(files.length > 10){ fs.unlinkSync(`${BACKUP_DIR}/${files.shift()}`); }
    console.log('Backup created:', filename);
  }catch(err){ console.error('Backup failed:', err.message); }
}
setInterval(runBackup, 6*60*60*1000); // every 6 hours
runBackup(); // also back up once immediately on server start

app.get('/admin/backup/latest-info', requireAdmin, (req, res) => {
  try{
    const files = fs.readdirSync(BACKUP_DIR).sort();
    if(files.length === 0) return res.json({ lastBackup: null });
    const latest = files[files.length-1];
    const stat = fs.statSync(`${BACKUP_DIR}/${latest}`);
    res.json({ lastBackup: stat.mtime });
  }catch(err){ res.json({ lastBackup: null }); }
});
app.post('/admin/backup/run-now', requireAdmin, (req, res) => {
  runBackup();
  res.json({ success: true });
});
app.get('/admin/backup/download', requireAdmin, (req, res) => {
  try{
    const files = fs.readdirSync(BACKUP_DIR).sort();
    if(files.length === 0) return res.status(404).json({ error: 'No backup exists yet' });
    res.download(`${BACKUP_DIR}/${files[files.length-1]}`);
  }catch(err){ res.status(500).json({ error: err.message }); }
});

app.post('/admin/users/:email/reset-password', requireAdmin, (req, res) => {
  const { newPassword } = req.body;
  if(!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const db = loadDB();
  const user = db.users.find(u => u.email === req.params.email);
  if(!user) return res.status(404).json({ error: 'User not found' });
  const salt = crypto.randomBytes(16).toString('hex');
  user.salt = salt;
  user.passwordHash = hashPassword(newPassword, salt);
  saveDB(db);
  res.json({ success: true });
});

app.post('/signup', rateLimitLogin('signup'), (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const db = loadDB();
  const existing = db.users.find(u => u.email === email);
  if (existing && existing.passwordHash) {
    return res.status(400).json({ error: 'An account with this email already exists' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  if(existing){
    // A plan was already granted to this email via a payment before they signed up
    existing.salt = salt;
    existing.passwordHash = hashPassword(password, salt);
  } else {
    db.users.push({ email, salt, passwordHash: hashPassword(password, salt), plan: 'Free', planExpiresAt: null, exportCredits: 0, createdAt: new Date().toISOString() });
  }
  saveDB(db);
  const user = db.users.find(u => u.email === email);
  const token = issueUserSession(user.email); // 🔒 real session, not just a trusted email string
  res.json({ email: user.email, plan: user.plan, token });
});
app.post('/login', rateLimitLogin('login'), (req, res) => {
  const { email, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.email === email);
  if (!user || !user.passwordHash || hashPassword(password, user.salt) !== user.passwordHash) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const token = issueUserSession(user.email);
  res.json({ email: user.email, plan: user.plan, token });
});

// ============ MEMBERSHIP STATUS (used by the export feature to decide free vs full) ============
// 🔒 SECURITY FIX: now requires a real session token — previously anyone
// could check (or manipulate) ANY email's plan/credits just by knowing it.
app.get('/me', requireUser, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.email === req.verifiedEmail);
  if(!user) return res.json({ plan: 'Free', planExpiresAt: null, exportCredits: 0, isActive: false });
  res.json({ plan: user.plan, planExpiresAt: user.planExpiresAt || null, exportCredits: user.exportCredits || 0, isActive: isPlanActive(user) });
});
app.post('/me/consume-credit', requireUser, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.email === req.verifiedEmail);
  if(!user || !user.exportCredits) return res.status(400).json({ error: 'No export credit available' });
  user.exportCredits -= 1;
  saveDB(db);
  res.json({ exportCredits: user.exportCredits });
});

// ============ 🔧 BUG FIX: these 3 endpoints were called by the frontend
// (Export My Data, Delete Account, Team features) but never existed on the
// backend at all — every click on those buttons was silently failing. ============

// GDPR-style: download everything the app knows about you.
app.get('/export', requireUser, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.email === req.verifiedEmail);
  if(!user) return res.status(404).json({ error: 'Account not found' });
  const { passwordHash, salt, ...safeUser } = user; // never include the password hash, even in your own export
  res.json({
    account: safeUser,
    orders: db.orders.filter(o => o.email === req.verifiedEmail),
    projects: db.projects.filter(p => p.email === req.verifiedEmail).map(p => ({ id:p.id, title:p.title, createdAt:p.createdAt, captionCount:(p.captions||[]).length }))
  });
});

// Permanently deletes the account, their projects, and their saved videos.
app.delete('/delete', requireUser, (req, res) => {
  const db = loadDB();
  const email = req.verifiedEmail;
  db.users = db.users.filter(u => u.email !== email);
  const theirProjects = db.projects.filter(p => p.email === email);
  theirProjects.forEach(p => { if(p.videoFile){ try{ fs.unlinkSync(`${PROJECT_VIDEOS_DIR}/${p.videoFile}`); }catch(_e){} } });
  db.projects = db.projects.filter(p => p.email !== email);
  db.team = (db.team||[]).filter(t => t.owner !== email && t.member !== email);
  saveDB(db);
  for(const [token, tokenEmail] of userSessions){ if(tokenEmail === email) userSessions.delete(token); }
  logActivity(`Account deleted: ${email}`);
  res.json({ success: true });
});

// ============ TEAM (simple: one owner invites members, no real roles/permissions yet) ============
app.post('/team/invite', requireUser, (req, res) => {
  const { invitee, role } = req.body;
  if(!invitee) return res.status(400).json({ error: 'Email required' });
  const db = loadDB();
  if(!db.team) db.team = [];
  if(db.team.find(t => t.owner === req.verifiedEmail && t.member === invitee)){
    return res.status(400).json({ error: 'Already invited' });
  }
  db.team.push({ owner: req.verifiedEmail, member: invitee, role: role || 'editor', invitedAt: new Date().toISOString() });
  saveDB(db);
  res.json({ success: true });
});
app.get('/team', requireUser, (req, res) => {
  const db = loadDB();
  const members = (db.team||[]).filter(t => t.owner === req.verifiedEmail);
  res.json(members.map(m => ({ email: m.member, role: m.role })));
});
app.delete('/team/remove', requireUser, (req, res) => {
  const { member } = req.body;
  const db = loadDB();
  db.team = (db.team||[]).filter(t => !(t.owner === req.verifiedEmail && t.member === member));
  saveDB(db);
  res.json({ success: true });
});

// ============ TRANSLATION (for the Output Language dropdown, incl. Hinglish) ============
// Whisper only transcribes/translates-to-English natively. For arbitrary
// output languages (and things like "Hinglish" which isn't a real ISO
// language), we ask a free Groq LLM to translate the caption text — same
// API key, no extra signup needed.
app.post('/translate', async (req, res) => {
  try{
    const { words, targetLanguage } = req.body; // words: [{word,start,end}, ...]
    if(!words || !Array.isArray(words) || words.length === 0){
      return res.status(400).json({ error: 'No words provided' });
    }
    const apiKey = process.env.GROQ_API_KEY;
    if(!apiKey) return res.status(500).json({ error: 'Server is missing GROQ_API_KEY' });

    const originalText = words.map(w => w.word).join(' ');
    const languageInstruction = targetLanguage === 'hinglish'
      ? 'Hinglish (write Hindi words using plain English/Latin letters, the way Indians casually text — NOT Devanagari script)'
      : targetLanguage;

    const prompt = `Translate the following transcript into ${languageInstruction}. Keep the SAME NUMBER of words as natural as possible so timing stays aligned — do not add explanations, only output the translated transcript text, nothing else.\n\nTranscript: "${originalText}"`;

    const llmRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.3
      })
    });
    const data = await llmRes.json();
    if(!llmRes.ok) return res.status(llmRes.status).json({ error: data.error?.message || 'Translation failed' });

    const translatedText = data.choices?.[0]?.message?.content?.trim() || '';
    // Map translated words back onto the ORIGINAL timings as evenly as
    // possible — not perfectly synced to the new word boundaries, but a
    // reasonable, honest best-effort (true re-alignment would need a second
    // forced-alignment pass, a bigger future upgrade).
    const translatedWords = translatedText.split(/\s+/).filter(Boolean);
    const ratio = translatedWords.length / words.length;
    const remapped = translatedWords.map((w, i) => {
      const origIdx = Math.min(words.length - 1, Math.floor(i / (ratio || 1)));
      return { word: w, start: words[origIdx].start, end: words[origIdx].end };
    });
    res.json({ words: remapped });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: err.message || 'Translation failed' });
  }
});

// ============ GOOGLE SIGN-IN ============
// Verifies the ID token Google's own Sign-In button hands us, by asking
// Google directly whether it's genuine — no extra library/dependency needed.
// Requires GOOGLE_CLIENT_ID to be set as an environment variable (see README)
// to check the token was actually issued for YOUR site.
app.post('/auth/google', async (req, res) => {
  try{
    const { credential } = req.body;
    if(!credential) return res.status(400).json({ error: 'No credential provided' });
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if(!clientId) return res.status(500).json({ error: 'Server is missing GOOGLE_CLIENT_ID — Google Sign-In is not set up yet' });

    const verifyRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
    const payload = await verifyRes.json();
    if(!verifyRes.ok || payload.aud !== clientId){
      return res.status(401).json({ error: 'Invalid Google credential' });
    }
    const email = payload.email;
    const db = loadDB();
    let user = db.users.find(u => u.email === email);
    if(!user){
      user = { email, salt: null, passwordHash: null, plan: 'Free', planExpiresAt: null, exportCredits: 0, viaGoogle: true, createdAt: new Date().toISOString() };
      db.users.push(user);
      saveDB(db);
    }
    res.json({ email: user.email, plan: user.plan, token: issueUserSession(user.email) });
  }catch(err){
    console.error(err);
    res.status(500).json({ error: 'Google sign-in failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AutoCaptio backend listening on port ${PORT}`));
