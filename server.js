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

// ============ SIMPLE JSON FILE "DATABASE" ============
const DB_PATH = './db.json';
function loadDB(){
  try{ return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
  catch(_e){
    return {
      orders: [],
      users: [],
      settings: { upiId: 'autocaptio@upi', prices: { single: 10, weekly: 39, monthly: 114, yearly: 900 } }
    };
  }
}
function saveDB(db){ fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }

function hashPassword(password, salt){
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

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

// ============ SETTINGS (UPI ID, QR, prices) — shared source of truth ============
app.get('/settings', (req, res) => {
  const db = loadDB();
  res.json(db.settings);
});
app.post('/settings', (req, res) => {
  // ⚠️ Demo-level: no admin auth check here yet. Anyone who finds this URL
  // could change settings. Fine to launch/test with; add a real admin
  // password check here before wide public use.
  const db = loadDB();
  db.settings = { ...db.settings, ...req.body };
  saveDB(db);
  res.json(db.settings);
});

// ============ ORDERS (UTR submissions + approvals) ============
app.get('/orders', (req, res) => {
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
app.post('/orders/:id/approve', (req, res) => {
  const db = loadDB();
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  order.status = 'approved';
  saveDB(db);
  res.json(order);
});
app.post('/orders/:id/reject', (req, res) => {
  const db = loadDB();
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  order.status = 'rejected';
  saveDB(db);
  res.json(order);
});

// ============ SIMPLE EMAIL/PASSWORD SIGNUP (no Google OAuth yet) ============
// Real "Sign in with Google" needs a Google Cloud OAuth client set up
// separately — this is a genuine, working email+password account system in
// the meantime, with passwords properly hashed (never stored in plain text).
app.post('/signup', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const db = loadDB();
  if (db.users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'An account with this email already exists' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  db.users.push({ email, salt, passwordHash: hashPassword(password, salt), plan: 'Free', createdAt: new Date().toISOString() });
  saveDB(db);
  res.json({ email, plan: 'Free' });
});
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.email === email);
  if (!user || hashPassword(password, user.salt) !== user.passwordHash) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  res.json({ email: user.email, plan: user.plan });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AutoCaptio backend listening on port ${PORT}`));
