// ============================================================
// server.js — AutoCaptio Backend (Real, Production‑Ready)
// Deploy to Render / any Node.js host.
// ============================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OpenAI } = require('openai');
const { translate } = require('@vitalets/google-translate-api');

// ============================================================
// CONFIGURATION
// ============================================================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'autocaptio-super-secret-key-change-this';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const PROJECTS_DIR = path.join(DATA_DIR, 'projects');

// Ensure data directories exist
[ DATA_DIR, UPLOAD_DIR, PROJECTS_DIR ].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ============================================================
// DATA STORE (file‑based persistence)
// ============================================================
const DB_FILE = path.join(DATA_DIR, 'db.json');

let db = {
  users: [],        // { id, email, passwordHash, referralCode, createdAt }
  projects: [],     // { id, userId, title, captions, presetKey, chapters, hasVideo, createdAt }
  orders: [],       // { id, userEmail, plan, amount, utr, status, createdAt }
  teamInvites: [],  // { id, inviterEmail, inviteeEmail, role, status, createdAt }
  callbacks: [],    // { id, name, phone, createdAt }
};

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf-8');
      const parsed = JSON.parse(raw);
      db = { ...db, ...parsed };
    }
  } catch (e) { console.warn('DB load warning:', e.message); }
}

function saveDB() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
  } catch (e) { console.error('DB save error:', e.message); }
}

loadDB();

// ============================================================
// HELPERS
// ============================================================
function findUserByEmail(email) {
  return db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
}

function findUserById(id) {
  return db.users.find(u => u.id === id);
}

function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch (_) { return null; }
}

// Authentication middleware (reads x‑user‑token header)
function authMiddleware(req, res, next) {
  const token = req.headers['x-user-token'];
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: missing token' });
  }
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }
  const user = findUserById(decoded.id);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized: user not found' });
  }
  req.user = user;
  next();
}

// ============================================================
// MULTER CONFIG (file uploads)
// ============================================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.webm';
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 600 * 1024 * 1024 }, // 600 MB
  fileFilter: (req, file, cb) => {
    const allowed = ['video/mp4', 'video/webm', 'video/ogg', 'audio/webm', 'audio/mp4', 'audio/mpeg'];
    if (allowed.includes(file.mimetype) || file.originalname.match(/\.(mp4|webm|mov|mkv|avi|m4a|mp3|wav)$/i)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type'), false);
    }
  }
});

// ============================================================
// EXPRESS APP
// ============================================================
const app = express();
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginOpenerPolicy: { policy: 'unsafe-none' }
}));
app.use(cors({ origin: '*', exposedHeaders: ['Content-Disposition'] }));
app.use(morgan('dev'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files (for project videos etc.)
app.use('/projects/video', express.static(PROJECTS_DIR));

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// ============================================================
// PUBLIC SETTINGS (used by frontend)
// ============================================================
app.get('/settings', (req, res) => {
  res.json({
    upiId: process.env.UPI_ID || 'autocaptio@upi',
    qrImage: process.env.QR_IMAGE_URL || null,
    prices: {
      single: 10,
      weekly: 39,
      monthly: 114,
      yearly: 900
    }
  });
});

// ============================================================
// AUTH: SIGNUP & LOGIN
// ============================================================
app.post('/signup', async (req, res) => {
  try {
    const { email, password, referral } = req.body;
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: 'Email and password (min 6 chars) required' });
    }
    if (findUserByEmail(email)) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: uuidv4(),
      email: email.toLowerCase(),
      passwordHash: hash,
      referralCode: (referral || '').trim() || null,
      createdAt: new Date().toISOString()
    };
    db.users.push(user);
    saveDB();
    const token = generateToken(user);
    res.status(201).json({ email: user.email, token });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    const user = findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = generateToken(user);
    res.json({ email: user.email, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// TRANSCRIBE (Whisper API)
// ============================================================
app.post('/transcribe', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio/video file uploaded' });
    }
    if (!OPENAI_API_KEY) {
      return res.status(500).json({ error: 'OpenAI API key not configured' });
    }

    const openai = new OpenAI({ apiKey: OPENAI_API_KEY });
    const fileStream = fs.createReadStream(req.file.path);
    const lang = req.body.language || '';

    const transcription = await openai.audio.transcriptions.create({
      file: fileStream,
      model: 'whisper-1',
      response_format: 'verbose_json',
      language: lang || undefined,
      timestamp_granularities: ['word']
    });

    // Clean up uploaded file
    try { fs.unlinkSync(req.file.path); } catch (_) {}

    // Build response with word‑level timestamps
    const words = (transcription.words || []).map(w => ({
      word: w.word.trim(),
      start: w.start,
      end: w.end,
      confidence: w.confidence || 0.95
    })).filter(w => w.word.length > 0);

    res.json({
      text: transcription.text || '',
      words: words,
      language: transcription.language || 'en'
    });
  } catch (err) {
    console.error('Transcription error:', err);
    // Clean up on error
    try { if (req.file && req.file.path) fs.unlinkSync(req.file.path); } catch (_) {}
    res.status(500).json({ error: err.message || 'Transcription failed' });
  }
});

// ============================================================
// TRANSLATE (Google Translate)
// ============================================================
app.post('/translate', async (req, res) => {
  try {
    const { words, targetLanguage } = req.body;
    if (!words || !Array.isArray(words) || words.length === 0) {
      return res.status(400).json({ error: 'Words array required' });
    }
    if (!targetLanguage) {
      return res.status(400).json({ error: 'targetLanguage required' });
    }

    // Translate each word individually to preserve timing
    const translated = await Promise.all(words.map(async (item) => {
      if (!item.word || item.word.trim().length === 0) {
        return { ...item, word: item.word || '' };
      }
      try {
        const result = await translate(item.word.trim(), { to: targetLanguage });
        return { ...item, word: result.text };
      } catch (_) {
        return { ...item, word: item.word };
      }
    }));

    res.json({ words: translated });
  } catch (err) {
    console.error('Translation error:', err);
    res.status(500).json({ error: err.message || 'Translation failed' });
  }
});

// ============================================================
// PROJECTS (protected)
// ============================================================
app.get('/projects', authMiddleware, (req, res) => {
  const userProjects = db.projects.filter(p => p.userId === req.user.id);
  res.json(userProjects);
});

app.post('/projects', authMiddleware, upload.single('video'), async (req, res) => {
  try {
    const { title, captionsJson, presetKey, chapters } = req.body;
    if (!title) {
      return res.status(400).json({ error: 'Title required' });
    }
    let captions = [];
    try { captions = JSON.parse(captionsJson || '[]'); } catch (_) {}
    let chaptersParsed = [];
    try { chaptersParsed = JSON.parse(chapters || '[]'); } catch (_) {}

    const project = {
      id: uuidv4(),
      userId: req.user.id,
      title: title.trim(),
      captions,
      presetKey: presetKey || '',
      chapters: chaptersParsed,
      hasVideo: !!req.file,
      videoPath: req.file ? req.file.path : null,
      createdAt: new Date().toISOString()
    };

    // If video uploaded, move it to projects dir with clean name
    if (req.file && req.file.path) {
      const ext = path.extname(req.file.originalname) || '.webm';
      const newName = `${project.id}${ext}`;
      const newPath = path.join(PROJECTS_DIR, newName);
      try {
        fs.renameSync(req.file.path, newPath);
        project.videoPath = newPath;
      } catch (_) {
        // If rename fails, keep original path
      }
    }

    db.projects.push(project);
    saveDB();

    res.status(201).json({ id: project.id, message: 'Project saved' });
  } catch (err) {
    console.error('Save project error:', err);
    try { if (req.file && req.file.path) fs.unlinkSync(req.file.path); } catch (_) {}
    res.status(500).json({ error: err.message || 'Failed to save project' });
  }
});

app.delete('/projects/:id', authMiddleware, (req, res) => {
  const idx = db.projects.findIndex(p => p.id === req.params.id && p.userId === req.user.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Project not found' });
  }
  const project = db.projects[idx];
  // Delete video file if exists
  if (project.videoPath && fs.existsSync(project.videoPath)) {
    try { fs.unlinkSync(project.videoPath); } catch (_) {}
  }
  db.projects.splice(idx, 1);
  saveDB();
  res.json({ message: 'Project deleted' });
});

app.get('/projects/:id/video', authMiddleware, (req, res) => {
  const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
  if (!project || !project.videoPath || !fs.existsSync(project.videoPath)) {
    return res.status(404).json({ error: 'Video not found' });
  }
  const filename = project.title.replace(/[^a-zA-Z0-9]/g, '_') + '.webm';
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'video/webm');
  fs.createReadStream(project.videoPath).pipe(res);
});

// ============================================================
// ORDERS (payment verification)
// ============================================================
app.post('/orders', async (req, res) => {
  try {
    const { user, email, plan, amount, utr } = req.body;
    if (!utr || utr.length < 4) {
      return res.status(400).json({ error: 'Valid UTR required' });
    }
    const order = {
      id: uuidv4().slice(0, 8).toUpperCase(),
      userEmail: (email || user || 'anonymous').toLowerCase(),
      plan: plan || 'Monthly',
      amount: amount || 0,
      utr: utr.trim(),
      status: 'pending',
      createdAt: new Date().toISOString()
    };
    db.orders.push(order);
    saveDB();

    // Send notification to admin (optional) — we just store it
    res.status(201).json({ id: order.id, status: 'pending' });
  } catch (err) {
    console.error('Order error:', err);
    res.status(500).json({ error: err.message || 'Failed to create order' });
  }
});

// ============================================================
// GDPR: EXPORT USER DATA
// ============================================================
app.get('/export', authMiddleware, (req, res) => {
  const userProjects = db.projects.filter(p => p.userId === req.user.id);
  const userOrders = db.orders.filter(o => o.userEmail === req.user.email);
  const userData = {
    user: {
      email: req.user.email,
      createdAt: req.user.createdAt,
      referralCode: req.user.referralCode
    },
    projects: userProjects.map(p => ({
      id: p.id,
      title: p.title,
      captions: p.captions,
      presetKey: p.presetKey,
      chapters: p.chapters,
      createdAt: p.createdAt
    })),
    orders: userOrders.map(o => ({
      id: o.id,
      plan: o.plan,
      amount: o.amount,
      status: o.status,
      createdAt: o.createdAt
    }))
  };
  res.json(userData);
});

// ============================================================
// DELETE ACCOUNT
// ============================================================
app.delete('/delete', authMiddleware, (req, res) => {
  // Delete user's projects and video files
  const userProjects = db.projects.filter(p => p.userId === req.user.id);
  userProjects.forEach(p => {
    if (p.videoPath && fs.existsSync(p.videoPath)) {
      try { fs.unlinkSync(p.videoPath); } catch (_) {}
    }
  });
  db.projects = db.projects.filter(p => p.userId !== req.user.id);
  db.users = db.users.filter(u => u.id !== req.user.id);
  saveDB();
  res.json({ message: 'Account deleted' });
});

// ============================================================
// TEAM MANAGEMENT
// ============================================================
app.post('/team/invite', authMiddleware, (req, res) => {
  const { invitee, role } = req.body;
  if (!invitee || !invitee.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }
  const existing = db.teamInvites.find(t => t.inviteeEmail === invitee && t.status === 'pending');
  if (existing) {
    return res.status(400).json({ error: 'Invite already pending' });
  }
  db.teamInvites.push({
    id: uuidv4(),
    inviterEmail: req.user.email,
    inviteeEmail: invitee.toLowerCase(),
    role: role || 'editor',
    status: 'pending',
    createdAt: new Date().toISOString()
  });
  saveDB();
  res.json({ message: 'Invite sent to ' + invitee });
});

app.get('/team', authMiddleware, (req, res) => {
  // For simplicity, return invites where user is inviter
  const invites = db.teamInvites.filter(t => t.inviterEmail === req.user.email);
  res.json(invites.map(t => ({
    email: t.inviteeEmail,
    role: t.role,
    status: t.status,
    createdAt: t.createdAt
  })));
});

app.delete('/team/remove', authMiddleware, (req, res) => {
  const { member } = req.body;
  if (!member) {
    return res.status(400).json({ error: 'Member email required' });
  }
  db.teamInvites = db.teamInvites.filter(t =>
    !(t.inviterEmail === req.user.email && t.inviteeEmail === member)
  );
  saveDB();
  res.json({ message: 'Removed ' + member });
});

// ============================================================
// CALLBACK REQUEST
// ============================================================
app.post('/callback-request', (req, res) => {
  const { name, phone } = req.body;
  if (!phone || phone.length < 8) {
    return res.status(400).json({ error: 'Valid phone number required' });
  }
  db.callbacks.push({
    id: uuidv4(),
    name: (name || 'Anonymous').trim(),
    phone: phone.trim(),
    createdAt: new Date().toISOString()
  });
  saveDB();
  res.json({ message: 'Callback request recorded' });
});

// ============================================================
// FALLBACK: serve a simple status page
// ============================================================
app.get('/', (req, res) => {
  res.json({
    name: 'AutoCaptio Backend',
    version: '1.0.0',
    status: 'running',
    endpoints: [
      '/health', '/settings', '/signup', '/login',
      '/transcribe', '/translate',
      '/projects', '/projects/:id', '/projects/:id/video',
      '/orders', '/export', '/delete',
      '/team/invite', '/team', '/team/remove',
      '/callback-request'
    ]
  });
});

// ============================================================
// ERROR HANDLING
// ============================================================
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 AutoCaptio backend running on port ${PORT}`);
  console.log(`📁 Data directory: ${DATA_DIR}`);
  console.log(`🔑 OpenAI API key ${OPENAI_API_KEY ? '✓ set' : '✗ missing'}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  saveDB();
  console.log('🛑 Server shutting down...');
  process.exit(0);
});
