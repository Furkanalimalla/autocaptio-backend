// server.js
// Run with: node server.js
// Requires: express, cors, multer, bcrypt, uuid, fs, path

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Middleware ----------
app.use(cors({
  origin: '*', // allow all origins (for development)
  methods: ['GET', 'POST', 'DELETE', 'PUT'],
  allowedHeaders: ['Content-Type', 'x-user-token']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Multer configuration for file uploads (audio/video)
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

// ---------- Data persistence (JSON files) ----------
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const TEAM_FILE = path.join(DATA_DIR, 'team.json');
const CALLBACKS_FILE = path.join(DATA_DIR, 'callbacks.json');

// Helper to read/write JSON files
function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return [];
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ---------- In-memory stores (also persisted) ----------
let users = readJSON(USERS_FILE);
let projects = readJSON(PROJECTS_FILE);
let orders = readJSON(ORDERS_FILE);
let teamInvites = readJSON(TEAM_FILE);
let callbacks = readJSON(CALLBACKS_FILE);

function saveAll() {
  writeJSON(USERS_FILE, users);
  writeJSON(PROJECTS_FILE, projects);
  writeJSON(ORDERS_FILE, orders);
  writeJSON(TEAM_FILE, teamInvites);
  writeJSON(CALLBACKS_FILE, callbacks);
}

// ---------- Helper: get user by token ----------
function getUserByToken(token) {
  if (!token) return null;
  return users.find(u => u.token === token) || null;
}

// Middleware to verify token (used for protected routes)
function requireUser(req, res, next) {
  const token = req.headers['x-user-token'];
  const user = getUserByToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  req.user = user;
  next();
}

// ---------- Routes ----------

// ========== Settings (public) ==========
app.get('/settings', (req, res) => {
  res.json({
    upiId: 'autocaptio@upi',
    qrImage: null, // can be a base64 or URL
    prices: { single: 10, weekly: 39, monthly: 114, yearly: 900 }
  });
});

// ========== Auth ==========
app.post('/signup', async (req, res) => {
  const { email, password, referral } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'Email already registered' });
  }
  const hashed = await bcrypt.hash(password, 10);
  const token = uuidv4();
  const user = {
    id: uuidv4(),
    email,
    password: hashed,
    token,
    plan: 'free',
    createdAt: new Date().toISOString(),
    referralCode: uuidv4().slice(0, 8).toUpperCase(),
    referredBy: referral || null,
    points: 0,
    videosProcessed: 0
  };
  users.push(user);
  saveAll();
  res.json({ email: user.email, token: user.token });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  // Regenerate token (optional)
  user.token = uuidv4();
  saveAll();
  res.json({ email: user.email, token: user.token });
});

// ========== Dashboard (protected) ==========
app.get('/dashboard', requireUser, (req, res) => {
  const user = req.user;
  res.json({
    plan: user.plan || 'free',
    videosProcessed: user.videosProcessed || 0,
    points: user.points || 0,
    referralCode: user.referralCode,
    credits: 0 // always free now
  });
});

// ========== Projects (CRUD) ==========
// List projects
app.get('/projects', requireUser, (req, res) => {
  const userProjects = projects.filter(p => p.userId === req.user.id);
  res.json(userProjects);
});

// Save project (with optional video file)
app.post('/projects', requireUser, upload.single('video'), (req, res) => {
  const { title, captionsJson, presetKey, chapters } = req.body;
  if (!title) {
    return res.status(400).json({ error: 'Title required' });
  }
  let captions = [];
  try { captions = JSON.parse(captionsJson); } catch(e) { /* ignore */ }
  let chapterData = [];
  try { chapterData = JSON.parse(chapters || '[]'); } catch(e) { /* ignore */ }

  const project = {
    id: uuidv4(),
    userId: req.user.id,
    title,
    captions,
    presetKey: presetKey || '',
    chapters: chapterData,
    hasVideo: !!req.file,
    createdAt: new Date().toISOString()
  };
  projects.push(project);
  saveAll();

  // Optionally store video file (for simplicity we store as base64 in memory, but better to store on disk)
  // For demo, we'll store the video in a separate file or just keep as blob in memory.
  // Here we'll store it as a buffer in a 'videos' folder.
  if (req.file) {
    const videoDir = path.join(DATA_DIR, 'videos');
    if (!fs.existsSync(videoDir)) fs.mkdirSync(videoDir);
    const videoPath = path.join(videoDir, `${project.id}.mp4`);
    fs.writeFileSync(videoPath, req.file.buffer);
    project.videoPath = videoPath; // we could store path, but not in JSON for simplicity
    // We'll just set hasVideo true and serve via another endpoint.
  }
  saveAll();

  res.json({ id: project.id, message: 'Project saved' });
});

// Get video for a project
app.get('/projects/:id/video', requireUser, (req, res) => {
  const project = projects.find(p => p.id === req.params.id && p.userId === req.user.id);
  if (!project || !project.hasVideo) {
    return res.status(404).json({ error: 'Video not found' });
  }
  const videoPath = path.join(DATA_DIR, 'videos', `${project.id}.mp4`);
  if (fs.existsSync(videoPath)) {
    res.sendFile(videoPath);
  } else {
    res.status(404).json({ error: 'Video file missing' });
  }
});

// Delete project
app.delete('/projects/:id', requireUser, (req, res) => {
  const index = projects.findIndex(p => p.id === req.params.id && p.userId === req.user.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Project not found' });
  }
  projects.splice(index, 1);
  saveAll();
  res.json({ message: 'Project deleted' });
});

// ========== Transcription (mock) ==========
app.post('/transcribe', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No audio file provided' });
  }
  // Simulate transcription with some mock data
  // Replace this with actual Whisper API call or local inference
  const words = [
    { word: 'Hey', start: 0.0, end: 0.4, confidence: 0.95 },
    { word: 'creators!', start: 0.5, end: 1.2, confidence: 0.92 },
    { word: 'Welcome', start: 1.3, end: 1.9, confidence: 0.98 },
    { word: 'to', start: 2.0, end: 2.3, confidence: 0.99 },
    { word: 'AutoCaptio', start: 2.4, end: 3.2, confidence: 0.96 },
    { word: 'Upload', start: 3.3, end: 3.9, confidence: 0.94 },
    { word: 'your', start: 4.0, end: 4.3, confidence: 0.97 },
    { word: 'video', start: 4.4, end: 5.4, confidence: 0.93 },
    { word: 'Get', start: 5.5, end: 5.9, confidence: 0.95 },
    { word: 'instant', start: 6.0, end: 6.6, confidence: 0.91 },
    { word: 'subtitles', start: 6.7, end: 7.6, confidence: 0.89 },
    { word: 'Then', start: 7.7, end: 8.1, confidence: 0.92 },
    { word: 'make', start: 8.2, end: 8.6, confidence: 0.90 },
    { word: 'it', start: 8.7, end: 9.0, confidence: 0.98 },
    { word: 'viral', start: 9.1, end: 9.8, confidence: 0.88 }
  ];
  // Increase user's processed count
  const user = getUserByToken(req.headers['x-user-token']);
  if (user) {
    user.videosProcessed = (user.videosProcessed || 0) + 1;
    user.points = (user.points || 0) + 10;
    saveAll();
  }
  res.json({ words });
});

// ========== Translation (mock) ==========
app.post('/translate', express.json(), (req, res) => {
  const { words, targetLanguage } = req.body;
  if (!words || !targetLanguage) {
    return res.status(400).json({ error: 'Missing words or targetLanguage' });
  }
  // Simulate translation by prefixing or using a simple mapping (for demo)
  const translated = words.map(w => {
    let translatedWord = w.word;
    if (targetLanguage === 'hi') {
      // Simple mock Hindi (just for demo)
      const map = { 'Hey': 'अरे', 'creators!': 'निर्माताओं', 'Welcome': 'स्वागत', 'to': 'को', 'AutoCaptio': 'ऑटोकैप्शन', 'Upload': 'अपलोड', 'your': 'आपका', 'video': 'वीडियो', 'Get': 'प्राप्त', 'instant': 'तुरंत', 'subtitles': 'उपशीर्षक', 'Then': 'फिर', 'make': 'बनाएं', 'it': 'इसे', 'viral': 'वायरल' };
      translatedWord = map[w.word] || w.word + ' (hi)';
    } else if (targetLanguage === 'es') {
      const map = { 'Hey': 'Hola', 'creators!': 'creadores', 'Welcome': 'Bienvenido', 'to': 'a', 'AutoCaptio': 'AutoCaptio', 'Upload': 'Subir', 'your': 'tu', 'video': 'video', 'Get': 'Obtener', 'instant': 'instantáneo', 'subtitles': 'subtítulos', 'Then': 'Entonces', 'make': 'hacer', 'it': 'lo', 'viral': 'viral' };
      translatedWord = map[w.word] || w.word + ' (es)';
    } else if (targetLanguage === 'hinglish') {
      // Add "ji" for fun
      translatedWord = w.word + ' ji';
    }
    return { ...w, word: translatedWord };
  });
  res.json({ words: translated });
});

// ========== Orders ==========
app.post('/orders', express.json(), (req, res) => {
  const { user, email, plan, amount, utr } = req.body;
  if (!utr) {
    return res.status(400).json({ error: 'UTR required' });
  }
  const order = {
    id: uuidv4().slice(0, 8).toUpperCase(),
    user: user || email,
    email,
    plan,
    amount,
    utr,
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  orders.push(order);
  saveAll();
  res.json({ id: order.id, status: 'pending' });
});

// ========== Callback request ==========
app.post('/callback-request', express.json(), (req, res) => {
  const { name, phone } = req.body;
  if (!phone) {
    return res.status(400).json({ error: 'Phone required' });
  }
  callbacks.push({ id: uuidv4(), name, phone, createdAt: new Date().toISOString() });
  saveAll();
  res.json({ message: 'Callback request received' });
});

// ========== Team Management ==========
app.get('/team', requireUser, (req, res) => {
  // For demo, return a static list or from teamInvites
  const members = teamInvites.filter(t => t.ownerId === req.user.id);
  res.json(members);
});

app.post('/team/invite', requireUser, express.json(), (req, res) => {
  const { invitee, role } = req.body;
  if (!invitee) {
    return res.status(400).json({ error: 'Invitee email required' });
  }
  teamInvites.push({
    id: uuidv4(),
    ownerId: req.user.id,
    email: invitee,
    role: role || 'editor',
    createdAt: new Date().toISOString()
  });
  saveAll();
  res.json({ message: 'Invite sent' });
});

app.delete('/team/remove', requireUser, express.json(), (req, res) => {
  const { member } = req.body;
  const index = teamInvites.findIndex(t => t.email === member && t.ownerId === req.user.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Member not found' });
  }
  teamInvites.splice(index, 1);
  saveAll();
  res.json({ message: 'Removed' });
});

// ========== GDPR Export ==========
app.get('/export', requireUser, (req, res) => {
  const userProjects = projects.filter(p => p.userId === req.user.id);
  const userOrders = orders.filter(o => o.user === req.user.email || o.email === req.user.email);
  res.json({
    user: req.user,
    projects: userProjects,
    orders: userOrders,
    callbacks: callbacks.filter(c => c.phone === req.user.phone) // optional
  });
});

// ========== Delete Account ==========
app.delete('/delete', requireUser, (req, res) => {
  const userIndex = users.findIndex(u => u.id === req.user.id);
  if (userIndex > -1) {
    users.splice(userIndex, 1);
    // Also delete their projects
    projects = projects.filter(p => p.userId !== req.user.id);
    saveAll();
    res.json({ message: 'Account deleted' });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// ========== Start server ==========
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
