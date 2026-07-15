// server.js — Full backend for AutoCaptio (new HTML version)
// Supports: auth, projects, transcription, translation, team, etc.
// Uses in‑memory storage (resets on restart). For production, use a database.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const OpenAI = require('openai');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- MIDDLEWARE ----------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------- OPENAI SETUP ----------
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// ---------- MULTER ----------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB
});

// ---------- IN‑MEMORY STORAGE ----------
// Users: { email, passwordHash, token, referralCode, points, videosProcessed, plan, planExpiry, exportCredits, team: [] }
const users = new Map();

// Projects: { id, userId, title, captions, presetKey, chapters, hasVideo, videoData (Buffer), createdAt }
const projects = new Map();

// Team invites: { inviteeEmail, role, inviterEmail }
const invites = [];

// Callback requests: { name, phone }
const callbacks = [];

// Helper: generate token
function generateToken() {
  return jwt.sign({ id: uuidv4() }, process.env.JWT_SECRET || 'secret-key', { expiresIn: '30d' });
}

// Helper: hash password
async function hashPassword(pw) {
  return await bcrypt.hash(pw, 10);
}

// Helper: verify password
async function verifyPassword(pw, hash) {
  return await bcrypt.compare(pw, hash);
}

// Helper: auth middleware
function authenticate(req, res, next) {
  const token = req.headers['x-user-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const user = users.get(decoded.id);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    req.userId = decoded.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- ROUTES ----------

// Health
app.get('/', (req, res) => res.json({ status: 'ok', message: 'AutoCaptio Backend running' }));

// Settings (public)
app.get('/settings', (req, res) => {
  res.json({
    upiId: 'autocaptio@upi',
    qrImage: null,
    prices: { single: 10, weekly: 39, monthly: 114, yearly: 900 },
  });
});

// ---------- AUTH ----------
app.post('/signup', async (req, res) => {
  try {
    const { email, password, referral } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    // Check if user exists
    let existing = null;
    for (let [id, user] of users.entries()) {
      if (user.email === email) { existing = user; break; }
    }
    if (existing) return res.status(400).json({ error: 'User already exists' });

    const userId = uuidv4();
    const hashed = await hashPassword(password);
    const referralCode = 'AUTO-' + Math.random().toString(36).substring(2, 8).toUpperCase();

    // Handle referral (just add points, not implemented fully)
    let points = 0;
    if (referral) {
      // Give referrer points (simplified)
      for (let [id, user] of users.entries()) {
        if (user.referralCode === referral) {
          user.points = (user.points || 0) + 10;
          break;
        }
      }
      points = 5; // new user gets points
    }

    const newUser = {
      email,
      passwordHash: hashed,
      token: generateToken(),
      referralCode,
      points,
      videosProcessed: 0,
      plan: 'Free Forever',
      planExpiry: null,
      exportCredits: 0,
      team: [], // emails of team members (invited by this user)
    };
    users.set(userId, newUser);

    res.json({ email, token: newUser.token, referralCode });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    let foundUser = null;
    let foundId = null;
    for (let [id, user] of users.entries()) {
      if (user.email === email) { foundUser = user; foundId = id; break; }
    }
    if (!foundUser) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await verifyPassword(password, foundUser.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    // Generate new token
    const token = generateToken();
    foundUser.token = token;
    users.set(foundId, foundUser);

    res.json({ email, token, referralCode: foundUser.referralCode });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/me', authenticate, (req, res) => {
  const user = req.user;
  res.json({
    email: user.email,
    plan: user.plan,
    expiry: user.planExpiry,
    videosProcessed: user.videosProcessed || 0,
    points: user.points || 0,
    exportCredits: user.exportCredits || 0,
    referralCode: user.referralCode,
  });
});

// Consume a credit (for single video plans)
app.post('/me/consume-credit', authenticate, (req, res) => {
  const user = req.user;
  if (user.exportCredits > 0) {
    user.exportCredits -= 1;
    users.set(req.userId, user);
    res.json({ success: true, remaining: user.exportCredits });
  } else {
    res.status(400).json({ error: 'No credits left' });
  }
});

// Delete account
app.delete('/delete', authenticate, (req, res) => {
  const userId = req.userId;
  // Delete all projects of this user
  for (let [projId, proj] of projects.entries()) {
    if (proj.userId === userId) projects.delete(projId);
  }
  users.delete(userId);
  res.json({ success: true });
});

// ---------- PROJECTS ----------
app.get('/projects', authenticate, (req, res) => {
  const userId = req.userId;
  const userProjects = [];
  for (let [id, proj] of projects.entries()) {
    if (proj.userId === userId) {
      userProjects.push({
        id,
        title: proj.title,
        captions: proj.captions,
        presetKey: proj.presetKey,
        chapters: proj.chapters,
        hasVideo: !!proj.videoData,
        createdAt: proj.createdAt,
      });
    }
  }
  res.json(userProjects);
});

app.post('/projects', authenticate, upload.single('video'), (req, res) => {
  try {
    const userId = req.userId;
    const { title, captionsJson, presetKey, chapters } = req.body;
    if (!captionsJson) return res.status(400).json({ error: 'Missing captions' });

    const id = uuidv4();
    const project = {
      userId,
      title: title || 'Untitled',
      captions: JSON.parse(captionsJson),
      presetKey: presetKey || '',
      chapters: chapters ? JSON.parse(chapters) : [],
      videoData: req.file ? req.file.buffer : null,
      createdAt: new Date().toISOString(),
    };
    projects.set(id, project);

    // Increment videos processed
    const user = req.user;
    user.videosProcessed = (user.videosProcessed || 0) + 1;
    users.set(userId, user);

    res.json({ id, success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Project save failed' });
  }
});

app.delete('/projects/:id', authenticate, (req, res) => {
  const userId = req.userId;
  const projId = req.params.id;
  const proj = projects.get(projId);
  if (!proj) return res.status(404).json({ error: 'Project not found' });
  if (proj.userId !== userId) return res.status(403).json({ error: 'Forbidden' });
  projects.delete(projId);
  res.json({ success: true });
});

app.get('/projects/:id/video', authenticate, (req, res) => {
  const userId = req.userId;
  const projId = req.params.id;
  const proj = projects.get(projId);
  if (!proj) return res.status(404).json({ error: 'Project not found' });
  if (proj.userId !== userId) return res.status(403).json({ error: 'Forbidden' });
  if (!proj.videoData) return res.status(404).json({ error: 'No video saved' });
  res.set('Content-Type', 'video/mp4');
  res.set('Content-Disposition', `attachment; filename="${proj.title || 'project'}.mp4"`);
  res.send(proj.videoData);
});

// ---------- TRANSCRIBE ----------
app.post('/transcribe', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No audio file uploaded' });

    const language = req.body.language || '';
    const audioFile = new File([req.file.buffer], req.file.originalname || 'audio.webm', {
      type: req.file.mimetype || 'audio/webm',
    });

    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      language: language || undefined,
      response_format: 'verbose_json',
      timestamp_granularities: ['word'],
    });

    const words = transcription.words.map(w => ({
      word: w.word,
      start: w.start,
      end: w.end,
      confidence: w.confidence || 0.9,
    }));

    res.json({ words });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Transcription failed' });
  }
});

// ---------- TRANSLATE ----------
app.post('/translate', async (req, res) => {
  try {
    const { words, targetLanguage } = req.body;
    if (!words || !targetLanguage) return res.status(400).json({ error: 'Missing parameters' });

    // If no API key, return original
    if (!process.env.OPENAI_API_KEY) {
      return res.json({ words: words.map(w => ({ ...w, word: w.word })) });
    }

    const text = words.map(w => w.word).join(' ');
    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: `Translate the following to ${targetLanguage}. Only output the translated text, no extra words.` },
        { role: 'user', content: text },
      ],
      temperature: 0.3,
    });

    const translatedText = completion.choices[0].message.content.trim();
    const translatedWords = translatedText.split(/\s+/);
    const newWords = words.map((w, i) => ({
      ...w,
      word: translatedWords[i] || w.word,
    }));

    res.json({ words: newWords });
  } catch (err) {
    console.error(err);
    // Return original words on error
    res.json({ words: words.map(w => ({ ...w, word: w.word })) });
  }
});

// ---------- CALLBACK REQUEST ----------
app.post('/callback-request', (req, res) => {
  const { name, phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });
  callbacks.push({ name: name || 'Anonymous', phone, timestamp: new Date().toISOString() });
  res.json({ success: true });
});

// ---------- TEAM MANAGEMENT ----------
app.get('/team', authenticate, (req, res) => {
  const user = req.user;
  // Return team members (invited by this user)
  const members = user.team ? user.team.map(email => ({ email, role: 'editor' })) : [];
  res.json(members);
});

app.post('/team/invite', authenticate, (req, res) => {
  const { invitee, role } = req.body;
  if (!invitee) return res.status(400).json({ error: 'Email required' });
  // Check if invitee exists as a user (optional)
  const user = req.user;
  if (!user.team) user.team = [];
  if (user.team.includes(invitee)) return res.status(400).json({ error: 'Already invited' });
  user.team.push(invitee);
  users.set(req.userId, user);
  res.json({ success: true });
});

app.delete('/team/remove', authenticate, (req, res) => {
  const { member } = req.body;
  if (!member) return res.status(400).json({ error: 'Member email required' });
  const user = req.user;
  if (!user.team) return res.status(404).json({ error: 'No team' });
  const idx = user.team.indexOf(member);
  if (idx === -1) return res.status(404).json({ error: 'Member not found' });
  user.team.splice(idx, 1);
  users.set(req.userId, user);
  res.json({ success: true });
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 Endpoints ready: /signup, /login, /me, /projects, /transcribe, /translate, /team, /callback-request`);
  if (!process.env.OPENAI_API_KEY) {
    console.warn('⚠️  OPENAI_API_KEY is not set. Transcription will fail.');
  }
});
