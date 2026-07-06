// AutoCaptio backend — the ONLY place your OpenAI API key ever lives.
// Users never see this key. Their browser sends audio here; this server
// forwards it to OpenAI using YOUR key (kept in an environment variable /
// Glitch "Secret", never written into this file or sent to the browser).

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fetch = require('node-fetch');
const FormData = require('form-data');

const app = express();
app.use(cors()); // allows your website (on a different domain) to call this server

// Accept uploaded audio in memory (fine for the small, compressed audio files
// the frontend sends — it's already extracted/compressed audio, not the raw video).
const upload = multer({ limits: { fileSize: 30 * 1024 * 1024 } }); // 30MB safety cap

app.get('/', (req, res) => {
  res.send('AutoCaptio backend is running ✓');
});

app.post('/transcribe', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file received' });
    }
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Server is missing OPENAI_API_KEY — add it in your hosting dashboard\'s secrets/environment variables' });
    }

    const form = new FormData();
    form.append('file', req.file.buffer, { filename: req.file.originalname || 'audio.webm' });
    form.append('model', 'whisper-1');
    form.append('response_format', 'verbose_json');
    form.append('timestamp_granularities[]', 'word');

    const whisperRes = await fetch('https://api.openai.com/v1/audio/transcriptions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, ...form.getHeaders() },
      body: form
    });

    const data = await whisperRes.json();
    if (!whisperRes.ok) {
      return res.status(whisperRes.status).json({ error: data.error?.message || 'Whisper API error' });
    }
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Transcription failed on the server' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`AutoCaptio backend listening on port ${PORT}`));
