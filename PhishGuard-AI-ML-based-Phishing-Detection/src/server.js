const express = require('express');
const axios = require('axios');
const path = require('path');
const fetchEmails = require("./fetchEmails");
const { analyzeEmail } = require('./phishingDetector');

const app = express();
const PORT = process.env.PORT || 8080;

const cors = require('cors');
app.use(cors());


// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// === ROUTES === //

// Fetch Gmail Emails
app.get("/api/fetch-emails", async (req, res) => {
  try {
    const emails = await fetchEmails();
    res.json(emails);
  } catch (error) {
    console.error("Error fetching emails:", error.message);
    res.status(500).json({ error: "Failed to fetch emails" });
  }
});

// Run Local Detection Logic (Node.js)
app.post('/api/check-email', (req, res) => {
  const content = req.body.content || '';
  const subject = req.body.subject || '';
  const from = req.body.from || '';

  const result = analyzeEmail(content, subject, from);
  res.json(result);
});

// Health check for Python backend
app.get('/api/check-backend', async (req, res) => {
  try {
    const response = await axios.get('http://localhost:5001/api/health');
    res.json({ status: 'Connected ✅', details: response.data });
  } catch (error) {
    res.json({ status: 'Not Connected ❌', error: error.message });
  }
});

// Python backend phishing analysis
app.post('/analyze-email', async (req, res) => {
  try {
    const { sender_email, subject, content } = req.body;
    const response = await axios.post('http://localhost:5001/api/analyze', {
      sender_email,
      subject,
      content
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error calling Python API:', error.message);
    res.status(error.code === 'ECONNREFUSED' ? 503 : 500).json({
      error: error.code === 'ECONNREFUSED'
        ? 'Python analysis service is not running'
        : 'Analysis service error',
      details: error.message
    });
  }
});

// Shortcut route for compatibility
app.post('/api/analyze', (req, res) => {
  req.url = '/analyze-email';
  app._router.handle(req, res);
});

// Frontend Entry
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Node.js Server running on http://localhost:${PORT}`);
  console.log(`📡 Ensure Python backend is running at http://localhost:5001`);
});
