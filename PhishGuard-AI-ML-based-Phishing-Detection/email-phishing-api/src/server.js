const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

const fetchEmails = require("./fetchEmails");

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// API to fetch Gmail emails
app.get("/api/fetch-emails", async (req, res) => {
    try {
        const emails = await fetchEmails();
        res.json(emails);
    } catch (error) {
        console.error("Error fetching emails:", error.message);
        res.status(500).json({ error: "Failed to fetch emails" });
    }
});

// Serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Check if Python backend is running
app.get('/api/check-backend', async (req, res) => {
    try {
        const response = await axios.get('http://localhost:5001/api/health');
        res.json({ status: 'Connected ✅', details: response.data });
    } catch (error) {
        res.json({ status: 'Not Connected ❌', error: error.message });
    }
});

// Analyze email endpoint (calls Python backend)
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
        if (error.code === 'ECONNREFUSED') {
            res.status(503).json({
                error: 'Python analysis service is not running',
                details: 'Please start the Python backend first'
            });
        } else {
            res.status(500).json({
                error: 'Analysis service error',
                details: error.message
            });
        }
    }
});

// Support alternative endpoint
app.post('/api/analyze', (req, res) => {
    req.url = '/analyze-email';
    app._router.handle(req, res);
});


// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, '..', 'public')));

// Serve the main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 Node.js Frontend running on http://localhost:${PORT}`);
    console.log(`📡 Make sure Python backend is running on port 5001`);
    console.log(`🔗 Visit: http://localhost:${PORT} to use the app`);
});
