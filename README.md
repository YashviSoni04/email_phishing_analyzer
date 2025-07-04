# 📧 PhishGuard — AI/ML-Based Email Phishing Detection

PhishGuard is a **Node.js + Python** powered system that integrates with your Gmail to detect phishing emails in real-time. It uses custom logic, keyword scanning, and external reputation APIs to identify suspicious messages.

---

## 🚀 Features

✅ Fetches emails from Gmail using OAuth2  
🚨 Detects phishing based on:
- Suspicious phrases (e.g., *verify your account*, *urgent action*)
- Phishing URLs (via VirusTotal, WHOIS)
- Newly registered domains or spoofing signs  
📊 Dashboard with score, reasons, and links  
🧩 Chrome Extension to view phishing detection **inside Gmail UI**

---

## 🛠️ Tech Stack

- **Frontend:** Vanilla HTML + Bootstrap
- **Node.js:** Express server (REST APIs)
- **Python:** Email content analyzer
- **Google APIs:** Gmail + OAuth2 integration
- **Optional APIs:** VirusTotal, WHOIS

---

## 📁 Folder Structure

phishing_analyzer/
│
├── public/ # Frontend dashboard
│ └── index.html
│
├── src/ # Backend
│ ├── server.js # Main Node.js server
│ ├── fetchEmails.js # Gmail API logic
│ ├── phishingDetector.js # Node.js detection logic
│ ├── generateToken.js # Google OAuth2 token setup
│ ├── token.json # Google token (gitignored)
│ └── client_secret.json # Google credentials (gitignored)
│
├── phishing_analyzer.py # (Optional) Python-based ML analyzer
├── gmail-extension/ # Chrome extension folder
│ ├── content.js # Injects results in Gmail
│ ├── manifest.json
│ └── (icons, optional popup.html)
│
├── .env # API keys (VirusTotal, Gmail info)
├── README.md


---

## 🔧 Setup Instructions

### 1. Clone and Navigate

```bash
git clone https://github.com/YashviSoni04/email_phishing_analyzer.git
cd email_phishing_analyzer



2. 🔑 Set Up Google OAuth2
Go to https://console.cloud.google.com/

Create OAuth client ID

Add this as redirect URI:
http://localhost:8080/oauth2callback

Download the client_secret.json and place it in /src/


3. 🧠 Python Backend (Optional)
pip install -r requirements.txt
python phishing_analyzer.py  

4. 🚀 Start Node Server
cd PhishGuard-AI-ML-based-Phishing-Detection
npm install
node src/server.js

5. 🌐 Open Dashboard
http://localhost:8080

If using a Chrome extension, expose the port via:
cloudflared tunnel --url http://localhost:8080
Copy the HTTPS URL and use it in your extension content.js and manifest.json.

🧩 Chrome Extension Setup (Optional)
Go to chrome://extensions
Enable Developer Mode
Click Load Unpacked
Select the gmail-extension folder

⚠️ Update the Cloudflare URL in:

gmail-extension/content.js (for fetch URL)
gmail-extension/manifest.json under "host_permissions"

