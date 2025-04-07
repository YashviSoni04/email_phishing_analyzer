

---

```markdown
# 🛡️ PhishGuard: AI/ML-based Phishing Detection System

PhishGuard is a comprehensive phishing email detection system that integrates Gmail API access with phishing heuristics and threat intelligence APIs to identify suspicious emails. This project utilizes Natural Language Processing, link analysis, and domain reputation checks to detect potentially malicious emails.

---

## 📂 Project Structure

```
PhishGuard-AI-ML-based-Phishing-Detection/
│
├── email-phishing-api/
│   └── src/
│       ├── server.js           # Backend server
│       ├── phishingChecker.js  # Main phishing detection logic
│       ├── token.json          # Gmail API token
│       ├── client_secret.json  # Gmail API credentials
│       ├── index.html          # Frontend interface
│       └── ...
```

---

## 🚀 Features

- ✅ Gmail API integration to fetch emails
- 🔗 URL extraction and analysis using VirusTotal
- 🌐 WHOIS-based domain reputation checks
- 🧠 Pattern recognition for phishing phrases
- ⚠️ Flags emails with suspicious links or phishing patterns
- 📊 Frontend interface for quick testing

---

## 📦 Requirements

- Node.js >= 16.x
- Google API Credentials (`client_secret.json` and `token.json`)
- VirusTotal API Key (set in `.env` or environment variable)
- Internet connection

---

## 🔧 Installation

1. **Clone the Repository**

```bash
git clone https://github.com/yourusername/PhishGuard-AI-ML-based-Phishing-Detection.git
cd PhishGuard-AI-ML-based-Phishing-Detection/email-phishing-api/src
```

2. **Install Dependencies**

```bash
npm install
```

3. **Setup Environment Variables**

Create a `.env` file or export the following:

```env
VIRUS_TOTAL_API_KEY=your_api_key_here
```

4. **Add Gmail API Credentials**

Place the following files in the `src/` folder:
- `client_secret.json`
- `token.json`

[Get Gmail API Credentials →](https://developers.google.com/gmail/api/quickstart/nodejs)

---

## 🖥️ Run the Application

### Backend (API Server)

```bash
node server.js
```

Server will run on: [http://localhost:8080](http://localhost:8080)

You may see a warning:
```
[DEP0040] DeprecationWarning: The `punycode` module is deprecated.
```
This can be safely ignored or patched by replacing `punycode` with a userland library if needed.

---

### Frontend

Open the HTML file in your browser:

```
http://127.0.0.1:5500/PhishGuard-AI-ML-based-Phishing-Detection/email-phishing-api/src/index.html
```

---

## 📌 Notes

- Limits email fetch to the latest **100** emails.
- Emails are scanned for suspicious keywords, domains, and links.
- External APIs (e.g., VirusTotal) may have rate limits.

---

## 📸 Screenshot

![PhishGuard Interface]![alt text](image.png)

---

## 🛠️ Future Enhancements

- 🔍 ML-based text classification for phishing
- 📦 Save reports to local DB (e.g., SQLite, MongoDB)
- 📤 Auto-forward detected phishing mails to admin
- 📈 Dashboard with analytics and filters

---

## 🤝 Contributions

Pull requests are welcome! Feel free to fork and enhance the detection logic or interface.

---

