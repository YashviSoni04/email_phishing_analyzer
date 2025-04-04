# Automated Phishing Email Analyzer

This application provides automated triage and analysis of suspected phishing emails, implementing SOAR (Security Orchestration, Automation and Response) security principles.

## Features

- Automatic extraction and analysis of email artifacts
- Detection of suspicious patterns in email content
- URL and IP analysis
- Attachment scanning
- Real-time web interface for email analysis
- API endpoint for integration with other systems

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Start the API server:
```bash
python api.py
```

3. Open the web interface by navigating to the `static/index.html` file in your browser

## Usage

1. Access the web interface
2. Paste the suspicious email content into the text area
3. Click "Analyze" to get detailed analysis results including:
   - Verdict (Benign/Malicious/Unknown)
   - Reason for the verdict
   - Extracted artifacts (URLs, IPs, attachments)

## API Endpoint

POST `/analyze`
- Request body: `{ "content": "email content here" }`
- Returns analysis results including verdict and artifacts

## Architecture

The system follows the workflow shown in the design:
1. Automatically pulls suspected phishing emails
2. Extracts IPs/URLs and researches them with threat intelligence
3. If unknown, submits attachments to sandbox for inspection
4. Based on analysis, marks emails as benign or malicious
5. Takes appropriate action (notify user or quarantine)
