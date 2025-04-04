import email
from email import policy
import re
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import requests
from bs4 import BeautifulSoup
import logging
from enum import Enum
from urllib.parse import urlparse
import dns.resolver
import socket
import uuid
from datetime import datetime
import webbrowser
import os
import threading
import tempfile
from flask import Flask, request, render_template_string, jsonify

class EmailVerdict(Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

@dataclass
class EmailArtifact:
    sender: str
    subject: str
    ips: List[str]
    urls: List[str]
    attachments: List[str]

@dataclass
class EmailAnalysisResult:
    verdict: str
    risk_score: float
    reason: str
    artifacts: Dict[str, Any]
    recommendations: List[str]

class PhishingAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_patterns = [
            r'urgent|password|account.*suspend|verify.*account',
            r'bank.*transfer|credit.*card|social.*security',
            r'\.exe$|\.zip$|\.scr$',
            r'bitcoin|crypto|wallet|investment',
            r'login.*verify|security.*alert|unusual.*activity'
        ]
        
        self.malicious_tlds = [
            '.tk', '.top', '.xyz', '.zip', '.review', '.country', '.kim', '.cricket',
            '.science', '.work', '.party', '.gq', '.link', '.win', '.bid', '.loan'
        ]

    def analyze_email(self, content: str, sender: Optional[str] = None, subject: Optional[str] = None,
                     urls: Optional[List[Dict]] = None, auth_results: Optional[Dict] = None,
                     attachments: Optional[List[Dict]] = None) -> EmailAnalysisResult:
        """Analyze email content for phishing indicators"""
        risk_factors = []
        risk_score = 0
        artifacts = {}
        
        # Extract basic artifacts
        email_artifacts = self.extract_artifacts(content)
        artifacts = {
            "sender": sender or email_artifacts.sender,
            "subject": subject or email_artifacts.subject,
            "urls": email_artifacts.urls,
            "ips": email_artifacts.ips,
            "attachments": email_artifacts.attachments
        }
        
        # Check sender
        if sender:
            sender_domain = sender.split('@')[1] if '@' in sender else ''
            if any(tld in sender_domain.lower() for tld in self.malicious_tlds):
                risk_factors.append(f"Suspicious sender domain: {sender_domain}")
                risk_score += 30
        
        # Check authentication results
        if auth_results:
            if not auth_results.get('spf', {}).get('record'):
                risk_factors.append("Missing SPF record")
                risk_score += 15
            if not auth_results.get('dkim', {}).get('record'):
                risk_factors.append("Missing DKIM record")
                risk_score += 15
            if not auth_results.get('dmarc', {}).get('record'):
                risk_factors.append("Missing DMARC record")
                risk_score += 15
        
        # Check for suspicious patterns
        pattern_matches = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, content.lower()):
                pattern_matches.append(pattern)
                risk_score += 10
        
        if pattern_matches:
            risk_factors.append(f"Suspicious patterns found: {', '.join(pattern_matches)}")
        
        # Check URLs
        if urls:
            malicious_urls = [url for url in urls if url.get("is_malicious")]
            if malicious_urls:
                risk_factors.append(f"Found {len(malicious_urls)} malicious URLs")
                risk_score += 30 * len(malicious_urls)
        
        # Check attachments
        if attachments:
            malicious_attachments = [att for att in attachments if att.get("is_malicious")]
            if malicious_attachments:
                risk_factors.append(f"Found {len(malicious_attachments)} suspicious attachments")
                risk_score += 40 * len(malicious_attachments)
        
        # Determine verdict
        verdict = EmailVerdict.SAFE
        if risk_score >= 60:
            verdict = EmailVerdict.MALICIOUS
        elif risk_score >= 30:
            verdict = EmailVerdict.SUSPICIOUS
        
        # Generate recommendations
        recommendations = []
        if verdict != EmailVerdict.SAFE:
            recommendations.append("Do not click on any links in this email")
            recommendations.append("Do not download or open any attachments")
            recommendations.append("Do not reply to this email")
            if verdict == EmailVerdict.MALICIOUS:
                recommendations.append("Report this email to your IT security team")
                recommendations.append("Delete this email immediately")
        
        return EmailAnalysisResult(
            verdict=verdict.value,
            risk_score=min(100, risk_score),
            reason="; ".join(risk_factors) if risk_factors else "No suspicious indicators found",
            artifacts=artifacts,
            recommendations=recommendations
        )

    def extract_artifacts(self, email_content: str) -> EmailArtifact:
        """Extract important artifacts from email content"""
        msg = email.message_from_string(email_content, policy=policy.default)
        
        # Extract basic info
        sender = msg.get('from', '')
        subject = msg.get('subject', '')
        
        # Extract IPs and URLs
        body = self._get_email_body(msg)
        ips = self._extract_ips(body)
        urls = self._extract_urls(body)
        
        # Get attachments
        attachments = []
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                attachments.append(part.get_filename())
        
        return EmailArtifact(
            sender=sender,
            subject=subject,
            ips=ips,
            urls=urls,
            attachments=attachments
        )

    def _get_email_body(self, msg) -> str:
        """Extract email body content"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_content()
                elif part.get_content_type() == "text/html":
                    soup = BeautifulSoup(part.get_content(), 'html.parser')
                    body += soup.get_text()
        else:
            body = msg.get_content()
        return body

    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, text)

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)

# Flask app for the web interface
app = Flask(__name__)
analyzer = PhishingAnalyzer()

# HTML Template for the frontend
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Phishing Analyzer</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 30px;
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
        }
        textarea, input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            font-family: inherit;
        }
        textarea {
            min-height: 200px;
        }
        button {
            background-color: #2980b9;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            display: block;
            margin: 20px auto;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #3498db;
        }
        .result {
            margin-top: 30px;
            padding: 20px;
            border-radius: 8px;
            display: none;
        }
        .safe {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
        }
        .suspicious {
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
        }
        .malicious {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
        }
        .verdict {
            font-size: 24px;
            text-align: center;
            margin-bottom: 20px;
            font-weight: bold;
        }
        .risk-meter {
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            margin: 20px 0;
            overflow: hidden;
        }
        .risk-value {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #ffc107, #dc3545);
            border-radius: 10px;
            transition: width 0.5s;
        }
        .section {
            margin-top: 20px;
        }
        .section h3 {
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            color: #2c3e50;
        }
        ul {
            padding-left: 20px;
        }
        li {
            margin-bottom: 8px;
        }
        .artifact-item {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        #loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-left: 4px solid #3498db;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Email Phishing Analyzer</h1>
        
        <div class="form-group">
            <label for="sender">Sender Email:</label>
            <input type="email" id="sender" name="sender" placeholder="example@domain.com">
        </div>
        
        <div class="form-group">
            <label for="subject">Email Subject:</label>
            <input type="text" id="subject" name="subject" placeholder="Email subject line">
        </div>
        
        <div class="form-group">
            <label for="content">Email Content (Full email with headers if possible):</label>
            <textarea id="content" name="content" placeholder="Paste the full email content here including headers..."></textarea>
        </div>
        
        <button id="analyzeBtn" onclick="analyzeEmail()">Analyze Email</button>
        
        <div id="loading">
            <div class="spinner"></div>
            <p>Analyzing email...</p>
        </div>
        
        <div id="results" class="result">
            <div class="verdict" id="verdict"></div>
            
            <div class="section">
                <h3>Risk Score</h3>
                <div class="risk-meter">
                    <div class="risk-value" id="riskValue"></div>
                </div>
                <div id="riskScore" style="text-align: center;"></div>
            </div>
            
            <div class="section">
                <h3>Analysis Reason</h3>
                <p id="reason"></p>
            </div>
            
            <div class="section">
                <h3>Recommendations</h3>
                <ul id="recommendations"></ul>
            </div>
            
            <div class="section">
                <h3>Email Artifacts</h3>
                
                <div class="artifact-item">
                    <strong>Sender:</strong> <span id="senderInfo"></span>
                </div>
                
                <div class="artifact-item">
                    <strong>Subject:</strong> <span id="subjectInfo"></span>
                </div>
                
                <div class="artifact-item">
                    <strong>URLs Found:</strong>
                    <ul id="urlsList"></ul>
                </div>
                
                <div class="artifact-item">
                    <strong>IP Addresses Found:</strong>
                    <ul id="ipsList"></ul>
                </div>
                
                <div class="artifact-item">
                    <strong>Attachments:</strong>
                    <ul id="attachmentsList"></ul>
                </div>
            </div>
        </div>
    </div>

    <script>
        function analyzeEmail() {
            // Show loading spinner
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            
            // Get form values
            const sender = document.getElementById('sender').value;
            const subject = document.getElementById('subject').value;
            const content = document.getElementById('content').value;
            
            // Send data to backend
            fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    sender: sender,
                    subject: subject,
                    content: content
                }),
            })
            .then(response => response.json())
            .then(data => {
                // Hide loading spinner
                document.getElementById('loading').style.display = 'none';
                
                // Set verdict class
                const resultsDiv = document.getElementById('results');
                resultsDiv.className = 'result';
                resultsDiv.classList.add(data.verdict.toLowerCase());
                resultsDiv.style.display = 'block';
                
                // Display verdict
                document.getElementById('verdict').textContent = data.verdict;
                
                // Set risk score
                document.getElementById('riskScore').textContent = `${data.risk_score}/100`;
                document.getElementById('riskValue').style.width = `${data.risk_score}%`;
                
                // Set reason
                document.getElementById('reason').textContent = data.reason || 'No suspicious indicators found';
                
                // Set recommendations
                const recsElement = document.getElementById('recommendations');
                recsElement.innerHTML = '';
                if (data.recommendations && data.recommendations.length > 0) {
                    data.recommendations.forEach(rec => {
                        const li = document.createElement('li');
                        li.textContent = rec;
                        recsElement.appendChild(li);
                    });
                } else {
                    recsElement.innerHTML = '<li>No specific recommendations needed.</li>';
                }
                
                // Set artifacts
                document.getElementById('senderInfo').textContent = data.artifacts.sender || 'Unknown';
                document.getElementById('subjectInfo').textContent = data.artifacts.subject || 'Unknown';
                
                // URLs
                const urlsList = document.getElementById('urlsList');
                urlsList.innerHTML = '';
                if (data.artifacts.urls && data.artifacts.urls.length > 0) {
                    data.artifacts.urls.forEach(url => {
                        const li = document.createElement('li');
                        li.textContent = url;
                        urlsList.appendChild(li);
                    });
                } else {
                    urlsList.innerHTML = '<li>No URLs found</li>';
                }
                
                // IPs
                const ipsList = document.getElementById('ipsList');
                ipsList.innerHTML = '';
                if (data.artifacts.ips && data.artifacts.ips.length > 0) {
                    data.artifacts.ips.forEach(ip => {
                        const li = document.createElement('li');
                        li.textContent = ip;
                        ipsList.appendChild(li);
                    });
                } else {
                    ipsList.innerHTML = '<li>No IP addresses found</li>';
                }
                
                // Attachments
                const attachmentsList = document.getElementById('attachmentsList');
                attachmentsList.innerHTML = '';
                if (data.artifacts.attachments && data.artifacts.attachments.length > 0) {
                    data.artifacts.attachments.forEach(attachment => {
                        const li = document.createElement('li');
                        li.textContent = attachment;
                        attachmentsList.appendChild(li);
                    });
                } else {
                    attachmentsList.innerHTML = '<li>No attachments found</li>';
                }
            })
            .catch((error) => {
                console.error('Error:', error);
                document.getElementById('loading').style.display = 'none';
                alert('An error occurred while analyzing the email. Please try again.');
            });
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    content = data.get('content', '')
    sender = data.get('sender', '')
    subject = data.get('subject', '')
    
    # If sender or subject are not provided in the form, try to extract from content
    if content and (not sender or not subject):
        msg = email.message_from_string(content, policy=policy.default)
        if not sender:
            sender = msg.get('from', '')
        if not subject:
            subject = msg.get('subject', '')
    
    # Analyze the email
    result = analyzer.analyze_email(content, sender=sender, subject=subject)
    
    # Return the analysis result as JSON
    return jsonify({
        'verdict': result.verdict,
        'risk_score': result.risk_score,
        'reason': result.reason,
        'artifacts': result.artifacts,
        'recommendations': result.recommendations
    })

def open_browser():
    """Open browser after a short delay"""
    # Give the server time to start
    threading.Timer(1.5, lambda: webbrowser.open(f'http://127.0.0.1:{port}')).start()

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Find an available port
    port = 5000
    
    print("🔹 Starting Phishing Analyzer Web App")
    print(f"🔹 Opening web interface at http://127.0.0.1:{port}")
    
    # Open browser automatically
    open_browser()
    
    # Start the Flask app
    app.run(debug=False, port=port)