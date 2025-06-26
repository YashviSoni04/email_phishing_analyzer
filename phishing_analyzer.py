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
from flask import Flask, request, jsonify
from flask_cors import CORS

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
CORS(app)  
analyzer = PhishingAnalyzer()



@app.route('/')
def index():
    """API status endpoint"""
    return jsonify({
        'message': 'Phishing Analyzer API',
        'status': 'running',
        'version': '1.0',
        'endpoints': {
            'analyze': '/api/analyze (POST)',
            'health': '/api/health (GET)'
        }
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'running', 'service': 'python-analyzer'})

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        content = data.get('content', '')
        sender = data.get('sender_email', data.get('sender', ''))
        subject = data.get('subject', '')
        
        # If sender or subject are not provided, try to extract from content
        if content and (not sender or not subject):
            msg = email.message_from_string(content, policy=policy.default)
            if not sender:
                sender = msg.get('from', '')
            if not subject:
                subject = msg.get('subject', '')
        
        # Analyze the email using your existing logic
        result = analyzer.analyze_email(content, sender=sender, subject=subject)
        
        # Return the analysis result as JSON
        return jsonify({
            'verdict': result.verdict,
            'risk_score': result.risk_score,
            'confidence': result.risk_score,  # For Node.js compatibility
            'reason': result.reason,
            'reasons': [result.reason] if result.reason else [],  # For Node.js compatibility
            'artifacts': result.artifacts,
            'recommendations': result.recommendations,
            'details': {
                'sender_analysis': {'sender': sender},
                'content_analysis': {'analyzed': True},
                'link_analysis': result.artifacts
            }
        })
    
    except Exception as e:
        logging.error(f"Analysis error: {str(e)}")
        return jsonify({'error': 'Analysis failed', 'details': str(e)}), 500

# Update your main section:
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Use port 5001 (different from Node.js)
    port = 5001
    
    print("🔹 Starting Phishing Analyzer API Server")
    print(f"🔹 API available at http://127.0.0.1:{port}")
    print(f"🔹 Endpoints:")
    print(f"   GET  / - API status")
    print(f"   GET  /api/health - Health check")
    print(f"   POST /api/analyze - Analyze email")
    
    # Start the Flask app (API mode)
    app.run(debug=True, port=port, host='127.0.0.1')

