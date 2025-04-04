from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Literal
from datetime import datetime, timedelta
import hashlib
import os
import re
import dns.resolver
import requests
import aiohttp
import json
from urllib.parse import urlparse, unquote
import magic
import base64
from bs4 import BeautifulSoup
from phishing_analyzer import PhishingAnalyzer
from database import (
    get_db, EmailAnalysis, URLAnalysis, 
    AttachmentAnalysis, ThreatIntelligence, AnalyticsTrends
)
from sqlalchemy.orm import Session
from sqlalchemy import func, case
import uuid
import logging
from email_providers import GmailProvider, OutlookProvider, EmailMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def calculate_email_hash(content: str, sender: Optional[str] = None, subject: Optional[str] = None) -> str:
    """Calculate a unique hash for an email based on its content and metadata"""
    hash_input = f"{content}|{sender or ''}|{subject or ''}"
    return hashlib.sha256(hash_input.encode()).hexdigest()

app = FastAPI(
    title="Enterprise Phishing Email Analyzer",
    description="Advanced email analysis for phishing detection",
    version="1.0.0"
)

# Initialize services
analyzer = PhishingAnalyzer()
gmail_provider = GmailProvider()
outlook_provider = OutlookProvider()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Load API keys from environment
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")

class EmailRequest(BaseModel):
    content: str
    sender: Optional[EmailStr] = None
    subject: Optional[str] = None
    received_date: Optional[str] = None
    headers: Optional[Dict] = None
    attachments: Optional[List[Dict[str, str]]] = None
    urls: Optional[List[str]] = None

class ProviderEmailRequest(BaseModel):
    provider: Literal["gmail", "outlook"]
    message_id: str

class AnalysisResponse(BaseModel):
    id: str
    timestamp: str
    verdict: str
    risk_score: float
    reason: str
    artifacts: dict
    recommendations: List[str]
    is_historical: bool = False
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    urls_analysis: Optional[List[Dict]] = None
    attachments_analysis: Optional[List[Dict]] = None
    previous_threats: Optional[List[Dict]] = None

async def check_url_reputation(url: str) -> dict:
    """Check URL reputation using multiple services"""
    results = {
        "virustotal": None, 
        "phishtank": None,
        "is_malicious": False,
        "risk_factors": []
    }
    
    try:
        # Check for URL obfuscation
        decoded_url = unquote(url)
        if decoded_url != url:
            results["risk_factors"].append("URL is encoded/obfuscated")
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.top', '.xyz', '.zip', '.review', '.country', '.kim', '.cricket']
        domain = urlparse(decoded_url).netloc
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            results["risk_factors"].append(f"Suspicious TLD: {domain.split('.')[-1]}")
        
        # Check URL length (unusually long URLs are suspicious)
        if len(decoded_url) > 100:
            results["risk_factors"].append("Unusually long URL")
        
        # Check for IP addresses in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', decoded_url):
            results["risk_factors"].append("Contains IP address")
        
        # Check VirusTotal
        if VIRUSTOTAL_API_KEY:
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                url_id = base64.urlsafe_b64encode(decoded_url.encode()).decode().strip("=")
                async with session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        results["virustotal"] = data
                        if data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
                            results["is_malicious"] = True
                            results["risk_factors"].append(f"VirusTotal: {data['data']['attributes']['last_analysis_stats']['malicious']} vendors flagged as malicious")
        
        # Check PhishTank
        if PHISHTANK_API_KEY:
            async with aiohttp.ClientSession() as session:
                headers = {"Api-Key": PHISHTANK_API_KEY}
                data = {"url": decoded_url}
                async with session.post("https://checkurl.phishtank.com/checkurl/", headers=headers, data=data) as response:
                    if response.status == 200:
                        data = await response.json()
                        results["phishtank"] = data
                        if data.get("in_database", False) and data.get("verified", False):
                            results["is_malicious"] = True
                            results["risk_factors"].append("URL found in PhishTank database")
    
    except Exception as e:
        results["error"] = str(e)
    
    return results

def extract_urls_from_content(content: str) -> List[str]:
    """Extract URLs from email content, including obfuscated ones in HTML"""
    urls = set()
    
    # Extract plain URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls.update(re.findall(url_pattern, content))
    
    try:
        # Parse HTML content
        soup = BeautifulSoup(content, 'html.parser')
        
        # Find all links
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.startswith(('http://', 'https://')):
                urls.add(href)
        
        # Find potential obfuscated URLs in onclick attributes
        for elem in soup.find_all(attrs={'onclick': True}):
            onclick = elem['onclick']
            if 'window.location' in onclick or 'href' in onclick:
                potential_urls = re.findall(url_pattern, onclick)
                urls.update(potential_urls)
        
        # Find data-url attributes
        for elem in soup.find_all(attrs={'data-url': True}):
            data_url = elem['data-url']
            if data_url.startswith(('http://', 'https://')):
                urls.add(data_url)
    
    except Exception:
        pass
    
    return list(urls)

async def check_email_authentication(sender_domain: str) -> dict:
    """Check SPF, DKIM, and DMARC records with detailed explanations"""
    results = {
        "spf": {"status": None, "record": None, "details": None},
        "dkim": {"status": None, "record": None, "details": None},
        "dmarc": {"status": None, "record": None, "details": None}
    }
    
    try:
        # Check SPF
        try:
            spf_records = dns.resolver.resolve(sender_domain, 'TXT')
            for record in spf_records:
                record_text = str(record)
                if 'v=spf1' in record_text:
                    results["spf"]["status"] = "available"
                    results["spf"]["record"] = record_text
                    
                    # Analyze SPF record
                    if 'all' not in record_text:
                        results["spf"]["details"] = "WARNING: No 'all' mechanism found"
                    elif '-all' in record_text:
                        results["spf"]["details"] = "GOOD: Hard fail policy (-all)"
                    elif '~all' in record_text:
                        results["spf"]["details"] = "MEDIUM: Soft fail policy (~all)"
                    elif '?all' in record_text:
                        results["spf"]["details"] = "WEAK: Neutral policy (?all)"
                    elif '+all' in record_text:
                        results["spf"]["details"] = "DANGEROUS: Pass all policy (+all)"
                    break
            if not results["spf"]["status"]:
                results["spf"]["details"] = "No SPF record found"
        except Exception as e:
            results["spf"]["details"] = f"Error checking SPF: {str(e)}"
        
        # Check DKIM
        try:
            selectors = ['default', 'google', 'dkim', 'k1']  # Common selectors
            for selector in selectors:
                try:
                    dkim_domain = f"{selector}._domainkey.{sender_domain}"
                    dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
                    record_text = str(dkim_records[0])
                    if 'v=DKIM1' in record_text:
                        results["dkim"]["status"] = "available"
                        results["dkim"]["record"] = record_text
                        results["dkim"]["details"] = f"Found DKIM record with selector '{selector}'"
                        break
                except:
                    continue
            if not results["dkim"]["status"]:
                results["dkim"]["details"] = "No DKIM record found with common selectors"
        except Exception as e:
            results["dkim"]["details"] = f"Error checking DKIM: {str(e)}"
        
        # Check DMARC
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{sender_domain}", 'TXT')
            record_text = str(dmarc_records[0])
            if 'v=DMARC1' in record_text:
                results["dmarc"]["status"] = "available"
                results["dmarc"]["record"] = record_text
                
                # Analyze DMARC policy
                policy_match = re.search(r'p=(\w+)', record_text)
                if policy_match:
                    policy = policy_match.group(1)
                    if policy == 'reject':
                        results["dmarc"]["details"] = "GOOD: Reject policy"
                    elif policy == 'quarantine':
                        results["dmarc"]["details"] = "MEDIUM: Quarantine policy"
                    elif policy == 'none':
                        results["dmarc"]["details"] = "WEAK: Monitor-only policy"
                else:
                    results["dmarc"]["details"] = "No policy specified"
            else:
                results["dmarc"]["details"] = "No DMARC record found"
        except Exception as e:
            results["dmarc"]["details"] = f"Error checking DMARC: {str(e)}"
    
    except Exception as e:
        results["error"] = str(e)
    
    return results

async def analyze_attachment(attachment: dict) -> dict:
    """Analyze an attachment for potential threats"""
    try:
        filename = attachment.get("filename", "")
        content = base64.b64decode(attachment.get("content", ""))
        
        results = {
            "filename": filename,
            "size": len(content),
            "mime_type": magic.from_buffer(content, mime=True),
            "risk_factors": [],
            "is_malicious": False,
            "risk_score": 0
        }
        
        # Check file size
        if len(content) > 10 * 1024 * 1024:  # 10MB
            results["risk_factors"].append("Large file size")
            results["risk_score"] += 10
        
        # Check file extension
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.js', '.vbs', '.ps1', '.msi', '.jar']
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            results["risk_factors"].append("Dangerous file extension")
            results["risk_score"] += 50
        
        # Check for double extensions
        if filename.count('.') > 1:
            results["risk_factors"].append("Multiple file extensions")
            results["risk_score"] += 30
        
        # Calculate file hash
        file_hash = hashlib.sha256(content).hexdigest()
        results["file_hash"] = file_hash
        
        # Check VirusTotal if API key is available
        if VIRUSTOTAL_API_KEY:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        if stats.get("malicious", 0) > 0:
                            results["risk_factors"].append(f"VirusTotal: {stats['malicious']} vendors flagged as malicious")
                            results["risk_score"] += stats["malicious"] * 5
                            results["virustotal_results"] = data
        
        # Set malicious flag if risk score is high
        if results["risk_score"] >= 50:
            results["is_malicious"] = True
        
        return results
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_email(
    request: EmailRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    try:
        if not request.content:
            raise HTTPException(status_code=400, detail="Email content is required")
            
        # Calculate email hash
        email_hash = calculate_email_hash(request.content, request.sender, request.subject)
        
        # Check for existing analysis
        existing_analysis = (
            db.query(EmailAnalysis)
            .filter(EmailAnalysis.email_hash == email_hash)
            .first()
        )
        
        if existing_analysis:
            # Return cached analysis if it's recent (less than 1 hour old)
            if datetime.utcnow() - existing_analysis.timestamp < timedelta(hours=1):
                return {
                    "id": existing_analysis.id,
                    "timestamp": existing_analysis.timestamp.isoformat(),
                    "verdict": existing_analysis.verdict,
                    "risk_score": existing_analysis.risk_score,
                    "reason": existing_analysis.reason,
                    "artifacts": existing_analysis.artifacts,
                    "recommendations": existing_analysis.recommendations,
                    "is_historical": True,
                    "spf_result": existing_analysis.spf_result,
                    "dkim_result": existing_analysis.dkim_result,
                    "dmarc_result": existing_analysis.dmarc_result,
                    "urls_analysis": existing_analysis.urls_analysis,
                    "attachments_analysis": existing_analysis.attachments_analysis,
                    "previous_threats": existing_analysis.previous_threats
                }
        
        # Extract URLs from content
        urls = extract_urls_from_content(request.content)
        
        # Check URL reputation in parallel
        url_analysis = []
        for url in urls:
            try:
                url_info = await check_url_reputation(url)
                url_analysis.append(url_info)
            except Exception as e:
                logger.error(f"Error checking URL {url}: {str(e)}")
                url_analysis.append({
                    "url": url,
                    "is_malicious": False,
                    "reputation_score": 0,
                    "error": str(e)
                })
        
        # Check email authentication
        auth_results = {}
        if request.sender:
            try:
                sender_domain = request.sender.split('@')[1]
                auth_results = await check_email_authentication(sender_domain)
            except Exception as e:
                logger.error(f"Error checking email authentication: {str(e)}")
                auth_results = {
                    "spf": {"record": None, "result": "error", "details": str(e)},
                    "dkim": {"record": None, "result": "error", "details": str(e)},
                    "dmarc": {"record": None, "result": "error", "details": str(e)}
                }
        
        # Analyze attachments
        attachment_analysis = []
        if request.attachments:
            for attachment in request.attachments:
                try:
                    att_info = await analyze_attachment(attachment)
                    attachment_analysis.append(att_info)
                except Exception as e:
                    logger.error(f"Error analyzing attachment: {str(e)}")
                    attachment_analysis.append({
                        "filename": attachment.get("filename", "unknown"),
                        "is_malicious": False,
                        "error": str(e)
                    })
        
        # Analyze email content
        analysis_result = analyzer.analyze_email(
            content=request.content,
            sender=request.sender,
            subject=request.subject,
            urls=url_analysis,
            auth_results=auth_results,
            attachments=attachment_analysis
        )
        
        # Create new analysis record
        new_analysis = EmailAnalysis(
            id=str(uuid.uuid4()),
            email_hash=email_hash,
            timestamp=datetime.utcnow(),
            sender=request.sender,
            subject=request.subject,
            verdict=analysis_result.verdict,
            risk_score=analysis_result.risk_score,
            reason=analysis_result.reason,
            artifacts=analysis_result.artifacts,
            recommendations=analysis_result.recommendations,
            spf_result=auth_results.get("spf", {}).get("result"),
            dkim_result=auth_results.get("dkim", {}).get("result"),
            dmarc_result=auth_results.get("dmarc", {}).get("result"),
            urls_analysis=url_analysis,
            attachments_analysis=attachment_analysis
        )
        
        try:
            # Save email analysis
            db.add(new_analysis)
            
            # Save URL analysis records
            for url_info in url_analysis:
                url_record = URLAnalysis(
                    id=str(uuid.uuid4()),
                    email_analysis_id=new_analysis.id,
                    url=url_info["url"],
                    is_malicious=url_info.get("is_malicious", False),
                    reputation_score=url_info.get("reputation_score", 0),
                    timestamp=datetime.utcnow()
                )
                db.add(url_record)
            
            # Save attachment analysis records
            for att_info in attachment_analysis:
                att_record = AttachmentAnalysis(
                    id=str(uuid.uuid4()),
                    email_analysis_id=new_analysis.id,
                    filename=att_info.get("filename", "unknown"),
                    is_malicious=att_info.get("is_malicious", False),
                    timestamp=datetime.utcnow()
                )
                db.add(att_record)
            
            db.commit()
        except Exception as e:
            logger.error(f"Error saving analysis results: {str(e)}")
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail="Error saving analysis results"
            )
        
        # Update analytics in background
        try:
            background_tasks.add_task(update_analytics_trends, db)
        except Exception as e:
            logger.error(f"Error updating analytics: {str(e)}")
            # Don't fail the request if analytics update fails
        
        return {
            "id": new_analysis.id,
            "timestamp": new_analysis.timestamp.isoformat(),
            "verdict": new_analysis.verdict,
            "risk_score": new_analysis.risk_score,
            "reason": new_analysis.reason,
            "artifacts": new_analysis.artifacts,
            "recommendations": new_analysis.recommendations,
            "is_historical": False,
            "spf_result": new_analysis.spf_result,
            "dkim_result": new_analysis.dkim_result,
            "dmarc_result": new_analysis.dmarc_result,
            "urls_analysis": new_analysis.urls_analysis,
            "attachments_analysis": new_analysis.attachments_analysis,
            "previous_threats": []
        }
        
    except Exception as e:
        logger.error(f"Error in analyze_email endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@app.post("/api/analyze/provider", response_model=AnalysisResponse)
async def analyze_provider_email(
    request: ProviderEmailRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    try:
        if request.provider == "gmail":
            email_message = await gmail_provider.get_email(request.message_id)
        elif request.provider == "outlook":
            email_message = await outlook_provider.get_email(request.message_id)
        else:
            raise HTTPException(status_code=400, detail="Unsupported provider")
        
        # Convert email message to EmailRequest format
        email_request = EmailRequest(
            content=email_message.content,
            sender=email_message.sender,
            subject=email_message.subject,
            received_date=email_message.received_date,
            headers=email_message.headers,
            attachments=email_message.attachments,
            urls=email_message.urls
        )
        
        # Call analyze_email endpoint
        return await analyze_email(email_request, background_tasks, db)
        
    except Exception as e:
        logger.error(f"Error in analyze_provider_email endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

async def update_analytics_trends(db: Session):
    """Update analytics trends in the background"""
    now = datetime.utcnow()
    today = now.date()
    
    # Get today's statistics
    daily_stats = {
        "id": str(uuid.uuid4()),
        "date": today,
        "period": "daily",
        "total_emails": await db.execute(
            func.count(EmailAnalysis.id).select().where(
                EmailAnalysis.timestamp >= today
            )
        ),
        "malicious_count": await db.execute(
            func.count(EmailAnalysis.id).select().where(
                EmailAnalysis.timestamp >= today,
                EmailAnalysis.verdict == "MALICIOUS"
            )
        ),
        "suspicious_count": await db.execute(
            func.count(EmailAnalysis.id).select().where(
                EmailAnalysis.timestamp >= today,
                EmailAnalysis.verdict == "SUSPICIOUS"
            )
        ),
        "top_threats": {},  # TODO: Aggregate threat types
        "top_domains": {},  # TODO: Aggregate malicious domains
        "geo_distribution": {}  # TODO: Aggregate geolocation data
    }
    
    await db.execute(AnalyticsTrends.insert().values(**daily_stats))

@app.on_event("startup")
async def startup():
    """Initialize database connection and other startup tasks"""
    pass

@app.on_event("shutdown")
async def shutdown():
    """Close database connection and other cleanup tasks"""
    pass

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
async def get_statistics(db: Session = Depends(get_db)):
    try:
        # Get today's date range
        today = datetime.utcnow().date()
        today_start = datetime.combine(today, datetime.min.time())
        today_end = datetime.combine(today, datetime.max.time())

        # Get daily stats
        daily_stats = db.query(
            func.count(EmailAnalysis.id).label('total'),
            func.sum(case((EmailAnalysis.verdict == 'MALICIOUS', 1), else_=0)).label('malicious'),
            func.sum(case((EmailAnalysis.verdict == 'SUSPICIOUS', 1), else_=0)).label('suspicious')
        ).filter(
            EmailAnalysis.timestamp.between(today_start, today_end)
        ).first()

        return {
            "daily": {
                "total_emails": daily_stats.total or 0,
                "malicious_count": daily_stats.malicious or 0,
                "suspicious_count": daily_stats.suspicious or 0
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/recent-threats")
async def get_recent_threats(db: Session = Depends(get_db)):
    try:
        # Get threats from the last 24 hours
        cutoff = datetime.utcnow() - timedelta(days=1)
        threats = db.query(EmailAnalysis).filter(
            EmailAnalysis.verdict.in_(['MALICIOUS', 'SUSPICIOUS']),
            EmailAnalysis.timestamp >= cutoff
        ).order_by(
            EmailAnalysis.timestamp.desc()
        ).limit(10).all()

        return [
            {
                "id": threat.id,
                "timestamp": threat.timestamp.isoformat(),
                "sender": threat.sender,
                "subject": threat.subject,
                "verdict": threat.verdict,
                "risk_score": threat.risk_score
            }
            for threat in threats
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"message": f"An error occurred: {str(exc)}"}
    )

if __name__ == "__main__":
    url = "http://127.0.0.1:8000/"
    print(f"Server starting at {url} ...")

    # Delay to ensure the server is up before opening the browser
    import time
    time.sleep(1)

    # Open the default web browser
    import webbrowser
    webbrowser.open(url)

    # Run FastAPI app
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
