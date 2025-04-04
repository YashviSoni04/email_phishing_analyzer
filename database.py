from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Boolean, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from datetime import datetime
import os

DATABASE_URL = "sqlite:///./phishing_analysis.db"
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class EmailAnalysis(Base):
    __tablename__ = "email_analyses"
    
    id = Column(String, primary_key=True)
    email_hash = Column(String, unique=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    sender = Column(String)
    subject = Column(String)
    verdict = Column(String)  # MALICIOUS, SUSPICIOUS, SAFE
    risk_score = Column(Float)
    reason = Column(String)
    artifacts = Column(JSON)
    recommendations = Column(JSON)
    spf_result = Column(String)
    dkim_result = Column(String)
    dmarc_result = Column(String)
    urls_analysis = Column(JSON)
    attachments_analysis = Column(JSON)
    previous_threats = Column(JSON)
    
    # Relationships
    urls = relationship("URLAnalysis", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("AttachmentAnalysis", back_populates="email", cascade="all, delete-orphan")

class URLAnalysis(Base):
    __tablename__ = "url_analyses"
    
    id = Column(String, primary_key=True)
    email_analysis_id = Column(String, ForeignKey("email_analyses.id", ondelete="CASCADE"))
    url = Column(String)
    is_malicious = Column(Boolean, default=False)
    reputation_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    email = relationship("EmailAnalysis", back_populates="urls")

class AttachmentAnalysis(Base):
    __tablename__ = "attachment_analyses"
    
    id = Column(String, primary_key=True)
    email_analysis_id = Column(String, ForeignKey("email_analyses.id", ondelete="CASCADE"))
    filename = Column(String)
    is_malicious = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    email = relationship("EmailAnalysis", back_populates="attachments")

class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    
    id = Column(String, primary_key=True)
    indicator_type = Column(String)  # url, domain, ip, hash
    indicator_value = Column(String)
    is_malicious = Column(Boolean, default=False)
    confidence_score = Column(Float)
    last_seen = Column(DateTime)
    source = Column(String)
    details = Column(JSON)

class AnalyticsTrends(Base):
    __tablename__ = "analytics_trends"
    
    id = Column(String, primary_key=True)
    date = Column(DateTime)
    total_emails = Column(Integer)
    malicious_count = Column(Integer)
    suspicious_count = Column(Integer)
    top_senders = Column(JSON)
    top_domains = Column(JSON)
    threat_types = Column(JSON)

# Create tables
Base.metadata.create_all(engine)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
