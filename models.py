from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

Base = declarative_base()

class GPGKey(Base):
    """Model for storing GPG key metadata"""
    __tablename__ = 'gpg_keys'
    
    id = Column(Integer, primary_key=True)
    fingerprint = Column(String(40), unique=True, nullable=False, index=True)
    key_id = Column(String(16), nullable=False)
    user_id = Column(String(255), nullable=False)
    email = Column(String(255))
    name = Column(String(255))
    owner = Column(String(255), nullable=False)
    requester = Column(String(255), nullable=False)
    jira_ticket = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    notes = Column(Text)
    
    def __repr__(self):
        return f"<GPGKey(fingerprint='{self.fingerprint}', owner='{self.owner}')>"

class UsageLog(Base):
    """Model for logging GPG key usage"""
    __tablename__ = 'usage_logs'
    
    id = Column(Integer, primary_key=True)
    fingerprint = Column(String(40), nullable=False, index=True)
    operation = Column(String(50), nullable=False)  # encrypt, decrypt, sign, verify
    user = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    file_path = Column(String(500))
    recipient = Column(String(255))
    success = Column(Boolean, default=True)
    error_message = Column(Text)
    
    def __repr__(self):
        return f"<UsageLog(fingerprint='{self.fingerprint}', operation='{self.operation}', user='{self.user}')>"

# Database setup
def get_database_url():
    """Get database URL from environment or use default"""
    db_path = os.getenv('DATABASE_PATH', './gpg_tracker.db')
    return f"sqlite:///{db_path}"

def create_database():
    """Create database and tables"""
    engine = create_engine(get_database_url())
    Base.metadata.create_all(engine)
    return engine

def get_session():
    """Get database session"""
    engine = create_engine(get_database_url())
    Session = sessionmaker(bind=engine)
    return Session()
