"""
Database models for the Io URL Shortener application.
Implements the complete database schema as specified in the architecture.
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, text
from sqlalchemy.ext.hybrid import hybrid_property
import uuid
import secrets
import string

db = SQLAlchemy()


class User(db.Model):
    """User model with complete authentication and verification system."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    api_key = db.Column(db.String(255), unique=True, nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), 
                          onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    monthly_requests = db.Column(db.Integer, default=0, nullable=False)
    last_request_reset = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    urls = db.relationship('URL', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    rate_limits = db.relationship('RateLimit', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    admin_actions = db.relationship('AdminAction', foreign_keys='AdminAction.admin_id', 
                                   backref='admin', lazy='dynamic', cascade='all, delete-orphan')
    target_actions = db.relationship('AdminAction', foreign_keys='AdminAction.target_user_id', 
                                    backref='target_user', lazy='dynamic')
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.api_key:
            self.generate_api_key()
    
    def generate_api_key(self):
        """Generate a secure API key for the user."""
        self.api_key = str(uuid.uuid4())
    
    @hybrid_property
    def monthly_limit(self):
        """Get the monthly request limit based on verification status."""
        from flask import current_app
        if self.is_verified:
            return current_app.config.get('VERIFIED_USER_MONTHLY_LIMIT', 999999999)
        return current_app.config.get('UNVERIFIED_USER_MONTHLY_LIMIT', 1000)
    
    @hybrid_property
    def requests_remaining(self):
        """Get the number of requests remaining for this month."""
        return max(0, self.monthly_limit - self.monthly_requests)
    
    def can_make_request(self):
        """Check if the user can make another API request."""
        return self.is_active and self.requests_remaining > 0
    
    def increment_monthly_requests(self):
        """Increment the monthly request counter."""
        self.monthly_requests += 1
        self.updated_at = datetime.now(timezone.utc)
    
    def reset_monthly_requests(self):
        """Reset the monthly request counter."""
        self.monthly_requests = 0
        self.last_request_reset = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary representation."""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_verified': self.is_verified,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'monthly_requests': self.monthly_requests,
            'monthly_limit': self.monthly_limit,
            'requests_remaining': self.requests_remaining
        }
        
        if include_sensitive:
            data['api_key'] = self.api_key
            data['last_request_reset'] = self.last_request_reset.isoformat()
        
        return data
    
    def __repr__(self):
        return f'<User {self.username}>'


class URL(db.Model):
    """URL model for shortened URLs with analytics tracking."""
    
    __tablename__ = 'urls'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    original_url = db.Column(db.Text, nullable=False)
    short_code = db.Column(db.String(10), unique=True, nullable=False, index=True)
    custom_alias = db.Column(db.String(50), unique=True, nullable=True, index=True)
    title = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), 
                          onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    analytics = db.relationship('Analytics', backref='url', lazy='dynamic', cascade='all, delete-orphan')
    admin_actions = db.relationship('AdminAction', backref='target_url', lazy='dynamic')
    
    def __init__(self, **kwargs):
        super(URL, self).__init__(**kwargs)
        if not self.short_code:
            self.generate_short_code()
    
    def generate_short_code(self, length=6):
        """Generate a unique short code for the URL."""
        characters = string.ascii_letters + string.digits
        while True:
            code = ''.join(secrets.choice(characters) for _ in range(length))
            if not URL.query.filter_by(short_code=code).first():
                self.short_code = code
                break
    
    @hybrid_property
    def short_url(self):
        """Get the full short URL."""
        from flask import current_app
        domain = current_app.config.get('SHORT_DOMAIN')
        if self.custom_alias:
            return f"https://{domain}/{self.custom_alias}"
        return f"https://{domain}/{self.short_code}"
    
    @hybrid_property
    def qr_url(self):
        """Get the QR code URL for this short URL."""
        from flask import current_app
        domain = current_app.config.get('SHORT_DOMAIN')
        code = self.custom_alias or self.short_code
        return f"https://{domain}/qr/{code}"
    
    @hybrid_property
    def click_count(self):
        """Get the total number of clicks for this URL."""
        return self.analytics.count()
    
    @hybrid_property
    def is_expired(self):
        """Check if the URL has expired."""
        if not self.expires_at:
            return False
        # Handle both timezone-aware and timezone-naive datetimes
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires
    
    def is_accessible(self):
        """Check if the URL is accessible (active and not expired)."""
        return self.is_active and not self.is_expired
    
    def to_dict(self, include_analytics=False):
        """Convert URL to dictionary representation."""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'original_url': self.original_url,
            'short_code': self.short_code,
            'custom_alias': self.custom_alias,
            'title': self.title,
            'description': self.description,
            'short_url': self.short_url,
            'is_active': self.is_active,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'click_count': self.click_count,
            'is_expired': self.is_expired
        }
        
        if include_analytics:
            data['analytics'] = [a.to_dict() for a in self.analytics.limit(100)]
        
        return data
    
    def __repr__(self):
        return f'<URL {self.short_code}: {self.original_url}>'


class Analytics(db.Model):
    """Analytics model for tracking URL click data."""
    
    __tablename__ = 'analytics'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False, index=True)
    user_agent = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    referer = db.Column(db.Text, nullable=True)
    country = db.Column(db.String(50), nullable=True, index=True)
    city = db.Column(db.String(100), nullable=True)
    device_type = db.Column(db.String(50), nullable=True, index=True)
    browser = db.Column(db.String(50), nullable=True, index=True)
    clicked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    def to_dict(self):
        """Convert analytics entry to dictionary representation."""
        return {
            'id': self.id,
            'url_id': self.url_id,
            'user_agent': self.user_agent,
            'ip_address': self.ip_address,
            'referer': self.referer,
            'country': self.country,
            'city': self.city,
            'device_type': self.device_type,
            'browser': self.browser,
            'clicked_at': self.clicked_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Analytics {self.id}: URL {self.url_id} at {self.clicked_at}>'


class RateLimit(db.Model):
    """Rate limiting model for tracking API usage."""
    
    __tablename__ = 'rate_limits'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    endpoint = db.Column(db.String(255), nullable=False, index=True)
    requests_count = db.Column(db.Integer, default=0, nullable=False)
    window_start = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    # Composite index for efficient rate limit queries
    __table_args__ = (
        Index('idx_rate_limit_user_endpoint', 'user_id', 'endpoint'),
        Index('idx_rate_limit_window', 'window_start'),
    )
    
    def to_dict(self):
        """Convert rate limit entry to dictionary representation."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'endpoint': self.endpoint,
            'requests_count': self.requests_count,
            'window_start': self.window_start.isoformat()
        }
    
    def __repr__(self):
        return f'<RateLimit {self.user_id}:{self.endpoint} - {self.requests_count}>'


class AdminAction(db.Model):
    """Admin action model for audit logging."""
    
    __tablename__ = 'admin_actions'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    action_type = db.Column(db.String(50), nullable=False, index=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    target_url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=True, index=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    def to_dict(self):
        """Convert admin action to dictionary representation."""
        return {
            'id': self.id,
            'admin_id': self.admin_id,
            'admin_username': self.admin.username if self.admin else None,
            'action_type': self.action_type,
            'target_user_id': self.target_user_id,
            'target_user_username': self.target_user.username if self.target_user else None,
            'target_url_id': self.target_url_id,
            'details': self.details,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<AdminAction {self.action_type} by {self.admin_id} at {self.created_at}>'


class BlacklistedToken(db.Model):
    """Blacklisted JWT tokens for logout functionality."""
    
    __tablename__ = 'blacklisted_tokens'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    jti = db.Column(db.String(36), nullable=False, unique=True, index=True)
    token_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    
    def to_dict(self):
        """Convert blacklisted token to dictionary representation."""
        return {
            'id': self.id,
            'jti': self.jti,
            'token_type': self.token_type,
            'user_id': self.user_id,
            'revoked_at': self.revoked_at.isoformat(),
            'expires_at': self.expires_at.isoformat()
        }
    
    def __repr__(self):
        return f'<BlacklistedToken {self.jti}>'
