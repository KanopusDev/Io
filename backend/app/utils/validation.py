"""
Validation schemas for API requests and responses using Marshmallow.
Implements enterprise-grade input validation and serialization.
"""

from marshmallow import Schema, fields, validate, validates, validates_schema, ValidationError
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from datetime import datetime, timezone
import validators
import re

from ..models import User, URL, Analytics, AdminAction


class UserRegistrationSchema(Schema):
    """Schema for user registration validation."""
    
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=50),
            validate.Regexp(
                r'^[a-zA-Z0-9_-]+$',
                error='Username can only contain letters, numbers, hyphens, and underscores'
            )
        ]
    )
    email = fields.Email(required=True, validate=validate.Length(max=255))
    password = fields.Str(required=True, validate=validate.Length(min=8, max=128))
    
    @validates('username')
    def validate_username(self, value):
        """Validate username format and reserved names."""
        value = value.lower().strip()
        
        # Check for reserved usernames
        reserved_usernames = [
            'api', 'admin', 'www', 'mail', 'ftp', 'localhost', 'root',
            'support', 'help', 'about', 'contact', 's', 'dashboard',
            'analytics', 'docs', 'blog', 'news', 'status'
        ]
        
        if value in reserved_usernames:
            raise ValidationError('This username is reserved and cannot be used')
    
    @validates('password')
    def validate_password(self, value):
        """Validate password strength."""
        if len(value) < 8:
            raise ValidationError('Password must be at least 8 characters long')
        
        if not re.search(r'[A-Z]', value):
            raise ValidationError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', value):
            raise ValidationError('Password must contain at least one lowercase letter')
        
        if not re.search(r'\d', value):
            raise ValidationError('Password must contain at least one digit')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValidationError('Password must contain at least one special character')


class UserLoginSchema(Schema):
    """Schema for user login validation."""
    
    login = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    password = fields.Str(required=True, validate=validate.Length(min=1, max=128))


class UserProfileUpdateSchema(Schema):
    """Schema for user profile update validation."""
    
    email = fields.Email(validate=validate.Length(max=255))
    
    @validates('email')
    def validate_email_change(self, value):
        """Additional validation for email changes."""
        if value:
            # Email format is already validated by fields.Email
            pass


class ChangePasswordSchema(Schema):
    """Schema for password change validation."""
    
    current_password = fields.Str(required=True)
    new_password = fields.Str(required=True, validate=validate.Length(min=8, max=128))
    
    @validates('new_password')
    def validate_new_password(self, value):
        """Validate new password strength."""
        if len(value) < 8:
            raise ValidationError('Password must be at least 8 characters long')
        
        if not re.search(r'[A-Z]', value):
            raise ValidationError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', value):
            raise ValidationError('Password must contain at least one lowercase letter')
        
        if not re.search(r'\d', value):
            raise ValidationError('Password must contain at least one digit')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValidationError('Password must contain at least one special character')


class URLCreationSchema(Schema):
    """Schema for URL creation validation."""
    
    original_url = fields.Str(required=True, validate=validate.Length(min=1, max=2048))
    custom_alias = fields.Str(validate=validate.Length(min=3, max=50), allow_none=True)
    title = fields.Str(validate=validate.Length(max=255), allow_none=True)
    description = fields.Str(validate=validate.Length(max=1000), allow_none=True)
    expires_at = fields.DateTime(allow_none=True)
    
    @validates('original_url')
    def validate_url(self, value):
        """Validate URL format and security."""
        value = value.strip()
        
        if not validators.url(value):
            raise ValidationError('Invalid URL format')
        
        # Parse URL for additional checks
        from urllib.parse import urlparse
        parsed = urlparse(value)
        
        # Check scheme
        if parsed.scheme.lower() not in ['http', 'https']:
            raise ValidationError('Only HTTP and HTTPS URLs are allowed')
        
        # Check for blocked domains (basic check)
        blocked_domains = ['malware.com', 'virus.com', 'spam.com', 'phishing.com']
        if parsed.netloc.lower() in blocked_domains:
            raise ValidationError('This domain is blocked')
        
        # Check for localhost/private IPs
        if parsed.netloc.lower() in ['localhost', '127.0.0.1', '0.0.0.0']:
            raise ValidationError('Localhost URLs are not allowed')
    
    @validates('custom_alias')
    def validate_custom_alias(self, value):
        """Validate custom alias format."""
        if value:
            value = value.strip()
            
            if not re.match(r'^[a-zA-Z0-9_-]+$', value):
                raise ValidationError('Custom alias can only contain letters, numbers, hyphens, and underscores')
            
            # Check for reserved aliases
            reserved_aliases = [
                'api', 'admin', 'www', 'mail', 'ftp', 'localhost', 'root',
                'support', 'help', 'about', 'contact', 's', 'dashboard',
                'analytics', 'docs', 'blog', 'news', 'status'
            ]
            
            if value.lower() in reserved_aliases:
                raise ValidationError('This alias is reserved and cannot be used')
    
    @validates('expires_at')
    def validate_expiration(self, value):
        """Validate expiration date."""
        if value:
            if value <= datetime.now(timezone.utc):
                raise ValidationError('Expiration date must be in the future')


class URLUpdateSchema(Schema):
    """Schema for URL update validation."""
    
    original_url = fields.Str(validate=validate.Length(min=1, max=2048))
    custom_alias = fields.Str(validate=validate.Length(min=3, max=50), allow_none=True)
    title = fields.Str(validate=validate.Length(max=255), allow_none=True)
    description = fields.Str(validate=validate.Length(max=1000), allow_none=True)
    is_active = fields.Bool()
    expires_at = fields.DateTime(allow_none=True)
    
    @validates('original_url')
    def validate_url(self, value):
        """Validate URL format and security."""
        if value:
            value = value.strip()
            
            if not validators.url(value):
                raise ValidationError('Invalid URL format')
            
            from urllib.parse import urlparse
            parsed = urlparse(value)
            
            if parsed.scheme.lower() not in ['http', 'https']:
                raise ValidationError('Only HTTP and HTTPS URLs are allowed')
    
    @validates('custom_alias')
    def validate_custom_alias(self, value):
        """Validate custom alias format."""
        if value:
            value = value.strip()
            
            if not re.match(r'^[a-zA-Z0-9_-]+$', value):
                raise ValidationError('Custom alias can only contain letters, numbers, hyphens, and underscores')
    
    @validates('expires_at')
    def validate_expiration(self, value):
        """Validate expiration date."""
        if value:
            if value <= datetime.now(timezone.utc):
                raise ValidationError('Expiration date must be in the future')


class PaginationSchema(Schema):
    """Schema for pagination parameters."""
    
    page = fields.Int(validate=validate.Range(min=1), missing=1)
    per_page = fields.Int(validate=validate.Range(min=1, max=100), missing=20)


class AnalyticsQuerySchema(Schema):
    """Schema for analytics query parameters."""
    
    days = fields.Int(validate=validate.Range(min=1, max=365), missing=30)


class AdminUserActionSchema(Schema):
    """Schema for admin user actions."""
    
    action = fields.Str(
        required=True,
        validate=validate.OneOf(['verify', 'unverify', 'suspend', 'reactivate'])
    )


class AdminUserSearchSchema(Schema):
    """Schema for admin user search and filtering."""
    
    page = fields.Int(validate=validate.Range(min=1), missing=1)
    per_page = fields.Int(validate=validate.Range(min=1, max=100), missing=50)
    search = fields.Str(validate=validate.Length(max=255))
    status_filter = fields.Str(
        validate=validate.OneOf(['active', 'inactive', 'verified', 'unverified', 'admin'])
    )


class AdminURLSearchSchema(Schema):
    """Schema for admin URL search and filtering."""
    
    page = fields.Int(validate=validate.Range(min=1), missing=1)
    per_page = fields.Int(validate=validate.Range(min=1, max=100), missing=50)
    search = fields.Str(validate=validate.Length(max=255))
    status_filter = fields.Str(
        validate=validate.OneOf(['active', 'inactive', 'expired'])
    )


class AdminAnalyticsSchema(Schema):
    """Schema for admin analytics query."""
    
    days = fields.Int(validate=validate.Range(min=1, max=365), missing=30)


class AdminAuditLogSchema(Schema):
    """Schema for admin audit log query."""
    
    page = fields.Int(validate=validate.Range(min=1), missing=1)
    per_page = fields.Int(validate=validate.Range(min=1, max=100), missing=50)
    action_type = fields.Str(validate=validate.Length(max=50))
    admin_id = fields.Int(validate=validate.Range(min=1))


class AdminUserUpdateSchema(Schema):
    """Schema for admin user update validation."""
    
    is_verified = fields.Bool()
    is_suspended = fields.Bool()
    monthly_limit = fields.Int(validate=validate.Range(min=1, max=1000000))
    admin_note = fields.Str(validate=validate.Length(max=1000))


# Response schemas
class UserResponseSchema(SQLAlchemyAutoSchema):
    """Schema for user response serialization."""
    
    class Meta:
        model = User
        load_instance = True
        exclude = ['password_hash']
    
    monthly_limit = fields.Int(dump_only=True)
    requests_remaining = fields.Int(dump_only=True)


class URLResponseSchema(SQLAlchemyAutoSchema):
    """Schema for URL response serialization."""
    
    class Meta:
        model = URL
        load_instance = True
    
    short_url = fields.Str(dump_only=True)
    qr_url = fields.Str(dump_only=True)
    click_count = fields.Int(dump_only=True)
    is_expired = fields.Bool(dump_only=True)


class AnalyticsResponseSchema(SQLAlchemyAutoSchema):
    """Schema for analytics response serialization."""
    
    class Meta:
        model = Analytics
        load_instance = True


class AdminActionResponseSchema(SQLAlchemyAutoSchema):
    """Schema for admin action response serialization."""
    
    class Meta:
        model = AdminAction
        load_instance = True


class ErrorResponseSchema(Schema):
    """Schema for error response serialization."""
    
    error = fields.Bool(default=True)
    message = fields.Str(required=True)
    error_code = fields.Str()
    status_code = fields.Int()
    timestamp = fields.DateTime(default=datetime.now(timezone.utc))


class SuccessResponseSchema(Schema):
    """Schema for success response serialization."""
    
    success = fields.Bool(default=True)
    message = fields.Str()
    data = fields.Raw()
    timestamp = fields.DateTime(default=datetime.now(timezone.utc))


class TokenResponseSchema(Schema):
    """Schema for authentication token response."""
    
    access_token = fields.Str(required=True)
    refresh_token = fields.Str(required=True)
    token_type = fields.Str(default='Bearer')
    expires_in = fields.Int(required=True)
    user = fields.Nested(UserResponseSchema)


class PaginatedResponseSchema(Schema):
    """Schema for paginated response serialization."""
    
    items = fields.List(fields.Raw())
    page = fields.Int()
    per_page = fields.Int()
    total = fields.Int()
    pages = fields.Int()
    has_prev = fields.Bool()
    has_next = fields.Bool()
    prev_num = fields.Int(allow_none=True)
    next_num = fields.Int(allow_none=True)
