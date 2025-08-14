"""
Authentication service for handling user registration, login, and JWT token management.
Implements enterprise-grade security practices with bcrypt hashing and JWT tokens.
"""

import bcrypt
from datetime import datetime, timezone
from flask import current_app
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, get_jwt
from sqlalchemy.exc import IntegrityError
import uuid
import validators
import re

from ..models import db, User, BlacklistedToken
from ..utils.exceptions import ValidationError, AuthenticationError, AuthorizationError


class AuthService:
    """Service class for authentication operations."""
    
    @staticmethod
    def validate_password(password):
        """Validate password strength according to security requirements."""
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        
        if not re.search(r"[A-Z]", password):
            raise ValidationError("Password must contain at least one uppercase letter")
        
        if not re.search(r"[a-z]", password):
            raise ValidationError("Password must contain at least one lowercase letter")
        
        if not re.search(r"\d", password):
            raise ValidationError("Password must contain at least one digit")
        
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValidationError("Password must contain at least one special character")
    
    @staticmethod
    def validate_username(username):
        """Validate username format and availability."""
        if not username or len(username.strip()) == 0:
            raise ValidationError("Username is required")
        
        username = username.strip().lower()
        
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long")
        
        if len(username) > 50:
            raise ValidationError("Username must be no more than 50 characters long")
        
        if not re.match(r"^[a-z0-9_-]+$", username):
            raise ValidationError("Username can only contain lowercase letters, numbers, hyphens, and underscores")
        
        # Check for reserved usernames
        reserved_usernames = ['api', 'admin', 'www', 'mail', 'ftp', 'localhost', 'root', 'support', 'help', 'about', 'contact', 's']
        if username in reserved_usernames:
            raise ValidationError("This username is reserved and cannot be used")
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            raise ValidationError("Username already exists")
        
        return username
    
    @staticmethod
    def validate_email(email):
        """Validate email format and availability."""
        if not email or len(email.strip()) == 0:
            raise ValidationError("Email is required")
        
        email = email.strip().lower()
        
        if not validators.email(email):
            raise ValidationError("Invalid email format")
        
        if len(email) > 255:
            raise ValidationError("Email address is too long")
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            raise ValidationError("Email already registered")
        
        return email
    
    @staticmethod
    def hash_password(password):
        """Hash password using bcrypt with configured salt rounds."""
        salt_rounds = current_app.config.get('BCRYPT_LOG_ROUNDS', 12)
        salt = bcrypt.gensalt(rounds=salt_rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password, hashed_password):
        """Verify password against bcrypt hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    @staticmethod
    def register_user(username, email, password):
        """Register a new user with validation and security checks."""
        try:
            # Validate input data
            username = AuthService.validate_username(username)
            email = AuthService.validate_email(email)
            AuthService.validate_password(password)
            
            # Hash password
            password_hash = AuthService.hash_password(password)
            
            # Create user
            user = User(
                username=username,
                email=email,
                password_hash=password_hash
            )
            
            db.session.add(user)
            db.session.commit()
            
            current_app.logger.info(f"New user registered: {username} ({email})")
            
            return user
            
        except IntegrityError as e:
            db.session.rollback()
            current_app.logger.error(f"Database integrity error during user registration: {e}")
            raise ValidationError("Username or email already exists")
        
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error during user registration: {e}")
            raise
    
    @staticmethod
    def authenticate_user(login, password):
        """Authenticate user with email/username and password."""
        if not login or not password:
            raise AuthenticationError("Email/username and password are required")
        
        login = login.strip().lower()
        
        # Find user by email or username
        user = User.query.filter(
            (User.email == login) | (User.username == login)
        ).first()
        
        if not user:
            current_app.logger.warning(f"Authentication attempt with invalid login: {login}")
            raise AuthenticationError("Invalid email/username or password")
        
        if not user.is_active:
            current_app.logger.warning(f"Authentication attempt for inactive user: {login}")
            raise AuthenticationError("Account is deactivated")
        
        if not AuthService.verify_password(password, user.password_hash):
            current_app.logger.warning(f"Authentication attempt with invalid password for user: {login}")
            raise AuthenticationError("Invalid email/username or password")
        
        current_app.logger.info(f"User authenticated successfully: {user.username}")
        return user
    
    @staticmethod
    def generate_tokens(user):
        """Generate access and refresh tokens for authenticated user."""
        # Additional claims for JWT token
        additional_claims = {
            'username': user.username,
            'is_verified': user.is_verified,
            'is_admin': user.is_admin
        }
        
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims=additional_claims
        )
        
        refresh_token = create_refresh_token(
            identity=str(user.id),
            additional_claims={'username': user.username}
        )
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
        }
    
    @staticmethod
    def refresh_access_token():
        """Generate new access token from refresh token."""
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if not user or not user.is_active:
            raise AuthenticationError("Invalid refresh token")
        
        # Additional claims for new access token
        additional_claims = {
            'username': user.username,
            'is_verified': user.is_verified,
            'is_admin': user.is_admin
        }
        
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims=additional_claims
        )
        
        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
        }
    
    @staticmethod
    def logout_user(jti, token_type='access'):
        """Logout user by blacklisting JWT token."""
        current_user_id = int(get_jwt_identity())
        claims = get_jwt()
        
        # Calculate token expiration
        expires_at = datetime.fromtimestamp(claims['exp'], tz=timezone.utc)
        
        # Add token to blacklist
        blacklisted_token = BlacklistedToken(
            jti=jti,
            token_type=token_type,
            user_id=current_user_id,
            expires_at=expires_at
        )
        
        db.session.add(blacklisted_token)
        db.session.commit()
        
        current_app.logger.info(f"User logged out: {current_user_id}")
    
    @staticmethod
    def is_token_blacklisted(jti):
        """Check if JWT token is blacklisted."""
        return BlacklistedToken.query.filter_by(jti=jti).first() is not None
    
    @staticmethod
    def get_user_by_id(user_id):
        """Get user by ID with safety checks."""
        user = User.query.get(user_id)
        if not user:
            raise AuthenticationError("User not found")
        
        if not user.is_active:
            raise AuthenticationError("User account is deactivated")
        
        return user
    
    @staticmethod
    def get_user_by_api_key(api_key):
        """Get user by API key for custom endpoint authentication."""
        if not api_key:
            raise AuthenticationError("API key is required")
        
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            raise AuthenticationError("Invalid API key")
        
        if not user.is_active:
            raise AuthenticationError("User account is deactivated")
        
        if not user.is_verified:
            raise AuthorizationError("Custom endpoints are only available for verified users")
        
        return user
    
    @staticmethod
    def update_user_profile(user_id, **kwargs):
        """Update user profile with validation."""
        user = AuthService.get_user_by_id(user_id)
        
        # Validate and update email if provided
        if 'email' in kwargs:
            new_email = kwargs['email']
            if new_email != user.email:
                new_email = AuthService.validate_email(new_email)
                user.email = new_email
        
        # Update other allowed fields
        allowed_fields = ['title', 'description']
        for field in allowed_fields:
            if field in kwargs:
                setattr(user, field, kwargs[field])
        
        user.updated_at = datetime.now(timezone.utc)
        
        try:
            db.session.commit()
            current_app.logger.info(f"User profile updated: {user.username}")
            return user
        
        except IntegrityError:
            db.session.rollback()
            raise ValidationError("Email already registered")
    
    @staticmethod
    def change_password(user_id, current_password, new_password):
        """Change user password with current password verification."""
        user = AuthService.get_user_by_id(user_id)
        
        # Verify current password
        if not AuthService.verify_password(current_password, user.password_hash):
            raise AuthenticationError("Current password is incorrect")
        
        # Validate new password
        AuthService.validate_password(new_password)
        
        # Hash and update password
        user.password_hash = AuthService.hash_password(new_password)
        user.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        current_app.logger.info(f"Password changed for user: {user.username}")
    
    @staticmethod
    def regenerate_api_key(user_id):
        """Regenerate API key for user."""
        user = AuthService.get_user_by_id(user_id)
        
        if not user.is_verified:
            raise AuthorizationError("API key regeneration is only available for verified users")
        
        user.generate_api_key()
        user.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        current_app.logger.info(f"API key regenerated for user: {user.username}")
        return user.api_key
