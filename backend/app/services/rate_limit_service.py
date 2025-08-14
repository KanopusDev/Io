"""
Rate limiting service for API endpoints and user request tracking.
Implements enterprise-grade rate limiting with multiple strategies and user quotas.
"""

import time
from datetime import datetime, timezone, timedelta
from flask import current_app, request, g
from functools import wraps
import fakeredis

from ..models import db, User, RateLimit
from ..utils.exceptions import RateLimitExceededError, QuotaExceededError


class RateLimitService:
    """Service class for rate limiting operations."""
    
    def __init__(self):
        self.redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    
    @staticmethod
    def check_monthly_quota(user_id):
        """Check if user has exceeded their monthly quota."""
        user = User.query.get(user_id)
        if not user:
            return False
        
        # Check if we need to reset the monthly counter
        now = datetime.now(timezone.utc)
        last_reset = user.last_request_reset.replace(tzinfo=timezone.utc)
        
        # Reset monthly counter if it's been more than 30 days
        if (now - last_reset).days >= 30:
            user.reset_monthly_requests()
            db.session.commit()
        
        # Check if user can make more requests
        if not user.can_make_request():
            raise QuotaExceededError(
                f"Monthly quota exceeded. Limit: {user.monthly_limit}, Used: {user.monthly_requests}",
                quota_type='monthly',
                limit=user.monthly_limit,
                current=user.monthly_requests
            )
        
        return True
    
    @staticmethod
    def increment_monthly_usage(user_id):
        """Increment user's monthly request counter."""
        user = User.query.get(user_id)
        if user:
            user.increment_monthly_requests()
            db.session.commit()
    
    def check_rate_limit(self, user_id, endpoint, limit, window):
        """Check rate limit for user and endpoint using sliding window."""
        key = f"rate_limit:{user_id}:{endpoint}"
        current_time = time.time()
        window_start = current_time - window
        
        # Remove old entries
        self.redis_client.zremrangebyscore(key, 0, window_start)
        
        # Count current requests in window
        current_requests = self.redis_client.zcard(key)
        
        if current_requests >= limit:
            # Get the oldest request time in current window
            oldest_request = self.redis_client.zrange(key, 0, 0, withscores=True)
            if oldest_request:
                retry_after = int(oldest_request[0][1] + window - current_time)
            else:
                retry_after = int(window)
            
            raise RateLimitExceededError(
                f"Rate limit exceeded for {endpoint}. Limit: {limit} requests per {window} seconds",
                retry_after=retry_after
            )
        
        # Add current request
        self.redis_client.zadd(key, {str(current_time): current_time})
        self.redis_client.expire(key, int(window))
        
        return True
    
    def check_ip_rate_limit(self, ip_address, endpoint, limit=100, window=3600):
        """Check rate limit for IP address."""
        key = f"ip_rate_limit:{ip_address}:{endpoint}"
        current_time = time.time()
        window_start = current_time - window
        
        # Remove old entries
        self.redis_client.zremrangebyscore(key, 0, window_start)
        
        # Count current requests in window
        current_requests = self.redis_client.zcard(key)
        
        if current_requests >= limit:
            oldest_request = self.redis_client.zrange(key, 0, 0, withscores=True)
            if oldest_request:
                retry_after = int(oldest_request[0][1] + window - current_time)
            else:
                retry_after = int(window)
            
            raise RateLimitExceededError(
                f"IP rate limit exceeded. Limit: {limit} requests per {window} seconds",
                retry_after=retry_after
            )
        
        # Add current request
        self.redis_client.zadd(key, {str(current_time): current_time})
        self.redis_client.expire(key, int(window))
        
        return True
    
    def get_rate_limit_status(self, user_id, endpoint, limit, window):
        """Get current rate limit status for user and endpoint."""
        key = f"rate_limit:{user_id}:{endpoint}"
        current_time = time.time()
        window_start = current_time - window
        
        # Remove old entries
        self.redis_client.zremrangebyscore(key, 0, window_start)
        
        # Count current requests
        current_requests = self.redis_client.zcard(key)
        remaining = max(0, limit - current_requests)
        
        # Get reset time (when oldest request expires)
        oldest_request = self.redis_client.zrange(key, 0, 0, withscores=True)
        if oldest_request:
            reset_time = int(oldest_request[0][1] + window)
        else:
            reset_time = int(current_time + window)
        
        return {
            'limit': limit,
            'remaining': remaining,
            'reset': reset_time,
            'window': window
        }


# Global rate limit service instance
rate_limit_service = RateLimitService()


def rate_limit(limit=60, window=3600, per_user=True, per_ip=True):
    """
    Decorator for rate limiting endpoints.
    
    Args:
        limit: Maximum number of requests
        window: Time window in seconds
        per_user: Apply rate limit per user
        per_ip: Apply rate limit per IP address
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoint = f"{request.endpoint or func.__name__}"
            
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip and ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Check IP rate limit if enabled
            if per_ip:
                ip_limit = limit * 2  # Allow more requests per IP
                rate_limit_service.check_ip_rate_limit(client_ip, endpoint, ip_limit, window)
            
            # Check user rate limit if enabled and user is authenticated
            if per_user and hasattr(g, 'current_user') and g.current_user:
                user_id = g.current_user.id
                
                # Check monthly quota first
                RateLimitService.check_monthly_quota(user_id)
                
                # Check endpoint rate limit
                rate_limit_service.check_rate_limit(user_id, endpoint, limit, window)
                
                # Get rate limit status for headers
                status = rate_limit_service.get_rate_limit_status(user_id, endpoint, limit, window)
                
                # Add rate limit headers to response
                response = func(*args, **kwargs)
                if hasattr(response, 'headers'):
                    response.headers['X-RateLimit-Limit'] = str(status['limit'])
                    response.headers['X-RateLimit-Remaining'] = str(status['remaining'])
                    response.headers['X-RateLimit-Reset'] = str(status['reset'])
                
                # Increment monthly usage
                RateLimitService.increment_monthly_usage(user_id)
                
                return response
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def api_key_rate_limit(limit=1000, window=3600):
    """
    Rate limit decorator specifically for API key endpoints.
    Higher limits for verified users with API keys.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoint = f"api_key:{request.endpoint or func.__name__}"
            
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip and ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Check IP rate limit
            rate_limit_service.check_ip_rate_limit(client_ip, endpoint, limit, window)
            
            # Check user rate limit if user is available
            if hasattr(g, 'current_user') and g.current_user:
                user_id = g.current_user.id
                
                # Check monthly quota
                RateLimitService.check_monthly_quota(user_id)
                
                # Higher limits for verified users
                user_limit = limit if g.current_user.is_verified else limit // 2
                
                # Check endpoint rate limit
                rate_limit_service.check_rate_limit(user_id, endpoint, user_limit, window)
                
                # Increment monthly usage
                RateLimitService.increment_monthly_usage(user_id)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def admin_rate_limit(limit=200, window=3600):
    """Rate limit decorator for admin endpoints."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoint = f"admin:{request.endpoint or func.__name__}"
            
            if hasattr(g, 'current_user') and g.current_user and g.current_user.is_admin:
                user_id = g.current_user.id
                rate_limit_service.check_rate_limit(user_id, endpoint, limit, window)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def public_rate_limit(limit=10, window=60):
    """Rate limit decorator for public endpoints (no authentication required)."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoint = f"public:{request.endpoint or func.__name__}"
            
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip and ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Apply stricter rate limits for public endpoints
            rate_limit_service.check_ip_rate_limit(client_ip, endpoint, limit, window)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def ip_rate_limit(limit=10, window=300):
    """
    IP-based rate limiting decorator for temporary/demo endpoints.
    Used for endpoints that don't require authentication.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoint = f"ip_limit:{request.endpoint or func.__name__}"
            
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip and ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Apply IP-based rate limiting
            rate_limit_service.check_ip_rate_limit(client_ip, endpoint, limit, window)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator
