"""
Authentication utilities and middleware for JWT and API key authentication.
Implements enterprise-grade authentication decorators and token management.
"""

from functools import wraps
from flask import request, jsonify, g, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
import uuid

from ..models import User
from ..services.auth_service import AuthService
from ..utils.exceptions import AuthenticationError, AuthorizationError, TokenError


def jwt_required(optional=False):
    """
    JWT authentication decorator with optional mode.
    
    Args:
        optional: If True, authentication is optional
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request(optional=optional)
                
                if not optional or get_jwt_identity():
                    user_id = get_jwt_identity()
                    if user_id:
                        user = AuthService.get_user_by_id(int(user_id))
                        g.current_user = user
                        g.current_user_id = int(user_id)
                        
                        # Check if token is blacklisted
                        jti = get_jwt().get('jti')
                        if AuthService.is_token_blacklisted(jti):
                            raise TokenError("Token has been revoked")
                    else:
                        g.current_user = None
                        g.current_user_id = None
                else:
                    g.current_user = None
                    g.current_user_id = None
                
                return func(*args, **kwargs)
                
            except Exception as e:
                if optional and isinstance(e, (AuthenticationError, TokenError)):
                    g.current_user = None
                    g.current_user_id = None
                    return func(*args, **kwargs)
                
                current_app.logger.warning(f"JWT authentication failed: {e}")
                return jsonify({
                    'error': True,
                    'message': 'Authentication required',
                    'error_code': 'AUTHENTICATION_REQUIRED'
                }), 401
        
        return wrapper
    return decorator


def api_key_required():
    """API key authentication decorator for custom endpoints."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get API key from header or query parameter
            api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            
            if not api_key:
                current_app.logger.warning(f"API key auth failed: No API key provided for endpoint {request.endpoint}")
                return jsonify({
                    'error': True,
                    'message': 'API key required',
                    'error_code': 'API_KEY_REQUIRED'
                }), 401
            
            try:
                # Log the API key being used (first few characters only for security)
                current_app.logger.debug(f"API key auth attempt: {api_key[:8]}... for endpoint {request.endpoint}")
                
                user = AuthService.get_user_by_api_key(api_key)
                g.current_user = user
                g.current_user_id = user.id
                g.auth_method = 'api_key'
                
                current_app.logger.info(f"API key auth success: User {user.username} authenticated for endpoint {request.endpoint}")
                
                return func(*args, **kwargs)
                
            except Exception as e:
                current_app.logger.warning(f"API key authentication failed: {e} for endpoint {request.endpoint}")
                error_message = str(e) if hasattr(e, 'message') else 'Invalid API key'
                error_code = getattr(e, 'error_code', 'INVALID_API_KEY')
                status_code = getattr(e, 'status_code', 401)
                
                return jsonify({
                    'error': True,
                    'message': error_message,
                    'error_code': error_code
                }), status_code
        
        return wrapper
    return decorator


def admin_required():
    """Admin access decorator - requires valid JWT and admin privileges."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                if not user_id:
                    raise AuthenticationError("Authentication required")
                
                user = AuthService.get_user_by_id(int(user_id))
                
                if not user.is_admin:
                    raise AuthorizationError("Admin privileges required")
                
                g.current_user = user
                g.current_user_id = int(user_id)
                
                # Check if token is blacklisted
                jti = get_jwt().get('jti')
                if AuthService.is_token_blacklisted(jti):
                    raise TokenError("Token has been revoked")
                
                return func(*args, **kwargs)
                
            except Exception as e:
                current_app.logger.warning(f"Admin authentication failed: {e}")
                
                if isinstance(e, AuthenticationError):
                    status_code = 401
                    message = "Authentication required"
                    error_code = "AUTHENTICATION_REQUIRED"
                elif isinstance(e, AuthorizationError):
                    status_code = 403
                    message = "Admin privileges required"
                    error_code = "ADMIN_REQUIRED"
                else:
                    status_code = 401
                    message = "Authentication failed"
                    error_code = "AUTHENTICATION_FAILED"
                
                return jsonify({
                    'error': True,
                    'message': message,
                    'error_code': error_code
                }), status_code
        
        return wrapper
    return decorator


def verified_user_required():
    """Verified user decorator - requires valid JWT and verified status."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                if not user_id:
                    raise AuthenticationError("Authentication required")
                
                user = AuthService.get_user_by_id(int(user_id))
                
                if not user.is_verified:
                    raise AuthorizationError("Verified account required")
                
                g.current_user = user
                g.current_user_id = int(user_id)
                
                # Check if token is blacklisted
                jti = get_jwt().get('jti')
                if AuthService.is_token_blacklisted(jti):
                    raise TokenError("Token has been revoked")
                
                return func(*args, **kwargs)
                
            except Exception as e:
                current_app.logger.warning(f"Verified user authentication failed: {e}")
                
                if isinstance(e, AuthenticationError):
                    status_code = 401
                    message = "Authentication required"
                    error_code = "AUTHENTICATION_REQUIRED"
                elif isinstance(e, AuthorizationError):
                    status_code = 403
                    message = "Verified account required"
                    error_code = "VERIFICATION_REQUIRED"
                else:
                    status_code = 401
                    message = "Authentication failed"
                    error_code = "AUTHENTICATION_FAILED"
                
                return jsonify({
                    'error': True,
                    'message': message,
                    'error_code': error_code
                }), status_code
        
        return wrapper
    return decorator


def get_current_user():
    """Get current authenticated user from Flask global context."""
    return getattr(g, 'current_user', None)


def get_current_user_id():
    """Get current authenticated user ID from Flask global context."""
    return getattr(g, 'current_user_id', None)


def generate_request_id():
    """Generate unique request ID for tracking."""
    return str(uuid.uuid4())


def add_request_id():
    """Add unique request ID to Flask global context."""
    g.request_id = generate_request_id()


def get_request_id():
    """Get current request ID."""
    return getattr(g, 'request_id', None)


def extract_client_ip():
    """Extract client IP address from request headers."""
    # Check for forwarded IP first (common with load balancers/proxies)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(',')[0].strip()
    
    # Check for real IP header
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    
    # Fall back to remote address
    return request.remote_addr


def extract_user_agent():
    """Extract user agent from request headers."""
    return request.headers.get('User-Agent', '')


def extract_referer():
    """Extract referer from request headers."""
    return request.headers.get('Referer', '')


def is_bot_request():
    """Check if request is from a bot/crawler."""
    user_agent = extract_user_agent().lower()
    
    bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'parser',
        'googlebot', 'bingbot', 'facebookexternalhit',
        'twitterbot', 'linkedinbot', 'whatsapp', 'telegram'
    ]
    
    return any(indicator in user_agent for indicator in bot_indicators)


def validate_json_request():
    """Validate that request contains valid JSON."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'PATCH']:
                if not request.is_json:
                    return jsonify({
                        'error': True,
                        'message': 'Request must be JSON',
                        'error_code': 'INVALID_CONTENT_TYPE'
                    }), 400
                
                try:
                    # This will raise an exception if JSON is invalid
                    request.get_json(force=True)
                except Exception:
                    return jsonify({
                        'error': True,
                        'message': 'Invalid JSON format',
                        'error_code': 'INVALID_JSON'
                    }), 400
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_fields(*required_fields):
    """Validate that required fields are present in JSON request."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'PATCH']:
                data = request.get_json()
                
                if not data:
                    return jsonify({
                        'error': True,
                        'message': 'Request body is required',
                        'error_code': 'MISSING_REQUEST_BODY'
                    }), 400
                
                missing_fields = []
                for field in required_fields:
                    if field not in data or data[field] is None or str(data[field]).strip() == '':
                        missing_fields.append(field)
                
                if missing_fields:
                    return jsonify({
                        'error': True,
                        'message': f'Missing required fields: {", ".join(missing_fields)}',
                        'error_code': 'MISSING_REQUIRED_FIELDS',
                        'missing_fields': missing_fields
                    }), 400
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def dual_auth_required():
    """
    Dual authentication decorator that supports both JWT and API key authentication.
    Tries JWT first, then falls back to API key authentication.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Try JWT authentication first
            jwt_auth_success = False
            api_key_auth_success = False
            jwt_error = None
            api_key_error = None
            
            # Check for JWT token in Authorization header
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                try:
                    verify_jwt_in_request()
                    user_id = get_jwt_identity()
                    
                    if user_id:
                        user = AuthService.get_user_by_id(int(user_id))
                        
                        # Check if token is blacklisted
                        jti = get_jwt().get('jti')
                        if not AuthService.is_token_blacklisted(jti):
                            g.current_user = user
                            g.current_user_id = int(user_id)
                            g.auth_method = 'jwt'
                            jwt_auth_success = True
                        else:
                            jwt_error = "Token has been revoked"
                    else:
                        jwt_error = "Invalid token payload"
                
                except Exception as e:
                    jwt_error = str(e)
                    current_app.logger.debug(f"JWT authentication failed: {e}")
            
            # If JWT failed or not provided, try API key authentication
            if not jwt_auth_success:
                # Get API key from header or query parameter
                api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
                
                if api_key:
                    try:
                        user = AuthService.get_user_by_api_key(api_key)
                        # Ensure we found a user
                        if user:
                            g.current_user = user
                            g.current_user_id = user.id
                            g.auth_method = 'api_key'
                            api_key_auth_success = True
                            current_app.logger.debug(f"API key authentication successful for user: {user.username}")
                        else:
                            api_key_error = "Invalid API key - no user found"
                            current_app.logger.warning(f"API key authentication failed: no user found for key")
                    except Exception as e:
                        api_key_error = str(e)
                        current_app.logger.debug(f"API key authentication failed: {e}")
            
            # If both authentication methods failed
            if not jwt_auth_success and not api_key_auth_success:
                # Prepare detailed error response
                error_details = {}
                if auth_header.startswith('Bearer '):
                    error_details['jwt_error'] = jwt_error
                
                if api_key:
                    error_details['api_key_error'] = api_key_error
                
                if not auth_header.startswith('Bearer ') and not api_key:
                    error_details['missing_auth'] = "No authentication credentials provided"
                
                return jsonify({
                    'error': True,
                    'message': 'Authentication required. Provide either JWT token (Authorization: Bearer <token>) or API key (X-API-Key: <key>)',
                    'error_code': 'AUTHENTICATION_REQUIRED',
                    'details': error_details
                }), 401
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator
