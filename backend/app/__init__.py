"""
Flask application factory for the Io URL Shortener.
Implements enterprise-grade Flask application with proper configuration,
security, logging, and error handling.
"""

import os
import logging
from datetime import datetime, timezone
from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import structlog

from config import config
from .models import db, BlacklistedToken
from .utils.exceptions import IoError
from .utils.auth import add_request_id, extract_client_ip


def create_app(config_name=None):
    """
    Application factory function to create and configure Flask app.
    
    Args:
        config_name: Configuration environment name
    
    Returns:
        Flask application instance
    """
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.getenv('FLASK_ENV', 'development')
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    initialize_extensions(app)
    
    # Setup logging
    setup_logging(app)
    
    # Setup error handlers
    setup_error_handlers(app)
    
    # Setup request hooks
    setup_request_hooks(app)
    
    # Register blueprints
    register_blueprints(app)
    
    return app


def initialize_extensions(app):
    """Initialize Flask extensions."""
    
    # Database
    db.init_app(app)
    
    # JWT
    jwt = JWTManager(app)
    setup_jwt_handlers(jwt)
    
    # CORS
    CORS(app, origins=app.config['CORS_ORIGINS'])
    
    # Rate Limiting
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000 per hour"]
    )
    limiter.init_app(app)
    
    # Store limiter instance for use in routes
    app.limiter = limiter


def setup_jwt_handlers(jwt):
    """Setup JWT event handlers."""
    
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        """Check if JWT token is in blocklist."""
        jti = jwt_payload['jti']
        token = BlacklistedToken.query.filter_by(jti=jti).first()
        return token is not None
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        """Handle expired token."""
        return jsonify({
            'error': True,
            'message': 'Token has expired',
            'error_code': 'TOKEN_EXPIRED'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        """Handle invalid token."""
        return jsonify({
            'error': True,
            'message': 'Invalid token',
            'error_code': 'INVALID_TOKEN'
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        """Handle missing token."""
        return jsonify({
            'error': True,
            'message': 'Authentication token required',
            'error_code': 'TOKEN_REQUIRED'
        }), 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        """Handle revoked token."""
        return jsonify({
            'error': True,
            'message': 'Token has been revoked',
            'error_code': 'TOKEN_REVOKED'
        }), 401


def setup_logging(app):
    """Setup structured logging."""
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(app.config.get('LOG_FILE', 'logs/app.log'))
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Setup Flask logger
    handler = logging.FileHandler(app.config.get('LOG_FILE', 'logs/app.log'))
    handler.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
    
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s %(name)s: %(message)s'
    )
    handler.setFormatter(formatter)
    
    app.logger.addHandler(handler)
    app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))


def setup_error_handlers(app):
    """Setup global error handlers."""
    
    @app.errorhandler(IoError)
    def handle_io_error(error):
        """Handle custom IoError exceptions."""
        app.logger.error(f"IoError: {error.message}", extra={
            'error_code': error.error_code,
            'status_code': error.status_code,
            'request_id': getattr(g, 'request_id', None)
        })
        
        return jsonify(error.to_dict()), error.status_code
    
    @app.errorhandler(400)
    def handle_bad_request(error):
        """Handle 400 Bad Request errors."""
        return jsonify({
            'error': True,
            'message': 'Bad request',
            'error_code': 'BAD_REQUEST',
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def handle_unauthorized(error):
        """Handle 401 Unauthorized errors."""
        return jsonify({
            'error': True,
            'message': 'Unauthorized',
            'error_code': 'UNAUTHORIZED',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def handle_forbidden(error):
        """Handle 403 Forbidden errors."""
        return jsonify({
            'error': True,
            'message': 'Forbidden',
            'error_code': 'FORBIDDEN',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 Not Found errors."""
        return jsonify({
            'error': True,
            'message': 'Resource not found',
            'error_code': 'NOT_FOUND',
            'status_code': 404
        }), 404
    
    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        """Handle 405 Method Not Allowed errors."""
        return jsonify({
            'error': True,
            'message': 'Method not allowed',
            'error_code': 'METHOD_NOT_ALLOWED',
            'status_code': 405
        }), 405
    
    @app.errorhandler(429)
    def handle_rate_limit_exceeded(error):
        """Handle 429 Too Many Requests errors."""
        return jsonify({
            'error': True,
            'message': 'Rate limit exceeded',
            'error_code': 'RATE_LIMIT_EXCEEDED',
            'status_code': 429
        }), 429
    
    @app.errorhandler(500)
    def handle_internal_server_error(error):
        """Handle 500 Internal Server Error."""
        app.logger.error(f"Internal server error: {error}", extra={
            'request_id': getattr(g, 'request_id', None),
            'url': request.url,
            'method': request.method
        })
        
        return jsonify({
            'error': True,
            'message': 'Internal server error',
            'error_code': 'INTERNAL_SERVER_ERROR',
            'status_code': 500
        }), 500
    
    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Handle unexpected errors."""
        app.logger.error(f"Unexpected error: {error}", extra={
            'request_id': getattr(g, 'request_id', None),
            'url': request.url,
            'method': request.method
        }, exc_info=True)
        
        return jsonify({
            'error': True,
            'message': 'An unexpected error occurred',
            'error_code': 'UNEXPECTED_ERROR',
            'status_code': 500
        }), 500


def setup_request_hooks(app):
    """Setup request hooks for logging and monitoring."""
    
    @app.before_request
    def before_request():
        """Execute before each request."""
        # Add request ID
        add_request_id()
        
        # Log request start
        app.logger.info(f"Request started: {request.method} {request.url}", extra={
            'request_id': g.request_id,
            'method': request.method,
            'url': request.url,
            'remote_addr': extract_client_ip(),
            'user_agent': request.headers.get('User-Agent', '')
        })
        
        # Record request start time
        g.request_start_time = datetime.now(timezone.utc)
    
    @app.after_request
    def after_request(response):
        """Execute after each request."""
        # Calculate request duration
        if hasattr(g, 'request_start_time'):
            duration = (datetime.now(timezone.utc) - g.request_start_time).total_seconds()
        else:
            duration = 0
        
        # Log request completion
        app.logger.info(f"Request completed: {response.status_code}", extra={
            'request_id': getattr(g, 'request_id', None),
            'status_code': response.status_code,
            'duration_seconds': duration
        })
        
        # Add security headers
        if app.config.get('SECURITY_HEADERS_ENABLED', True):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            if request.is_secure:
                response.headers['Strict-Transport-Security'] = f"max-age={app.config.get('HSTS_MAX_AGE', 31536000)}; includeSubDomains"
            
            csp_policy = app.config.get('CSP_POLICY', "default-src 'self'")
            response.headers['Content-Security-Policy'] = csp_policy
        
        # Add request ID to response headers
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        
        return response


def register_blueprints(app):
    """Register application blueprints."""
    
    # Import blueprints
    from .routes.auth import auth_bp
    from .routes.urls import urls_bp
    from .routes.analytics import analytics_bp
    from .routes.admin import admin_bp
    from .routes.public import public_bp
    
    # Register blueprints with URL prefixes
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(urls_bp, url_prefix='/api/v1/urls')
    app.register_blueprint(analytics_bp, url_prefix='/api/v1/analytics')
    app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')
    app.register_blueprint(public_bp, url_prefix='')  # Public routes at root level
    
    # Root endpoint
    @app.route('/')
    def root():
        """Root endpoint with API information."""
        return jsonify({
            'name': app.config.get('API_TITLE', 'Io URL Shortener API'),
            'version': app.config.get('API_VERSION', 'v1'),
            'description': app.config.get('API_DESCRIPTION', 'Enterprise URL Shortener Service'),
            'documentation': '/docs',
            'health': '/health'
        })


def init_database(app):
    """Initialize database with tables and default data."""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create default admin user if it doesn't exist
        from .models import User
        from .services.auth_service import AuthService
        
        admin_email = app.config.get('ADMIN_EMAIL')
        admin_user = User.query.filter_by(email=admin_email).first()
        
        if not admin_user:
            try:
                admin_user = User(
                    username='admin',
                    email=admin_email,
                    password_hash=AuthService.hash_password(app.config.get("ADMIN_PASSWORD", "admin123")),
                    is_verified=True,
                    is_admin=True
                )
                
                db.session.add(admin_user)
                db.session.commit()
                
                app.logger.info(f"Default admin user created: {admin_email}")
                
            except Exception as e:
                app.logger.error(f"Failed to create default admin user: {e}")
                db.session.rollback()
        
        app.logger.info("Database initialization completed")


if __name__ == '__main__':
    app = create_app()
    init_database(app)
    app.run(debug=True)
