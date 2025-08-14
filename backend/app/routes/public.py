"""
Public routes for URL resolution, health checks, and public API endpoints.
Implements enterprise-grade public functionality with security and analytics.
"""

from flask import Blueprint, request, jsonify, redirect, current_app, render_template_string
from marshmallow import ValidationError as MarshmallowValidationError
from datetime import datetime, timezone
import user_agents

from ..services.url_service import URLService
from ..services.rate_limit_service import ip_rate_limit
from ..utils.exceptions import ResourceNotFoundError, ValidationError
import os
# Create blueprint
public_bp = Blueprint('public', __name__)


@public_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring and load balancers.
    
    Returns:
        200: Service is healthy
        503: Service is unhealthy
    """
    try:
        # Check database connectivity
        from ..models import db
        db.session.execute(db.text('SELECT 1'))
        
        # Check basic service functionality
        health_data = {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.0.0',
            'services': {
                'database': 'up',
                'redis': 'up'  # fakeredis is always up
            }
        }
        
        return jsonify(health_data), 200
        
    except Exception as e:
        current_app.logger.error(f"Health check failed: {e}")
        
        health_data = {
            'status': 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.0.0',
            'error': 'Database connectivity issue'
        }
        
        return jsonify(health_data), 503


@public_bp.route('/status', methods=['GET'])
def service_status():
    """
    Detailed service status endpoint for monitoring.
    
    Returns:
        200: Service status information
    """
    try:
        from ..models import db, User, URL
        
        # Get basic statistics
        total_users = db.session.query(User).count()
        total_urls = db.session.query(URL).count()
        
        status_data = {
            'service': 'Io URL Shortener',
            'status': 'operational',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '1.0.0',
            'uptime': 'Available',
            'statistics': {
                'total_users': total_users,
                'total_urls': total_urls
            },
            'components': {
                'api': 'operational',
                'database': 'operational',
                'rate_limiting': 'operational'
            }
        }
        
        return jsonify(status_data)
        
    except Exception as e:
        current_app.logger.error(f"Status check error: {e}")
        
        status_data = {
            'service': 'Io URL Shortener',
            'status': 'degraded',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': 'Service experiencing issues'
        }
        
        return jsonify(status_data), 500


@public_bp.route('/<short_code>', methods=['GET'])
@ip_rate_limit(limit=100, window=60)  # 100 redirects per minute per IP
def redirect_url(short_code):
    """
    Redirect to the original URL using short code.
    
    Path Parameters:
        short_code (str): Short code for the URL
    
    Query Parameters:
        preview (bool, optional): Show preview page instead of redirecting
    
    Returns:
        302: Redirect to original URL
        200: Preview page (if preview=true)
        404: Short code not found
        410: URL disabled or expired
        429: Rate limit exceeded
    """
    try:
        # Check if preview mode is requested
        preview_mode = request.args.get('preview', '').lower() in ['true', '1', 'yes']
        
        # Get client information for analytics
        user_agent_string = request.headers.get('User-Agent', '')
        user_agent = user_agents.parse(user_agent_string)
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
        referer = request.headers.get('Referer', '')
        
        # Analytics data
        analytics_data = {
            'ip_address': client_ip,
            'user_agent': user_agent_string,
            'referer': referer,
            'device_type': 'mobile' if user_agent.is_mobile else 'tablet' if user_agent.is_tablet else 'desktop',
            'browser': user_agent.browser.family if user_agent.browser else 'unknown'
        }
        
        # Resolve short code and track analytics
        url_data = URLService.resolve_short_code(short_code, analytics_data)
        
        if preview_mode:
            # Return preview page
            preview_html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>URL Preview - Io</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 min-h-screen flex items-center justify-center">
                <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                    <div class="text-center mb-6">
                        <h1 class="text-2xl font-bold text-gray-800 mb-2">URL Preview</h1>
                        <p class="text-gray-600">You are about to visit:</p>
                    </div>
                    
                    <div class="bg-gray-50 p-4 rounded mb-6">
                        <p class="text-sm text-gray-500 mb-1">Short URL:</p>
                        <p class="font-mono text-sm break-all">{request.url}</p>
                        
                        <p class="text-sm text-gray-500 mb-1 mt-3">Destination:</p>
                        <p class="font-mono text-sm break-all text-blue-600">{url_data['original_url']}</p>
                    </div>
                    
                    <div class="flex space-x-3">
                        <a href="{url_data['original_url']}" 
                           class="flex-1 bg-blue-500 text-white px-4 py-2 rounded text-center hover:bg-blue-600 transition-colors">
                            Continue
                        </a>
                        <button onclick="window.history.back()" 
                                class="flex-1 bg-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-400 transition-colors">
                            Go Back
                        </button>
                    </div>
                    
                    <div class="mt-4 text-center">
                        <p class="text-xs text-gray-500">
                            Powered by <span class="font-semibold">Io URL Shortener</span>
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            return preview_html, 200
        else:
            # Redirect to original URL
            return redirect(url_data['original_url'], code=302)
        
    except ResourceNotFoundError:
        if preview_mode:
            error_html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>URL Not Found - Io</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 min-h-screen flex items-center justify-center">
                <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full text-center">
                    <h1 class="text-2xl font-bold text-red-600 mb-4">URL Not Found</h1>
                    <p class="text-gray-600 mb-6">The short URL you requested does not exist or has been removed.</p>
                    <a href="/" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 transition-colors">
                        Go to Homepage
                    </a>
                </div>
            </body>
            </html>
            """
            return error_html, 404
        else:
            return jsonify({
                'error': True,
                'message': 'Short URL not found',
                'error_code': 'URL_NOT_FOUND'
            }), 404
        
    except ValidationError as e:
        if preview_mode:
            error_html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>URL Disabled - Io</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 min-h-screen flex items-center justify-center">
                <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full text-center">
                    <h1 class="text-2xl font-bold text-orange-600 mb-4">URL Disabled</h1>
                    <p class="text-gray-600 mb-6">{e.message}</p>
                    <a href="/" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 transition-colors">
                        Go to Homepage
                    </a>
                </div>
            </body>
            </html>
            """
            return error_html, 410
        else:
            return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"URL resolution error: {e}")
        
        if preview_mode:
            error_html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Service Error - Io</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 min-h-screen flex items-center justify-center">
                <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full text-center">
                    <h1 class="text-2xl font-bold text-red-600 mb-4">Service Error</h1>
                    <p class="text-gray-600 mb-6">We're experiencing technical difficulties. Please try again later.</p>
                    <a href="/" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 transition-colors">
                        Go to Homepage
                    </a>
                </div>
            </body>
            </html>
            """
            return error_html, 500
        else:
            return jsonify({
                'error': True,
                'message': 'Service temporarily unavailable',
                'error_code': 'SERVICE_ERROR'
            }), 500


@public_bp.route('/api/info/<short_code>', methods=['GET'])
@ip_rate_limit(limit=50, window=60)  # 50 info requests per minute per IP
def get_url_info(short_code):
    """
    Get public information about a short URL without redirecting.
    
    Path Parameters:
        short_code (str): Short code for the URL
    
    Returns:
        200: URL information
        404: Short code not found
        410: URL disabled
        429: Rate limit exceeded
    """
    try:
        # Get URL information without tracking analytics
        url_info = URLService.get_public_url_info(short_code)
        
        return jsonify({
            'success': True,
            'data': url_info
        })
        
    except ResourceNotFoundError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except ValidationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"URL info error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve URL information',
            'error_code': 'URL_INFO_FAILED'
        }), 500


@public_bp.route('/api/stats/<short_code>', methods=['GET'])
@ip_rate_limit(limit=30, window=60)  # 30 stats requests per minute per IP
def get_public_stats(short_code):
    """
    Get public statistics for a short URL (limited information).
    
    Path Parameters:
        short_code (str): Short code for the URL
    
    Returns:
        200: Public statistics
        404: Short code not found
        410: URL disabled
        429: Rate limit exceeded
    """
    try:
        # Get public statistics
        public_stats = URLService.get_public_url_stats(short_code)
        
        return jsonify({
            'success': True,
            'data': public_stats
        })
        
    except ResourceNotFoundError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except ValidationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Public stats error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve URL statistics',
            'error_code': 'STATS_FAILED'
        }), 500


@public_bp.route('/api/batch/info', methods=['POST'])
@ip_rate_limit(limit=10, window=60)  # 10 batch requests per minute per IP
def get_batch_url_info():
    """
    Get information for multiple short URLs in a single request.
    
    Headers:
        Content-Type: application/json
    
    Request Body:
        {
            "short_codes": ["code1", "code2", "code3"]
        }
    
    Returns:
        200: Batch URL information
        400: Validation failed
        429: Rate limit exceeded
    """
    try:
        request_data = request.get_json() or {}
        short_codes = request_data.get('short_codes', [])
        
        # Validate request
        if not isinstance(short_codes, list):
            return jsonify({
                'error': True,
                'message': 'short_codes must be an array',
                'error_code': 'INVALID_INPUT'
            }), 400
        
        if len(short_codes) == 0:
            return jsonify({
                'error': True,
                'message': 'At least one short code is required',
                'error_code': 'EMPTY_REQUEST'
            }), 400
        
        if len(short_codes) > 50:  # Limit batch size
            return jsonify({
                'error': True,
                'message': 'Maximum 50 short codes per request',
                'error_code': 'BATCH_SIZE_EXCEEDED'
            }), 400
        
        # Get batch information
        batch_info = URLService.get_batch_url_info(short_codes)
        
        return jsonify({
            'success': True,
            'data': batch_info
        })
        
    except Exception as e:
        current_app.logger.error(f"Batch URL info error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve batch URL information',
            'error_code': 'BATCH_INFO_FAILED'
        }), 500


@public_bp.route('/api/v1/public/shorten', methods=['POST'])
@ip_rate_limit(limit=10, window=300)  # 10 temporary URLs per 5 minutes per IP
def create_temporary_url():
    """
    Create a temporary short URL that expires in 15 minutes.
    This endpoint doesn't require authentication for demo purposes.
    
    Headers:
        Content-Type: application/json
    
    Request Body:
        {
            "original_url": "https://example.com"
        }
    
    Returns:
        201: Temporary URL created successfully
        400: Validation failed
        429: Rate limit exceeded
    """
    try:
        request_data = request.get_json() or {}
        original_url = request_data.get('original_url', '').strip()
        
        # Validate URL
        if not original_url:
            return jsonify({
                'error': True,
                'message': 'original_url is required',
                'error_code': 'MISSING_URL'
            }), 400
        
        # Import validators here to avoid circular imports
        import validators
        
        if not validators.url(original_url):
            return jsonify({
                'error': True,
                'message': 'Invalid URL format',
                'error_code': 'INVALID_URL'
            }), 400
        
        # Check URL length
        if len(original_url) > 2048:
            return jsonify({
                'error': True,
                'message': 'URL too long (maximum 2048 characters)',
                'error_code': 'URL_TOO_LONG'
            }), 400
        
        # Get client IP for analytics
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
        
        # Create temporary URL (15 minutes expiration)
        from datetime import timedelta
        temp_url_data = URLService.create_temporary_url(
            original_url=original_url,
            client_ip=client_ip,
            expires_in_minutes=15
        )
        
        # Construct full short URL
        base_url = request.url_root.rstrip('/')
        short_url = f"{base_url}/{temp_url_data['short_code']}"
        
        return jsonify({
            'success': True,
            'message': 'Temporary URL created successfully',
            'data': {
                'original_url': original_url,
                'short_url': short_url,
                'short_code': temp_url_data['short_code'],
                'expires_at': temp_url_data['expires_at'],
                'expires_in_minutes': 15,
                'qr_code_url': f"{base_url}/api/v1/public/qr/{temp_url_data['short_code']}"
            }
        }), 201
        
    except ValidationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Temporary URL creation error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to create temporary URL',
            'error_code': 'TEMP_URL_CREATION_FAILED'
        }), 500


@public_bp.route('/api/v1/public/qr/<short_code>', methods=['GET'])
@ip_rate_limit(limit=50, window=60)  # 50 QR code requests per minute per IP
def get_public_qr_code(short_code):
    """
    Generate QR code for a short URL (public endpoint).
    
    Path Parameters:
        short_code (str): Short code for the URL
    
    Query Parameters:
        size (int, optional): QR code size in pixels (default: 200, max: 500)
        format (str, optional): Image format (png, svg) (default: png)
    
    Returns:
        200: QR code image
        404: Short code not found
        410: URL disabled or expired
        429: Rate limit exceeded
    """
    try:
        # Get query parameters
        size = min(int(request.args.get('size', 200)), 500)  # Limit max size
        format_type = request.args.get('format', 'png').lower()
        
        if format_type not in ['png', 'svg']:
            format_type = 'png'
        
        # Generate QR code
        qr_code_data = URLService.generate_public_qr_code(
            short_code=short_code,
            size=size,
            format_type=format_type,
            base_url=request.url_root.rstrip('/')
        )
        
        # Set appropriate content type
        content_type = 'image/png' if format_type == 'png' else 'image/svg+xml'
        
        return qr_code_data, 200, {
            'Content-Type': content_type,
            'Cache-Control': 'public, max-age=3600'  # Cache for 1 hour
        }
        
    except ResourceNotFoundError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except ValidationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"QR code generation error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to generate QR code',
            'error_code': 'QR_GENERATION_FAILED'
        }), 500


@public_bp.route('/robots.txt', methods=['GET'])
def robots_txt():
    """
    Robots.txt for search engine crawlers.
    
    Returns:
        200: Robots.txt content
    """
    robots_content = """User-agent: *
Allow: /
Disallow: /api/
Disallow: /admin/

# Sitemap
Sitemap: {}/sitemap.xml
""".format(request.url_root.rstrip('/'))
    
    return robots_content, 200, {'Content-Type': 'text/plain'}


@public_bp.route('/sitemap.xml', methods=['GET'])
def sitemap_xml():
    """
    Basic sitemap for search engines.
    
    Returns:
        200: Sitemap XML content
    """
    sitemap_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>{request.url_root}</loc>
        <changefreq>daily</changefreq>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>{request.url_root}health</loc>
        <changefreq>daily</changefreq>
        <priority>0.5</priority>
    </url>
    <url>
        <loc>{request.url_root}status</loc>
        <changefreq>daily</changefreq>
        <priority>0.5</priority>
    </url>
</urlset>"""
    
    return sitemap_content, 200, {'Content-Type': 'application/xml'}


@public_bp.route('/', methods=['GET'])
def index():
    """
    Homepage for the URL shortener service.
    
    Returns:
        200: Homepage HTML
    """
    try:
        # Basic homepage HTML (will be replaced by frontend)
        homepage_html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Io URL Shortener</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <meta name="description" content="Professional URL shortening service with analytics and custom domains">
        </head>
        <body class="bg-gray-100 min-h-screen">
            <div class="container mx-auto px-4 py-8">
                <div class="text-center mb-8">
                    <h1 class="text-4xl font-bold text-gray-800 mb-4">Io URL Shortener</h1>
                    <p class="text-xl text-gray-600">Professional URL shortening with enterprise features</p>
                </div>
                
                <div class="max-w-2xl mx-auto bg-white rounded-lg shadow-md p-6">
                    <h2 class="text-2xl font-semibold mb-4">Features</h2>
                    <ul class="list-disc list-inside space-y-2 text-gray-700">
                        <li>Custom short URLs with analytics</li>
                        <li>QR code generation</li>
                        <li>API access for developers</li>
                        <li>Custom domains for verified users</li>
                        <li>Comprehensive dashboard and reporting</li>
                        <li>Enterprise-grade security</li>
                    </ul>
                    
                    <div class="mt-6 text-center">
                        <p class="text-gray-600">API documentation and web interface coming soon!</p>
                    </div>
                </div>
                
                <div class="text-center mt-8">
                    <p class="text-sm text-gray-500">
                        Check our <a href="/status" class="text-blue-500 hover:underline">service status</a> |
                        <a href="/health" class="text-blue-500 hover:underline">health check</a>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return homepage_html, 200
        
    except Exception as e:
        current_app.logger.error(f"Homepage error: {e}")
        return jsonify({
            'error': True,
            'message': 'Service temporarily unavailable',
            'error_code': 'SERVICE_ERROR'
        }), 500
