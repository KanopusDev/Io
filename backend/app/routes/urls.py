"""
URL management routes for creating, updating, and managing short URLs.
Implements enterprise-grade URL shortening with analytics and security features.
"""

from flask import Blueprint, request, jsonify, current_app
from marshmallow import ValidationError as MarshmallowValidationError

from ..services.url_service import URLService
from ..services.rate_limit_service import rate_limit, api_key_rate_limit
from ..utils.auth import (
    jwt_required, api_key_required, dual_auth_required, verified_user_required,
    get_current_user, get_current_user_id, validate_json_request, require_fields
)
from ..utils.validation import (
    URLCreationSchema, URLUpdateSchema, PaginationSchema,
    URLResponseSchema, PaginatedResponseSchema
)
from ..utils.exceptions import ValidationError, AuthenticationError, AuthorizationError, ResourceNotFoundError

# Create blueprint
urls_bp = Blueprint('urls', __name__)

# Schema instances
url_creation_schema = URLCreationSchema()
url_update_schema = URLUpdateSchema()
pagination_schema = PaginationSchema()
url_response_schema = URLResponseSchema()
paginated_response_schema = PaginatedResponseSchema()


@urls_bp.route('', methods=['POST'])
@dual_auth_required()
@rate_limit(limit=100, window=3600)  # 100 URL creations per hour per user
@validate_json_request()
@require_fields('original_url')
def create_url():
    """
    Create a new short URL.
    
    Authentication (either one):
        Authorization: Bearer <jwt_token>  (for web interface)
        X-API-Key: <api_key>              (for programmatic access)
    
    Request Body:
        original_url (str): URL to be shortened
        custom_alias (str, optional): Custom short code (3-50 characters)
        title (str, optional): Title for the URL (max 255 characters)
        description (str, optional): Description for the URL (max 1000 characters)
        expires_at (datetime, optional): Expiration date/time
    
    Returns:
        201: URL created successfully
        400: Validation error
        401: Authentication required
        409: Custom alias already exists
        429: Rate limit exceeded
    """
    try:
        # Validate request data
        data = url_creation_schema.load(request.get_json())
        
        user_id = get_current_user_id()
        
        # Create short URL
        url = URLService.create_short_url(
            user_id=user_id,
            original_url=data['original_url'],
            custom_alias=data.get('custom_alias'),
            title=data.get('title'),
            description=data.get('description'),
            expires_at=data.get('expires_at')
        )
        
        current_app.logger.info(f"URL created: {url.short_code} by user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'URL created successfully',
            'data': url_response_schema.dump(url)
        }), 201
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (ValidationError, AuthenticationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"URL creation error: {e}")
        return jsonify({
            'error': True,
            'message': 'URL creation failed',
            'error_code': 'URL_CREATION_FAILED'
        }), 500


@urls_bp.route('', methods=['GET'])
@jwt_required()
@rate_limit(limit=200, window=3600)  # 200 list requests per hour per user
def list_urls():
    """
    Get paginated list of user's URLs.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Query Parameters:
        page (int, optional): Page number (default: 1)
        per_page (int, optional): Items per page (default: 20, max: 100)
        include_inactive (bool, optional): Include inactive URLs (default: false)
    
    Returns:
        200: List of URLs with pagination
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Validate query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
        
        user_id = get_current_user_id()
        
        # Get user URLs
        urls_pagination = URLService.get_user_urls(
            user_id=user_id,
            page=page,
            per_page=per_page,
            include_inactive=include_inactive
        )
        
        # Prepare response
        response_data = {
            'items': [url_response_schema.dump(url) for url in urls_pagination.items],
            'page': urls_pagination.page,
            'per_page': urls_pagination.per_page,
            'total': urls_pagination.total,
            'pages': urls_pagination.pages,
            'has_prev': urls_pagination.has_prev,
            'has_next': urls_pagination.has_next,
            'prev_num': urls_pagination.prev_num,
            'next_num': urls_pagination.next_num
        }
        
        return jsonify({
            'success': True,
            'data': response_data
        })
        
    except AuthenticationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"URL listing error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve URLs',
            'error_code': 'URL_LISTING_FAILED'
        }), 500


@urls_bp.route('/<int:url_id>', methods=['GET'])
@jwt_required()
@rate_limit(limit=300, window=3600)  # 300 individual URL requests per hour per user
def get_url(url_id):
    """
    Get specific URL details.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        url_id (int): URL ID
    
    Returns:
        200: URL details
        401: Authentication required
        403: Access denied
        404: URL not found
        429: Rate limit exceeded
    """
    try:
        user_id = get_current_user_id()
        
        # Get URL by ID
        url = URLService.get_url_by_id(url_id, user_id)
        
        return jsonify({
            'success': True,
            'data': url_response_schema.dump(url)
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"URL retrieval error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve URL',
            'error_code': 'URL_RETRIEVAL_FAILED'
        }), 500


@urls_bp.route('/<int:url_id>', methods=['PUT'])
@jwt_required()
@rate_limit(limit=50, window=3600)  # 50 URL updates per hour per user
@validate_json_request()
def update_url(url_id):
    """
    Update URL details.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        url_id (int): URL ID
    
    Request Body:
        original_url (str, optional): New URL to redirect to
        custom_alias (str, optional): New custom short code
        title (str, optional): New title
        description (str, optional): New description
        is_active (bool, optional): Active status
        expires_at (datetime, optional): New expiration date/time
    
    Returns:
        200: URL updated successfully
        400: Validation error
        401: Authentication required
        403: Access denied
        404: URL not found
        409: Custom alias conflict
        429: Rate limit exceeded
    """
    try:
        # Validate request data
        data = url_update_schema.load(request.get_json())
        
        user_id = get_current_user_id()
        
        # Update URL
        url = URLService.update_url(url_id, user_id, **data)
        
        current_app.logger.info(f"URL updated: {url.short_code} by user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'URL updated successfully',
            'data': url_response_schema.dump(url)
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (ValidationError, AuthenticationError, AuthorizationError, ResourceNotFoundError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"URL update error: {e}")
        return jsonify({
            'error': True,
            'message': 'URL update failed',
            'error_code': 'URL_UPDATE_FAILED'
        }), 500


@urls_bp.route('/<int:url_id>', methods=['DELETE'])
@jwt_required()
@rate_limit(limit=100, window=3600)  # 100 URL deletions per hour per user
def delete_url(url_id):
    """
    Delete URL (soft delete by deactivating).
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        url_id (int): URL ID
    
    Returns:
        200: URL deleted successfully
        401: Authentication required
        403: Access denied
        404: URL not found
        429: Rate limit exceeded
    """
    try:
        user_id = get_current_user_id()
        
        # Delete URL
        URLService.delete_url(url_id, user_id)
        
        current_app.logger.info(f"URL deleted: {url_id} by user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'URL deleted successfully'
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"URL deletion error: {e}")
        return jsonify({
            'error': True,
            'message': 'URL deletion failed',
            'error_code': 'URL_DELETION_FAILED'
        }), 500


@urls_bp.route('/<int:url_id>/qr', methods=['GET'])
@jwt_required()
@rate_limit(limit=100, window=3600)  # 100 QR code requests per hour per user
def get_qr_code(url_id):
    """
    Get QR code for URL.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        url_id (int): URL ID
    
    Returns:
        200: QR code as base64 image
        401: Authentication required
        403: Access denied
        404: URL not found
        429: Rate limit exceeded
    """
    try:
        user_id = get_current_user_id()
        
        # Get URL to verify ownership
        url = URLService.get_url_by_id(url_id, user_id)
        
        # Generate QR code
        qr_code = URLService.generate_qr_code(url.short_code)
        
        if not qr_code:
            return jsonify({
                'error': True,
                'message': 'Failed to generate QR code',
                'error_code': 'QR_GENERATION_FAILED'
            }), 500
        
        return jsonify({
            'success': True,
            'data': {
                'qr_code': qr_code,
                'url': url_response_schema.dump(url)
            }
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"QR code generation error: {e}")
        return jsonify({
            'error': True,
            'message': 'QR code generation failed',
            'error_code': 'QR_GENERATION_FAILED'
        }), 500


# Custom API endpoints for verified users
@urls_bp.route('/<username>/shorten', methods=['POST'])
@api_key_required()
@api_key_rate_limit(limit=500, window=3600)  # 500 requests per hour for verified users
@validate_json_request()
@require_fields('original_url')
def custom_shorten(username):
    """
    Create short URL via custom user endpoint (API key required).
    
    Headers:
        X-API-Key: <api_key>
    
    Path Parameters:
        username (str): User's username
    
    Request Body:
        original_url (str): URL to be shortened
        custom_alias (str, optional): Custom short code
        title (str, optional): Title for the URL
        description (str, optional): Description for the URL
        expires_at (datetime, optional): Expiration date/time
    
    Returns:
        201: URL created successfully
        400: Validation error
        401: Invalid API key
        403: Verification required
        429: Rate limit exceeded
    """
    try:
        from ..utils.auth import get_current_user
        current_user = get_current_user()
        
        # Verify username matches authenticated user
        if current_user.username != username:
            return jsonify({
                'error': True,
                'message': 'Username mismatch',
                'error_code': 'USERNAME_MISMATCH'
            }), 403
        
        # Validate request data
        data = url_creation_schema.load(request.get_json())
        
        # Create short URL
        url = URLService.create_short_url(
            user_id=current_user.id,
            original_url=data['original_url'],
            custom_alias=data.get('custom_alias'),
            title=data.get('title'),
            description=data.get('description'),
            expires_at=data.get('expires_at')
        )
        
        current_app.logger.info(f"URL created via API: {url.short_code} by user {current_user.username}")
        
        return jsonify({
            'success': True,
            'message': 'URL created successfully',
            'data': url_response_schema.dump(url)
        }), 201
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (ValidationError, AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Custom API URL creation error: {e}")
        return jsonify({
            'error': True,
            'message': 'URL creation failed',
            'error_code': 'URL_CREATION_FAILED'
        }), 500


@urls_bp.route('/<username>/urls', methods=['GET'])
@api_key_required()
@api_key_rate_limit(limit=200, window=3600)  # 200 list requests per hour
def custom_list_urls(username):
    """
    Get user's URLs via custom endpoint (API key required).
    
    Headers:
        X-API-Key: <api_key>
    
    Path Parameters:
        username (str): User's username
    
    Query Parameters:
        page (int, optional): Page number (default: 1)
        per_page (int, optional): Items per page (default: 20, max: 100)
    
    Returns:
        200: List of URLs with pagination
        401: Invalid API key
        403: Username mismatch or verification required
        429: Rate limit exceeded
    """
    try:
        from ..utils.auth import get_current_user
        current_user = get_current_user()
        
        # Verify username matches authenticated user
        if current_user.username != username:
            return jsonify({
                'error': True,
                'message': 'Username mismatch',
                'error_code': 'USERNAME_MISMATCH'
            }), 403
        
        # Validate query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Get user URLs
        urls_pagination = URLService.get_user_urls(
            user_id=current_user.id,
            page=page,
            per_page=per_page,
            include_inactive=False
        )
        
        # Prepare response
        response_data = {
            'items': [url_response_schema.dump(url) for url in urls_pagination.items],
            'page': urls_pagination.page,
            'per_page': urls_pagination.per_page,
            'total': urls_pagination.total,
            'pages': urls_pagination.pages,
            'has_prev': urls_pagination.has_prev,
            'has_next': urls_pagination.has_next,
            'prev_num': urls_pagination.prev_num,
            'next_num': urls_pagination.next_num
        }
        
        return jsonify({
            'success': True,
            'data': response_data
        })
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Custom API URL listing error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve URLs',
            'error_code': 'URL_LISTING_FAILED'
        }), 500
