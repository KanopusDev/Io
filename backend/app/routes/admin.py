"""
Admin routes for user management and platform administration.
Implements enterprise-grade admin functionality with audit logging.
"""

from flask import Blueprint, request, jsonify, current_app
from marshmallow import ValidationError as MarshmallowValidationError

from ..services.admin_service import AdminService
from ..services.rate_limit_service import rate_limit
from ..utils.auth import admin_required, get_current_user_id
from ..utils.validation import AdminUserUpdateSchema, AdminUserSearchSchema
from ..utils.exceptions import AuthenticationError, AuthorizationError, ResourceNotFoundError, ValidationError

# Create blueprint
admin_bp = Blueprint('admin', __name__)

# Schema instances
admin_user_update_schema = AdminUserUpdateSchema()
admin_user_search_schema = AdminUserSearchSchema()


@admin_bp.route('/verify-access', methods=['GET'])
@admin_required()
@rate_limit(limit=50, window=3600)  # 50 verification requests per hour
def verify_admin_access():
    """
    Verify admin access token and permissions.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Returns:
        200: Admin access verified
        401: Authentication required
        403: Admin access required
        429: Rate limit exceeded
    """
    try:
        admin_id = get_current_user_id()
        admin_user = AdminService.get_admin_user(admin_id)
        
        # Log access verification
        AdminService.log_admin_action(
            admin_id=admin_id,
            action_type='admin_access_verification',
            details=f'Admin access verified for user {admin_user.username}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'message': 'Admin access verified',
            'data': {
                'admin_id': admin_user.id,
                'username': admin_user.username,
                'verified_at': admin_user.updated_at.isoformat(),
                'is_verified': admin_user.is_verified,
                'is_active': admin_user.is_active
            }
        })
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin access verification error: {e}")
        return jsonify({
            'error': True,
            'message': 'Admin access verification failed',
            'error_code': 'ADMIN_VERIFICATION_FAILED'
        }), 500


@admin_bp.route('/audit-log', methods=['POST'])
@admin_required()
@rate_limit(limit=1000, window=3600)  # 1000 audit log entries per hour
def create_audit_log():
    """
    Create audit log entry for admin actions.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Request Body:
        action_type (str): Type of action performed
        details (str): Detailed description of the action
        target_user_id (int, optional): Target user ID if applicable
        target_url_id (int, optional): Target URL ID if applicable
    
    Returns:
        201: Audit log entry created
        400: Validation error
        401: Authentication required
        403: Admin access required
        429: Rate limit exceeded
    """
    try:
        data = request.get_json() or {}
        
        admin_id = get_current_user_id()
        
        # Create audit log entry
        log_entry = AdminService.log_admin_action(
            admin_id=admin_id,
            action_type=data.get('action_type', 'unknown_action'),
            details=data.get('details', ''),
            target_user_id=data.get('target_user_id'),
            target_url_id=data.get('target_url_id'),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'message': 'Audit log entry created',
            'data': {
                'log_id': log_entry.id,
                'created_at': log_entry.created_at.isoformat()
            }
        }), 201
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin audit log error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to create audit log entry',
            'error_code': 'AUDIT_LOG_FAILED'
        }), 500


@admin_bp.route('/users', methods=['GET'])
@admin_required()
@rate_limit(limit=100, window=3600)  # 100 admin requests per hour
def list_users():
    """
    Get paginated list of users with search and filtering options.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Query Parameters:
        page (int, optional): Page number (default: 1)
        per_page (int, optional): Items per page (default: 20, max: 100)
        search (str, optional): Search term for username or email
        status (str, optional): Filter by status (active, suspended, pending)
        verified (bool, optional): Filter by verification status
        sort_by (str, optional): Sort field (created_at, username, last_login)
        sort_order (str, optional): Sort order (asc, desc)
    
    Returns:
        200: Paginated list of users
        401: Authentication required
        403: Admin access required
        429: Rate limit exceeded
    """
    try:
        # Validate query parameters
        query_params = admin_user_search_schema.load(request.args)
        
        admin_id = get_current_user_id()
        
        # Get paginated users
        users_data = AdminService.get_users(admin_id, **query_params)
        
        return jsonify({
            'success': True,
            'data': users_data
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin list users error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve users',
            'error_code': 'USERS_RETRIEVAL_FAILED'
        }), 500


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@admin_required()
@rate_limit(limit=200, window=3600)  # 200 admin requests per hour
def get_user_details(user_id):
    """
    Get detailed information about a specific user.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        user_id (int): User ID
    
    Returns:
        200: User details with statistics
        401: Authentication required
        403: Admin access required
        404: User not found
        429: Rate limit exceeded
    """
    try:
        admin_id = get_current_user_id()
        
        # Get user details
        user_data = AdminService.get_user_details(admin_id, user_id)
        
        return jsonify({
            'success': True,
            'data': user_data
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin get user details error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve user details',
            'error_code': 'USER_DETAILS_FAILED'
        }), 500


@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required()
@rate_limit(limit=100, window=3600)  # 100 admin update requests per hour
def update_user(user_id):
    """
    Update user information and status.
    
    Headers:
        Authorization: Bearer <access_token>
        Content-Type: application/json
    
    Path Parameters:
        user_id (int): User ID
    
    Request Body:
        {
            "is_verified": boolean (optional),
            "is_suspended": boolean (optional),
            "monthly_limit": integer (optional),
            "admin_note": string (optional)
        }
    
    Returns:
        200: User updated successfully
        400: Validation failed
        401: Authentication required
        403: Admin access required
        404: User not found
        429: Rate limit exceeded
    """
    try:
        # Validate request data
        update_data = admin_user_update_schema.load(request.get_json() or {})
        
        admin_id = get_current_user_id()
        
        # Update user
        updated_user = AdminService.update_user(admin_id, user_id, **update_data)
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully',
            'data': updated_user
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError, ValidationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin update user error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to update user',
            'error_code': 'USER_UPDATE_FAILED'
        }), 500


@admin_bp.route('/users/<int:user_id>/verify', methods=['POST'])
@admin_required()
@rate_limit(limit=50, window=3600)  # 50 verification requests per hour
def verify_user(user_id):
    """
    Verify a user account.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        user_id (int): User ID
    
    Returns:
        200: User verified successfully
        401: Authentication required
        403: Admin access required
        404: User not found
        409: User already verified
        429: Rate limit exceeded
    """
    try:
        admin_id = get_current_user_id()
        
        # Verify user
        result = AdminService.verify_user(admin_id, user_id)
        
        return jsonify({
            'success': True,
            'message': 'User verified successfully',
            'data': result
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError, ValidationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin verify user error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to verify user',
            'error_code': 'USER_VERIFICATION_FAILED'
        }), 500


@admin_bp.route('/users/<int:user_id>/suspend', methods=['POST'])
@admin_required()
@rate_limit(limit=50, window=3600)  # 50 suspension requests per hour
def suspend_user(user_id):
    """
    Suspend a user account.
    
    Headers:
        Authorization: Bearer <access_token>
        Content-Type: application/json
    
    Path Parameters:
        user_id (int): User ID
    
    Request Body:
        {
            "reason": string (required)
        }
    
    Returns:
        200: User suspended successfully
        400: Validation failed
        401: Authentication required
        403: Admin access required
        404: User not found
        409: User already suspended
        429: Rate limit exceeded
    """
    try:
        request_data = request.get_json() or {}
        reason = request_data.get('reason', '').strip()
        
        if not reason:
            return jsonify({
                'error': True,
                'message': 'Suspension reason is required',
                'error_code': 'REASON_REQUIRED'
            }), 400
        
        admin_id = get_current_user_id()
        
        # Suspend user
        result = AdminService.suspend_user(admin_id, user_id, reason)
        
        return jsonify({
            'success': True,
            'message': 'User suspended successfully',
            'data': result
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError, ValidationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin suspend user error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to suspend user',
            'error_code': 'USER_SUSPENSION_FAILED'
        }), 500


@admin_bp.route('/users/<int:user_id>/unsuspend', methods=['POST'])
@admin_required()
@rate_limit(limit=50, window=3600)  # 50 unsuspension requests per hour
def unsuspend_user(user_id):
    """
    Unsuspend a user account.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        user_id (int): User ID
    
    Returns:
        200: User unsuspended successfully
        401: Authentication required
        403: Admin access required
        404: User not found
        409: User not suspended
        429: Rate limit exceeded
    """
    try:
        admin_id = get_current_user_id()
        
        # Unsuspend user
        result = AdminService.unsuspend_user(admin_id, user_id)
        
        return jsonify({
            'success': True,
            'message': 'User unsuspended successfully',
            'data': result
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError, ValidationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin unsuspend user error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to unsuspend user',
            'error_code': 'USER_UNSUSPENSION_FAILED'
        }), 500


@admin_bp.route('/statistics', methods=['GET'])
@admin_required()
@rate_limit(limit=50, window=3600)  # 50 statistics requests per hour
def get_platform_statistics():
    """
    Get comprehensive platform statistics.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Query Parameters:
        days (int, optional): Number of days to include (default: 30, max: 365)
    
    Returns:
        200: Platform statistics
        401: Authentication required
        403: Admin access required
        429: Rate limit exceeded
    """
    try:
        days = request.args.get('days', 30, type=int)
        
        # Validate days parameter
        if days < 1 or days > 365:
            return jsonify({
                'error': True,
                'message': 'Days must be between 1 and 365',
                'error_code': 'INVALID_DAYS'
            }), 400
        
        admin_id = get_current_user_id()
        
        # Get platform statistics
        stats = AdminService.get_platform_statistics(admin_id, days)
        
        return jsonify({
            'success': True,
            'data': stats
        })
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin platform statistics error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve platform statistics',
            'error_code': 'STATISTICS_FAILED'
        }), 500


@admin_bp.route('/analytics', methods=['GET'])
@admin_required()
@rate_limit(limit=30, window=3600)  # 30 analytics requests per hour
def get_platform_analytics():
    """
    Get platform-wide analytics data.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Query Parameters:
        days (int, optional): Number of days to include (default: 30, max: 365)
    
    Returns:
        200: Platform analytics data
        401: Authentication required
        403: Admin access required
        429: Rate limit exceeded
    """
    try:
        days = request.args.get('days', 30, type=int)
        
        # Validate days parameter
        if days < 1 or days > 365:
            return jsonify({
                'error': True,
                'message': 'Days must be between 1 and 365',
                'error_code': 'INVALID_DAYS'
            }), 400
        
        admin_id = get_current_user_id()
        
        # Get platform analytics
        analytics = AdminService.get_platform_analytics(admin_id, days)
        
        return jsonify({
            'success': True,
            'data': analytics
        })
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin platform analytics error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve platform analytics',
            'error_code': 'ANALYTICS_FAILED'
        }), 500


@admin_bp.route('/audit-log', methods=['GET'])
@admin_required()
@rate_limit(limit=100, window=3600)  # 100 audit log requests per hour
def get_audit_log():
    """
    Get paginated audit log entries.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Query Parameters:
        page (int, optional): Page number (default: 1)
        per_page (int, optional): Items per page (default: 20, max: 100)
        action_type (str, optional): Filter by action type
        target_user_id (int, optional): Filter by target user ID
        days (int, optional): Number of days to include (default: 30, max: 365)
    
    Returns:
        200: Paginated audit log entries
        401: Authentication required
        403: Admin access required
        429: Rate limit exceeded
    """
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        action_type = request.args.get('action_type')
        target_user_id = request.args.get('target_user_id', type=int)
        days = request.args.get('days', 30, type=int)
        
        # Validate parameters
        if page < 1:
            page = 1
        if per_page < 1:
            per_page = 20
        if days < 1 or days > 365:
            days = 30
        
        admin_id = get_current_user_id()
        
        # Get audit log
        audit_data = AdminService.get_audit_log(
            admin_id=admin_id,
            page=page,
            per_page=per_page,
            action_type=action_type,
            target_user_id=target_user_id,
            days=days
        )
        
        return jsonify({
            'success': True,
            'data': audit_data
        })
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin audit log error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve audit log',
            'error_code': 'AUDIT_LOG_FAILED'
        }), 500


@admin_bp.route('/urls', methods=['GET'])
@admin_required()
@rate_limit(limit=100, window=3600)  # 100 URL listing requests per hour
def list_urls():
    """
    Get paginated list of all URLs in the system.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Query Parameters:
        page (int, optional): Page number (default: 1)
        per_page (int, optional): Items per page (default: 20, max: 100)
        user_id (int, optional): Filter by user ID
        status (str, optional): Filter by status (active, disabled)
        sort_by (str, optional): Sort field (created_at, clicks, short_code)
        sort_order (str, optional): Sort order (asc, desc)
    
    Returns:
        200: Paginated list of URLs
        401: Authentication required
        403: Admin access required
        429: Rate limit exceeded
    """
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        user_id = request.args.get('user_id', type=int)
        status = request.args.get('status')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # Validate parameters
        if page < 1:
            page = 1
        if per_page < 1:
            per_page = 20
        if sort_by not in ['created_at', 'clicks', 'short_code']:
            sort_by = 'created_at'
        if sort_order not in ['asc', 'desc']:
            sort_order = 'desc'
        if status and status not in ['active', 'disabled']:
            status = None
        
        admin_id = get_current_user_id()
        
        # Get URLs
        urls_data = AdminService.get_all_urls(
            admin_id=admin_id,
            page=page,
            per_page=per_page,
            user_id=user_id,
            status=status,
            sort_by=sort_by,
            sort_order=sort_order
        )
        
        return jsonify({
            'success': True,
            'data': urls_data
        })
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin list URLs error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve URLs',
            'error_code': 'URLS_RETRIEVAL_FAILED'
        }), 500


@admin_bp.route('/urls/<int:url_id>/disable', methods=['POST'])
@admin_required()
@rate_limit(limit=50, window=3600)  # 50 URL disable requests per hour
def disable_url(url_id):
    """
    Disable a URL.
    
    Headers:
        Authorization: Bearer <access_token>
        Content-Type: application/json
    
    Path Parameters:
        url_id (int): URL ID
    
    Request Body:
        {
            "reason": string (required)
        }
    
    Returns:
        200: URL disabled successfully
        400: Validation failed
        401: Authentication required
        403: Admin access required
        404: URL not found
        429: Rate limit exceeded
    """
    try:
        request_data = request.get_json() or {}
        reason = request_data.get('reason', '').strip()
        
        if not reason:
            return jsonify({
                'error': True,
                'message': 'Disable reason is required',
                'error_code': 'REASON_REQUIRED'
            }), 400
        
        admin_id = get_current_user_id()
        
        # Disable URL
        result = AdminService.disable_url(admin_id, url_id, reason)
        
        return jsonify({
            'success': True,
            'message': 'URL disabled successfully',
            'data': result
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError, ValidationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin disable URL error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to disable URL',
            'error_code': 'URL_DISABLE_FAILED'
        }), 500


@admin_bp.route('/urls/<int:url_id>/enable', methods=['POST'])
@admin_required()
@rate_limit(limit=50, window=3600)  # 50 URL enable requests per hour
def enable_url(url_id):
    """
    Enable a previously disabled URL.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        url_id (int): URL ID
    
    Returns:
        200: URL enabled successfully
        401: Authentication required
        403: Admin access required
        404: URL not found
        409: URL not disabled
        429: Rate limit exceeded
    """
    try:
        admin_id = get_current_user_id()
        
        # Enable URL
        result = AdminService.enable_url(admin_id, url_id)
        
        return jsonify({
            'success': True,
            'message': 'URL enabled successfully',
            'data': result
        })
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError, ValidationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Admin enable URL error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to enable URL',
            'error_code': 'URL_ENABLE_FAILED'
        }), 500
