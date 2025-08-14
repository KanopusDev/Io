"""
Analytics routes for URL click tracking and statistics.
Implements enterprise-grade analytics with comprehensive metrics and reporting.
"""

from flask import Blueprint, request, jsonify, current_app
from marshmallow import ValidationError as MarshmallowValidationError

from ..services.url_service import URLService
from ..services.rate_limit_service import rate_limit, api_key_rate_limit
from ..utils.auth import jwt_required, api_key_required, get_current_user_id
from ..utils.validation import AnalyticsQuerySchema
from ..utils.exceptions import AuthenticationError, AuthorizationError, ResourceNotFoundError
import os
# Create blueprint
analytics_bp = Blueprint('analytics', __name__)

# Schema instances
analytics_query_schema = AnalyticsQuerySchema()


@analytics_bp.route('/<int:url_id>', methods=['GET'])
@jwt_required()
@rate_limit(limit=100, window=3600)  # 100 analytics requests per hour per user
def get_url_analytics(url_id):
    """
    Get analytics for a specific URL.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        url_id (int): URL ID
    
    Query Parameters:
        days (int, optional): Number of days to include (default: 30, max: 365)
    
    Returns:
        200: Analytics data for the URL
        401: Authentication required
        403: Access denied
        404: URL not found
        429: Rate limit exceeded
    """
    try:
        # Validate query parameters
        query_params = analytics_query_schema.load(request.args)
        days = query_params.get('days', 30)
        
        user_id = get_current_user_id()
        
        # Get URL analytics
        analytics_data = URLService.get_url_analytics(url_id, user_id, days)
        
        return jsonify({
            'success': True,
            'data': analytics_data
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"URL analytics error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve analytics',
            'error_code': 'ANALYTICS_RETRIEVAL_FAILED'
        }), 500


@analytics_bp.route('/summary', methods=['GET'])
@jwt_required()
@rate_limit(limit=50, window=3600)  # 50 summary requests per hour per user
def get_analytics_summary():
    """
    Get analytics summary for all user URLs.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Query Parameters:
        days (int, optional): Number of days to include (default: 30, max: 365)
    
    Returns:
        200: Analytics summary data
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Validate query parameters
        query_params = analytics_query_schema.load(request.args)
        days = query_params.get('days', 30)
        
        user_id = get_current_user_id()
        
        # Get analytics summary
        summary_data = URLService.get_user_analytics_summary(user_id, days)
        
        return jsonify({
            'success': True,
            'data': summary_data
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except AuthenticationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Analytics summary error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve analytics summary',
            'error_code': 'ANALYTICS_SUMMARY_FAILED'
        }), 500


# Custom API endpoints for verified users
@analytics_bp.route('/<username>/analytics', methods=['GET'])
@api_key_required()
@api_key_rate_limit(limit=100, window=3600)  # 100 analytics requests per hour
def custom_get_analytics(username):
    """
    Get analytics summary via custom user endpoint (API key required).
    
    Headers:
        X-API-Key: <api_key>
    
    Path Parameters:
        username (str): User's username
    
    Query Parameters:
        days (int, optional): Number of days to include (default: 30, max: 365)
    
    Returns:
        200: Analytics summary data
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
        query_params = analytics_query_schema.load(request.args)
        days = query_params.get('days', 30)
        
        # Get analytics summary
        summary_data = URLService.get_user_analytics_summary(current_user.id, days)
        
        return jsonify({
            'success': True,
            'data': summary_data
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
        current_app.logger.error(f"Custom API analytics error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve analytics',
            'error_code': 'ANALYTICS_RETRIEVAL_FAILED'
        }), 500


@analytics_bp.route('/<username>/urls/<int:url_id>/analytics', methods=['GET'])
@api_key_required()
@api_key_rate_limit(limit=100, window=3600)  # 100 analytics requests per hour
def custom_get_url_analytics(username, url_id):
    """
    Get specific URL analytics via custom user endpoint (API key required).
    
    Headers:
        X-API-Key: <api_key>
    
    Path Parameters:
        username (str): User's username
        url_id (int): URL ID
    
    Query Parameters:
        days (int, optional): Number of days to include (default: 30, max: 365)
    
    Returns:
        200: Analytics data for the URL
        401: Invalid API key
        403: Username mismatch, verification required, or access denied
        404: URL not found
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
        query_params = analytics_query_schema.load(request.args)
        days = query_params.get('days', 30)
        
        # Get URL analytics
        analytics_data = URLService.get_url_analytics(url_id, current_user.id, days)
        
        return jsonify({
            'success': True,
            'data': analytics_data
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Custom API URL analytics error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve analytics',
            'error_code': 'ANALYTICS_RETRIEVAL_FAILED'
        }), 500


@analytics_bp.route('/export/<int:url_id>', methods=['GET'])
@jwt_required()
@rate_limit(limit=10, window=3600)  # 10 export requests per hour per user
def export_url_analytics(url_id):
    """
    Export URL analytics data (for verified users only).
    
    Headers:
        Authorization: Bearer <access_token>
    
    Path Parameters:
        url_id (int): URL ID
    
    Query Parameters:
        days (int, optional): Number of days to include (default: 30, max: 365)
        format (str, optional): Export format (json, csv) (default: json)
    
    Returns:
        200: Analytics data in requested format
        401: Authentication required
        403: Access denied or verification required
        404: URL not found
        429: Rate limit exceeded
    """
    try:
        from ..utils.auth import get_current_user
        current_user = get_current_user()
        
        # Check if user is verified
        if not current_user.is_verified:
            return jsonify({
                'error': True,
                'message': 'Analytics export is only available for verified users',
                'error_code': 'VERIFICATION_REQUIRED'
            }), 403
        
        # Validate query parameters
        query_params = analytics_query_schema.load(request.args)
        days = query_params.get('days', 30)
        export_format = request.args.get('format', 'json').lower()
        
        if export_format not in ['json', 'csv']:
            return jsonify({
                'error': True,
                'message': 'Invalid export format. Supported formats: json, csv',
                'error_code': 'INVALID_FORMAT'
            }), 400
        
        user_id = get_current_user_id()
        
        # Get URL analytics with full details
        analytics_data = URLService.get_url_analytics(url_id, user_id, days)
        
        if export_format == 'csv':
            # Convert to CSV format
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(['Date', 'Clicks'])
            
            # Write daily clicks data
            for item in analytics_data['daily_clicks']:
                writer.writerow([item['date'], item['clicks']])
            
            csv_content = output.getvalue()
            output.close()
            
            return csv_content, 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': f'attachment; filename=url_{url_id}_analytics.csv'
            }
        else:
            # Return JSON format
            return jsonify({
                'success': True,
                'data': analytics_data
            })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (AuthenticationError, AuthorizationError, ResourceNotFoundError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Analytics export error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to export analytics',
            'error_code': 'ANALYTICS_EXPORT_FAILED'
        }), 500


@analytics_bp.route('/dashboard', methods=['GET'])
@jwt_required()
@rate_limit(limit=30, window=3600)  # 30 dashboard requests per hour per user
def get_dashboard_data():
    """
    Get comprehensive dashboard data for user.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Query Parameters:
        days (int, optional): Number of days to include (default: 30, max: 365)
    
    Returns:
        200: Dashboard data with overview and analytics
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Validate query parameters
        query_params = analytics_query_schema.load(request.args)
        days = query_params.get('days', 30)
        
        user_id = get_current_user_id()
        
        # Get user analytics summary
        analytics_summary = URLService.get_user_analytics_summary(user_id, days)
        
        # Get user information
        from ..services.auth_service import AuthService
        user = AuthService.get_user_by_id(user_id)
        
        # Prepare dashboard data
        dashboard_data = {
            'user_info': {
                'username': user.username,
                'is_verified': user.is_verified,
                'monthly_requests': user.monthly_requests,
                'monthly_limit': user.monthly_limit,
                'requests_remaining': user.requests_remaining
            },
            'analytics': analytics_summary,
            'period_days': days
        }
        
        return jsonify({
            'success': True,
            'data': dashboard_data
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except AuthenticationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Dashboard data error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve dashboard data',
            'error_code': 'DASHBOARD_DATA_FAILED'
        }), 500
