"""
Authentication routes for user registration, login, and token management.
Implements enterprise-grade authentication endpoints with proper validation and security.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import get_jwt_identity, get_jwt
from marshmallow import ValidationError as MarshmallowValidationError

from ..services.auth_service import AuthService
from ..services.rate_limit_service import rate_limit, public_rate_limit
from ..utils.auth import jwt_required, validate_json_request, require_fields
from ..utils.validation import (
    UserRegistrationSchema, UserLoginSchema, UserProfileUpdateSchema,
    ChangePasswordSchema, TokenResponseSchema, UserResponseSchema,
    ErrorResponseSchema, SuccessResponseSchema
)
from ..utils.exceptions import ValidationError, AuthenticationError, AuthorizationError

# Create blueprint
auth_bp = Blueprint('auth', __name__)

# Schema instances
user_registration_schema = UserRegistrationSchema()
user_login_schema = UserLoginSchema()
user_profile_update_schema = UserProfileUpdateSchema()
change_password_schema = ChangePasswordSchema()
token_response_schema = TokenResponseSchema()
user_response_schema = UserResponseSchema()
error_response_schema = ErrorResponseSchema()
success_response_schema = SuccessResponseSchema()


@auth_bp.route('/register', methods=['POST'])
@public_rate_limit(limit=5, window=300)  # 5 registrations per 5 minutes per IP
@validate_json_request()
@require_fields('username', 'email', 'password')
def register():
    """
    Register a new user.
    
    Request Body:
        username (str): Unique username (3-50 characters, alphanumeric, hyphens, underscores)
        email (str): Valid email address
        password (str): Strong password (8+ characters with uppercase, lowercase, digit, special char)
    
    Returns:
        201: User created successfully with tokens
        400: Validation error
        409: Username or email already exists
        429: Rate limit exceeded
    """
    try:
        # Validate request data
        data = user_registration_schema.load(request.get_json())
        
        # Register user
        user = AuthService.register_user(
            username=data['username'],
            email=data['email'],
            password=data['password']
        )
        
        # Generate tokens for new user
        tokens = AuthService.generate_tokens(user)
        
        # Prepare response
        response_data = {
            'user': user_response_schema.dump(user),
            **tokens
        }
        
        current_app.logger.info(f"User registered successfully: {user.username}")
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'data': response_data
        }), 201
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except ValidationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Registration error: {e}")
        return jsonify({
            'error': True,
            'message': 'Registration failed',
            'error_code': 'REGISTRATION_FAILED'
        }), 500


@auth_bp.route('/login', methods=['POST'])
@public_rate_limit(limit=10, window=300)  # 10 login attempts per 5 minutes per IP
@validate_json_request()
@require_fields('login', 'password')
def login():
    """
    Authenticate user and return tokens.
    
    Request Body:
        login (str): Username or email
        password (str): User password
    
    Returns:
        200: Authentication successful with tokens
        400: Validation error
        401: Invalid credentials
        429: Rate limit exceeded
    """
    try:
        # Validate request data
        data = user_login_schema.load(request.get_json())
        
        # Authenticate user
        user = AuthService.authenticate_user(
            login=data['login'],
            password=data['password']
        )
        
        # Generate tokens
        tokens = AuthService.generate_tokens(user)
        
        # Prepare response
        response_data = {
            'user': user_response_schema.dump(user),
            **tokens
        }
        
        current_app.logger.info(f"User logged in successfully: {user.username}")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'data': response_data
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
        current_app.logger.error(f"Login error: {e}")
        return jsonify({
            'error': True,
            'message': 'Login failed',
            'error_code': 'LOGIN_FAILED'
        }), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required()
@rate_limit(limit=30, window=3600)  # 30 refresh attempts per hour per user
def refresh():
    """
    Refresh access token using refresh token.
    
    Headers:
        Authorization: Bearer <refresh_token>
    
    Returns:
        200: New access token generated
        401: Invalid or expired refresh token
        429: Rate limit exceeded
    """
    try:
        # Generate new access token
        tokens = AuthService.refresh_access_token()
        
        current_app.logger.info(f"Token refreshed for user: {get_jwt_identity()}")
        
        return jsonify({
            'success': True,
            'message': 'Token refreshed successfully',
            'data': tokens
        })
        
    except AuthenticationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {e}")
        return jsonify({
            'error': True,
            'message': 'Token refresh failed',
            'error_code': 'TOKEN_REFRESH_FAILED'
        }), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
@rate_limit(limit=20, window=3600)  # 20 logout attempts per hour per user
def logout():
    """
    Logout user by blacklisting current token.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Returns:
        200: Logout successful
        401: Invalid token
        429: Rate limit exceeded
    """
    try:
        # Get token information
        jti = get_jwt()['jti']
        token_type = get_jwt().get('type', 'access')
        
        # Blacklist token
        AuthService.logout_user(jti, token_type)
        
        current_app.logger.info(f"User logged out: {get_jwt_identity()}")
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        })
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {e}")
        return jsonify({
            'error': True,
            'message': 'Logout failed',
            'error_code': 'LOGOUT_FAILED'
        }), 500


@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
@rate_limit(limit=60, window=3600)  # 60 profile requests per hour per user
def get_profile():
    """
    Get current user profile.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Returns:
        200: User profile data
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        user_id = get_jwt_identity()
        user = AuthService.get_user_by_id(user_id)
        
        return jsonify({
            'success': True,
            'data': user_response_schema.dump(user)
        })
        
    except AuthenticationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Get profile error: {e}")
        return jsonify({
            'error': True,
            'message': 'Failed to retrieve profile',
            'error_code': 'PROFILE_RETRIEVAL_FAILED'
        }), 500


@auth_bp.route('/profile', methods=['PUT'])
@jwt_required()
@rate_limit(limit=10, window=3600)  # 10 profile updates per hour per user
@validate_json_request()
def update_profile():
    """
    Update current user profile.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Request Body:
        email (str, optional): New email address
    
    Returns:
        200: Profile updated successfully
        400: Validation error
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Validate request data
        data = user_profile_update_schema.load(request.get_json())
        
        user_id = get_jwt_identity()
        
        # Update user profile
        user = AuthService.update_user_profile(user_id, **data)
        
        current_app.logger.info(f"Profile updated for user: {user.username}")
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'data': user_response_schema.dump(user)
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (AuthenticationError, ValidationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Profile update error: {e}")
        return jsonify({
            'error': True,
            'message': 'Profile update failed',
            'error_code': 'PROFILE_UPDATE_FAILED'
        }), 500


@auth_bp.route('/change-password', methods=['PUT'])
@jwt_required()
@rate_limit(limit=5, window=3600)  # 5 password changes per hour per user
@validate_json_request()
@require_fields('current_password', 'new_password')
def change_password():
    """
    Change user password.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Request Body:
        current_password (str): Current password
        new_password (str): New strong password
    
    Returns:
        200: Password changed successfully
        400: Validation error
        401: Invalid current password
        429: Rate limit exceeded
    """
    try:
        # Validate request data
        data = change_password_schema.load(request.get_json())
        
        user_id = get_jwt_identity()
        
        # Change password
        AuthService.change_password(
            user_id=user_id,
            current_password=data['current_password'],
            new_password=data['new_password']
        )
        
        current_app.logger.info(f"Password changed for user: {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
        
    except MarshmallowValidationError as e:
        return jsonify({
            'error': True,
            'message': 'Validation failed',
            'errors': e.messages,
            'error_code': 'VALIDATION_ERROR'
        }), 400
        
    except (AuthenticationError, ValidationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Password change error: {e}")
        return jsonify({
            'error': True,
            'message': 'Password change failed',
            'error_code': 'PASSWORD_CHANGE_FAILED'
        }), 500


@auth_bp.route('/regenerate-api-key', methods=['POST'])
@jwt_required()
@rate_limit(limit=3, window=3600)  # 3 API key regenerations per hour per user
def regenerate_api_key():
    """
    Regenerate API key for verified users.
    
    Headers:
        Authorization: Bearer <access_token>
    
    Returns:
        200: API key regenerated successfully
        401: Authentication required
        403: Verification required
        429: Rate limit exceeded
    """
    try:
        user_id = get_jwt_identity()
        
        # Regenerate API key
        new_api_key = AuthService.regenerate_api_key(user_id)
        
        current_app.logger.info(f"API key regenerated for user: {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'API key regenerated successfully',
            'data': {
                'api_key': new_api_key
            }
        })
        
    except (AuthenticationError, AuthorizationError) as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"API key regeneration error: {e}")
        return jsonify({
            'error': True,
            'message': 'API key regeneration failed',
            'error_code': 'API_KEY_REGENERATION_FAILED'
        }), 500


@auth_bp.route('/account', methods=['DELETE'])
@jwt_required()
@rate_limit(limit=1, window=86400)  # 1 account deletion per day per user
def delete_account():
    """
    Delete user account (soft delete by deactivating).
    
    Headers:
        Authorization: Bearer <access_token>
    
    Returns:
        200: Account deleted successfully
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        user_id = get_jwt_identity()
        user = AuthService.get_user_by_id(user_id)
        
        # Deactivate user account
        user.is_active = False
        from ..models import db
        db.session.commit()
        
        # Blacklist current token
        jti = get_jwt()['jti']
        AuthService.logout_user(jti)
        
        current_app.logger.info(f"Account deleted for user: {user.username}")
        
        return jsonify({
            'success': True,
            'message': 'Account deleted successfully'
        })
        
    except AuthenticationError as e:
        return jsonify(e.to_dict()), e.status_code
        
    except Exception as e:
        current_app.logger.error(f"Account deletion error: {e}")
        return jsonify({
            'error': True,
            'message': 'Account deletion failed',
            'error_code': 'ACCOUNT_DELETION_FAILED'
        }), 500
