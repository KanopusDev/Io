"""
Admin service for handling administrative operations and user management.
Implements enterprise-grade admin functionalities with proper audit logging.
"""

from datetime import datetime, timezone, timedelta
from flask import current_app
from sqlalchemy import and_, or_, func
from sqlalchemy.exc import IntegrityError

from ..models import db, User, URL, Analytics, AdminAction
from ..utils.exceptions import (
    ValidationError, AuthorizationError, ResourceNotFoundError,
    ConflictError, DatabaseError
)


class AdminService:
    """Service class for administrative operations."""
    
    @staticmethod
    def verify_admin_access(admin_user):
        """Verify that user has admin access."""
        if not admin_user:
            raise AuthorizationError("User not found")
        if not admin_user.is_active:
            raise AuthorizationError("Account is suspended")
        if not admin_user.is_admin:
            raise AuthorizationError("Admin access required")
        return True
    
    @staticmethod
    def log_admin_action(admin_id, action_type, target_user_id=None, target_url_id=None, details=None, ip_address=None, user_agent=None):
        """Log admin action for audit trail with enhanced details."""
        try:
            # Enhance details with additional context
            details = details or ""
            if ip_address or user_agent:
                context_info = []
                if ip_address:
                    context_info.append(f"IP: {ip_address}")
                if user_agent:
                    context_info.append(f"User-Agent: {user_agent[:100]}")
                
                if context_info:
                    details = f"{details}\n[Context: {', '.join(context_info)}]"
            
            admin_action = AdminAction(
                admin_id=admin_id,
                action_type=action_type,
                target_user_id=target_user_id,
                target_url_id=target_url_id,
                details=details
            )
            
            db.session.add(admin_action)
            db.session.commit()
            
            current_app.logger.info(f"Admin action logged: {action_type} by admin {admin_id}")
            
            return admin_action
            
        except Exception as e:
            current_app.logger.error(f"Failed to log admin action: {e}")
            # Don't fail the main operation if logging fails
            return None
    
    @staticmethod
    def get_admin_user(admin_id):
        """Get admin user by ID with verification."""
        admin_user = User.query.get(admin_id)
        if not admin_user:
            raise ResourceNotFoundError("Admin user not found", resource_type='user')
        
        AdminService.verify_admin_access(admin_user)
        return admin_user
    
    @staticmethod
    def get_all_users(admin_user, page=1, per_page=50, search=None, status_filter=None):
        """Get paginated list of all users with optional filtering."""
        AdminService.verify_admin_access(admin_user)
        
        query = User.query
        
        # Apply search filter
        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    User.username.like(search_term),
                    User.email.like(search_term)
                )
            )
        
        # Apply status filter
        if status_filter == 'active':
            query = query.filter(User.is_active == True)
        elif status_filter == 'inactive':
            query = query.filter(User.is_active == False)
        elif status_filter == 'verified':
            query = query.filter(User.is_verified == True)
        elif status_filter == 'unverified':
            query = query.filter(User.is_verified == False)
        elif status_filter == 'admin':
            query = query.filter(User.is_admin == True)
        
        # Order by creation date (newest first)
        query = query.order_by(User.created_at.desc())
        
        users = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return users
    
    @staticmethod
    def get_user_details(admin_user, user_id):
        """Get detailed information about a specific user."""
        AdminService.verify_admin_access(admin_user)
        
        user = User.query.get(user_id)
        if not user:
            raise ResourceNotFoundError("User not found", resource_type='user')
        
        # Get user statistics
        total_urls = URL.query.filter_by(user_id=user_id).count()
        active_urls = URL.query.filter_by(user_id=user_id, is_active=True).count()
        
        # Get total clicks across all user URLs
        total_clicks = db.session.query(func.count(Analytics.id)).join(URL).filter(
            URL.user_id == user_id
        ).scalar() or 0
        
        # Get recent admin actions on this user
        recent_actions = AdminAction.query.filter_by(target_user_id=user_id).order_by(
            AdminAction.created_at.desc()
        ).limit(10).all()
        
        return {
            'user': user.to_dict(include_sensitive=True),
            'statistics': {
                'total_urls': total_urls,
                'active_urls': active_urls,
                'total_clicks': total_clicks
            },
            'recent_actions': [action.to_dict() for action in recent_actions]
        }
    
    @staticmethod
    def verify_user(admin_user, user_id, verify=True):
        """Verify or unverify a user."""
        AdminService.verify_admin_access(admin_user)
        
        user = User.query.get(user_id)
        if not user:
            raise ResourceNotFoundError("User not found", resource_type='user')
        
        if user.is_verified == verify:
            action = "verify" if verify else "unverify"
            raise ConflictError(f"User is already {action}ied")
        
        user.is_verified = verify
        user.updated_at = datetime.now(timezone.utc)
        
        # Generate API key for newly verified users
        if verify and not user.api_key:
            user.generate_api_key()
        
        try:
            db.session.commit()
            
            # Log admin action
            action_type = "USER_VERIFIED" if verify else "USER_UNVERIFIED"
            AdminService.log_admin_action(
                admin_user.id,
                action_type,
                target_user_id=user_id,
                details=f"User {'verified' if verify else 'unverified'} by admin"
            )
            
            current_app.logger.info(f"User {user.username} {'verified' if verify else 'unverified'} by admin {admin_user.username}")
            
            return user
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error {'verifying' if verify else 'unverifying'} user: {e}")
            raise DatabaseError(f"Failed to {'verify' if verify else 'unverify'} user")
    
    @staticmethod
    def suspend_user(admin_user, user_id, suspend=True):
        """Suspend or reactivate a user account."""
        AdminService.verify_admin_access(admin_user)
        
        user = User.query.get(user_id)
        if not user:
            raise ResourceNotFoundError("User not found", resource_type='user')
        
        # Prevent admin from suspending themselves
        if user.id == admin_user.id:
            raise ValidationError("Cannot suspend your own account")
        
        # Prevent suspending other admins (only super admin can do this)
        if user.is_admin and not admin_user.username == 'superadmin':
            raise AuthorizationError("Cannot suspend admin users")
        
        if user.is_active == (not suspend):
            action = "suspend" if suspend else "reactivate"
            raise ConflictError(f"User is already {action}d")
        
        user.is_active = not suspend
        user.updated_at = datetime.now(timezone.utc)
        
        try:
            db.session.commit()
            
            # Log admin action
            action_type = "USER_SUSPENDED" if suspend else "USER_REACTIVATED"
            AdminService.log_admin_action(
                admin_user.id,
                action_type,
                target_user_id=user_id,
                details=f"User {'suspended' if suspend else 'reactivated'} by admin"
            )
            
            current_app.logger.info(f"User {user.username} {'suspended' if suspend else 'reactivated'} by admin {admin_user.username}")
            
            return user
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error {'suspending' if suspend else 'reactivating'} user: {e}")
            raise DatabaseError(f"Failed to {'suspend' if suspend else 'reactivate'} user")
    
    @staticmethod
    def delete_user(admin_user, user_id):
        """Delete a user account and all associated data."""
        AdminService.verify_admin_access(admin_user)
        
        user = User.query.get(user_id)
        if not user:
            raise ResourceNotFoundError("User not found", resource_type='user')
        
        # Prevent admin from deleting themselves
        if user.id == admin_user.id:
            raise ValidationError("Cannot delete your own account")
        
        # Prevent deleting other admins
        if user.is_admin:
            raise AuthorizationError("Cannot delete admin users")
        
        try:
            # Get user data for logging
            username = user.username
            email = user.email
            
            # Delete user (cascade will handle related data)
            db.session.delete(user)
            db.session.commit()
            
            # Log admin action
            AdminService.log_admin_action(
                admin_user.id,
                "USER_DELETED",
                details=f"User {username} ({email}) deleted by admin"
            )
            
            current_app.logger.info(f"User {username} deleted by admin {admin_user.username}")
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error deleting user: {e}")
            raise DatabaseError("Failed to delete user")
    
    @staticmethod
    def get_all_urls(admin_user, page=1, per_page=50, search=None, status_filter=None):
        """Get paginated list of all URLs with optional filtering."""
        AdminService.verify_admin_access(admin_user)
        
        query = db.session.query(URL).join(User)
        
        # Apply search filter
        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    URL.short_code.like(search_term),
                    URL.custom_alias.like(search_term),
                    URL.original_url.like(search_term),
                    URL.title.like(search_term),
                    User.username.like(search_term)
                )
            )
        
        # Apply status filter
        if status_filter == 'active':
            query = query.filter(URL.is_active == True)
        elif status_filter == 'inactive':
            query = query.filter(URL.is_active == False)
        elif status_filter == 'expired':
            query = query.filter(
                and_(
                    URL.expires_at.isnot(None),
                    URL.expires_at < datetime.now(timezone.utc)
                )
            )
        
        # Order by creation date (newest first)
        query = query.order_by(URL.created_at.desc())
        
        urls = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return urls
    
    @staticmethod
    def delete_url(admin_user, url_id):
        """Delete a URL (admin action)."""
        AdminService.verify_admin_access(admin_user)
        
        url = URL.query.get(url_id)
        if not url:
            raise ResourceNotFoundError("URL not found", resource_type='url')
        
        try:
            # Get URL data for logging
            short_code = url.short_code
            original_url = url.original_url
            owner_username = url.user.username
            
            # Delete URL (cascade will handle analytics)
            db.session.delete(url)
            db.session.commit()
            
            # Log admin action
            AdminService.log_admin_action(
                admin_user.id,
                "URL_DELETED",
                target_url_id=url_id,
                target_user_id=url.user_id,
                details=f"URL {short_code} ({original_url}) owned by {owner_username} deleted by admin"
            )
            
            current_app.logger.info(f"URL {short_code} deleted by admin {admin_user.username}")
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error deleting URL: {e}")
            raise DatabaseError("Failed to delete URL")
    
    @staticmethod
    def get_global_analytics(admin_user, days=30):
        """Get global analytics for the platform."""
        AdminService.verify_admin_access(admin_user)
        
        # Date range filter
        end_date = datetime.now(timezone.utc)
        start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
        start_date = start_date.replace(day=start_date.day - days) if start_date.day > days else start_date.replace(month=start_date.month - 1, day=30 - (days - start_date.day))
        
        # Total statistics
        total_users = User.query.count()
        verified_users = User.query.filter_by(is_verified=True).count()
        active_users = User.query.filter_by(is_active=True).count()
        total_urls = URL.query.count()
        active_urls = URL.query.filter_by(is_active=True).count()
        total_clicks = Analytics.query.count()
        
        # Recent clicks
        recent_clicks = Analytics.query.filter(
            Analytics.clicked_at >= start_date
        ).count()
        
        # Daily statistics
        daily_stats = db.session.query(
            func.date(Analytics.clicked_at).label('date'),
            func.count(Analytics.id).label('clicks')
        ).filter(
            Analytics.clicked_at >= start_date
        ).group_by(func.date(Analytics.clicked_at)).all()
        
        # Top URLs by clicks
        top_urls = db.session.query(
            URL.short_code,
            URL.custom_alias,
            URL.original_url,
            URL.title,
            User.username,
            func.count(Analytics.id).label('clicks')
        ).join(Analytics).join(User).filter(
            Analytics.clicked_at >= start_date
        ).group_by(URL.id).order_by(func.count(Analytics.id).desc()).limit(10).all()
        
        # Top countries
        top_countries = db.session.query(
            Analytics.country,
            func.count(Analytics.id).label('clicks')
        ).filter(
            and_(
                Analytics.clicked_at >= start_date,
                Analytics.country.isnot(None)
            )
        ).group_by(Analytics.country).order_by(func.count(Analytics.id).desc()).limit(10).all()
        
        # Most active users
        active_user_stats = db.session.query(
            User.username,
            User.is_verified,
            func.count(URL.id).label('urls_count'),
            func.count(Analytics.id).label('total_clicks')
        ).join(URL).join(Analytics).filter(
            Analytics.clicked_at >= start_date
        ).group_by(User.id).order_by(func.count(Analytics.id).desc()).limit(10).all()
        
        return {
            'overview': {
                'total_users': total_users,
                'verified_users': verified_users,
                'active_users': active_users,
                'total_urls': total_urls,
                'active_urls': active_urls,
                'total_clicks': total_clicks,
                'recent_clicks': recent_clicks
            },
            'daily_clicks': [{'date': str(row.date), 'clicks': row.clicks} for row in daily_stats],
            'top_urls': [{
                'short_code': row.short_code,
                'custom_alias': row.custom_alias,
                'original_url': row.original_url,
                'title': row.title,
                'username': row.username,
                'clicks': row.clicks
            } for row in top_urls],
            'top_countries': [{'country': row.country, 'clicks': row.clicks} for row in top_countries],
            'active_users': [{
                'username': row.username,
                'is_verified': row.is_verified,
                'urls_count': row.urls_count,
                'total_clicks': row.total_clicks
            } for row in active_user_stats],
            'period_days': days
        }
    
    @staticmethod
    def get_audit_logs(admin_user, page=1, per_page=50, action_type=None, admin_id=None):
        """Get paginated audit logs."""
        AdminService.verify_admin_access(admin_user)
        
        query = AdminAction.query
        
        # Apply filters
        if action_type:
            query = query.filter(AdminAction.action_type == action_type)
        
        if admin_id:
            query = query.filter(AdminAction.admin_id == admin_id)
        
        # Order by creation date (newest first)
        query = query.order_by(AdminAction.created_at.desc())
        
        audit_logs = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return audit_logs
    
    @staticmethod
    def get_platform_statistics(admin_id, days=30):
        """Get comprehensive platform statistics."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        # User statistics
        total_users = User.query.count()
        verified_users = User.query.filter_by(is_verified=True).count()
        active_users = User.query.filter_by(is_active=True).count()
        
        # URL statistics
        total_urls = URL.query.count()
        active_urls = URL.query.filter_by(is_active=True).count()
        
        # Click statistics
        total_clicks = Analytics.query.count()
        recent_clicks = Analytics.query.filter(Analytics.clicked_at >= start_date).count()
        
        return {
            'total_users': total_users,
            'verified_users': verified_users,
            'active_users': active_users,
            'total_urls': total_urls,
            'active_urls': active_urls,
            'total_clicks': total_clicks,
            'recent_clicks': recent_clicks,
            'days': days
        }
    
    @staticmethod
    def get_platform_analytics(admin_id, days=30):
        """Get platform-wide analytics data."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        # Daily user registrations
        daily_registrations = db.session.query(
            func.date(User.created_at).label('date'),
            func.count(User.id).label('count')
        ).filter(
            User.created_at >= start_date
        ).group_by(func.date(User.created_at)).order_by(func.date(User.created_at)).all()
        
        # Daily URL creation
        daily_url_creation = db.session.query(
            func.date(URL.created_at).label('date'),
            func.count(URL.id).label('count')
        ).filter(
            URL.created_at >= start_date
        ).group_by(func.date(URL.created_at)).order_by(func.date(URL.created_at)).all()
        
        # Daily clicks
        daily_clicks = db.session.query(
            func.date(Analytics.clicked_at).label('date'),
            func.count(Analytics.id).label('clicks')
        ).filter(
            Analytics.clicked_at >= start_date
        ).group_by(func.date(Analytics.clicked_at)).order_by(func.date(Analytics.clicked_at)).all()
        
        # Top countries by clicks
        top_countries = db.session.query(
            Analytics.country,
            func.count(Analytics.id).label('clicks')
        ).filter(
            and_(
                Analytics.clicked_at >= start_date,
                Analytics.country.isnot(None)
            )
        ).group_by(Analytics.country).order_by(func.count(Analytics.id).desc()).limit(10).all()
        
        return {
            'daily_registrations': [{'date': str(row.date), 'count': row.count} for row in daily_registrations],
            'daily_url_creation': [{'date': str(row.date), 'count': row.count} for row in daily_url_creation],
            'daily_clicks': [{'date': str(row.date), 'clicks': row.clicks} for row in daily_clicks],
            'top_countries': [{'country': row.country, 'clicks': row.clicks} for row in top_countries],
            'days': days
        }
    
    @staticmethod
    def get_users(admin_id, page=1, per_page=20, search=None, status=None, verified=None, sort_by='created_at', sort_order='desc', **kwargs):
        """Get paginated list of users with filtering and search."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        query = User.query
        
        # Apply search filter
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    User.username.ilike(search_term),
                    User.email.ilike(search_term)
                )
            )
        
        # Apply status filter (active/suspended)
        if status:
            if status == 'active':
                query = query.filter_by(is_active=True)
            elif status == 'suspended':
                query = query.filter_by(is_active=False)
        
        # Apply verification filter
        if verified is not None:
            if verified == 'true' or verified is True:
                query = query.filter_by(is_verified=True)
            elif verified == 'false' or verified is False:
                query = query.filter_by(is_verified=False)
        
        # Apply sorting
        if sort_by == 'username':
            order_column = User.username
        elif sort_by == 'email':
            order_column = User.email
        else:
            order_column = User.created_at
        
        if sort_order == 'desc':
            query = query.order_by(order_column.desc())
        else:
            query = query.order_by(order_column.asc())
        
        # Paginate
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        users_data = []
        for user in pagination.items:
            user_data = user.to_dict()
            user_data['url_count'] = URL.query.filter_by(user_id=user.id).count()
            
            # Calculate total clicks from analytics
            total_clicks = db.session.query(func.count(Analytics.id)).join(URL).filter(URL.user_id == user.id).scalar() or 0
            user_data['total_clicks'] = total_clicks
            users_data.append(user_data)
        
        return {
            'users': users_data,
            'pagination': {
                'page': pagination.page,
                'per_page': pagination.per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_prev': pagination.has_prev,
                'has_next': pagination.has_next,
                'prev_num': pagination.prev_num,
                'next_num': pagination.next_num
            }
        }
    
    @staticmethod
    def get_user_details(admin_id, user_id):
        """Get detailed information about a specific user."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        user = User.query.get(user_id)
        if not user:
            raise ResourceNotFoundError("User not found")
        
        # Get user statistics
        url_count = URL.query.filter_by(user_id=user.id).count()
        active_url_count = URL.query.filter_by(user_id=user.id, is_active=True).count()
        
        # Calculate total clicks from analytics
        total_clicks = db.session.query(func.count(Analytics.id)).join(URL).filter(URL.user_id == user.id).scalar() or 0
        
        # Get recent activity
        recent_urls = URL.query.filter_by(user_id=user.id).order_by(URL.created_at.desc()).limit(5).all()
        
        # Get recent admin actions on this user
        recent_actions = AdminAction.query.filter_by(target_user_id=user.id).order_by(
            AdminAction.created_at.desc()
        ).limit(5).all()
        
        user_data = user.to_dict(include_sensitive=True)
        user_data.update({
            'url_count': url_count,
            'active_url_count': active_url_count,
            'total_clicks': total_clicks,
            'recent_urls': [url.to_dict() for url in recent_urls],
            'recent_actions': [action.to_dict() for action in recent_actions],
            'last_login': user.updated_at.isoformat()  # Use updated_at as proxy for last login
        })
        
        return user_data
    
    @staticmethod
    def update_user(admin_id, user_id, **update_data):
        """Update user information and status."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        user = User.query.get(user_id)
        if not user:
            raise ResourceNotFoundError("User not found")
        
        # Store original values for logging
        original_values = {
            'is_verified': user.is_verified,
            'is_suspended': user.is_suspended,
            'monthly_limit': user.monthly_limit
        }
        
        changes = []
        
        # Update fields
        if 'is_verified' in update_data:
            user.is_verified = update_data['is_verified']
            changes.append(f"verified: {original_values['is_verified']} -> {user.is_verified}")
        
        if 'is_suspended' in update_data:
            user.is_suspended = update_data['is_suspended']
            changes.append(f"suspended: {original_values['is_suspended']} -> {user.is_suspended}")
        
        if 'monthly_limit' in update_data:
            user.monthly_limit = update_data['monthly_limit']
            changes.append(f"monthly_limit: {original_values['monthly_limit']} -> {user.monthly_limit}")
        
        try:
            db.session.commit()
            
            # Log admin action
            if changes:
                AdminService.log_admin_action(
                    admin_user.id,
                    "USER_UPDATED",
                    target_user_id=user.id,
                    details=f"User {user.username} updated: {', '.join(changes)}"
                )
            
            current_app.logger.info(f"User {user.username} updated by admin {admin_user.username}: {', '.join(changes)}")
            
            return user.to_dict()
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating user: {e}")
            raise DatabaseError("Failed to update user")
    
    @staticmethod
    def get_audit_log(admin_id, page=1, per_page=20, action_type=None, target_user_id=None, days=30):
        """Get paginated audit log entries."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        query = AdminAction.query
        
        # Apply date filter
        if days:
            start_date = datetime.now(timezone.utc) - timedelta(days=days)
            query = query.filter(AdminAction.created_at >= start_date)
        
        # Apply action type filter
        if action_type:
            query = query.filter_by(action_type=action_type)
        
        # Apply target user filter
        if target_user_id:
            query = query.filter_by(target_user_id=target_user_id)
        
        # Order by most recent
        query = query.order_by(AdminAction.created_at.desc())
        
        # Paginate
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Prepare audit log data with user information
        audit_entries = []
        for action in pagination.items:
            entry = action.to_dict()
            
            # Add admin user information
            if action.admin:
                entry['admin_user'] = {
                    'id': action.admin.id,
                    'username': action.admin.username
                }
            
            # Add target user information if available
            if action.target_user:
                entry['target_user'] = {
                    'id': action.target_user.id,
                    'username': action.target_user.username
                }
            
            audit_entries.append(entry)
        
        return {
            'audit_log': audit_entries,
            'pagination': {
                'page': pagination.page,
                'per_page': pagination.per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_prev': pagination.has_prev,
                'has_next': pagination.has_next,
                'prev_num': pagination.prev_num,
                'next_num': pagination.next_num
            }
        }
    
    @staticmethod
    def get_all_urls(admin_id, page=1, per_page=20, user_id=None, status=None, sort_by='created_at', sort_order='desc'):
        """Get paginated list of all URLs in the system."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        query = URL.query.join(User)
        
        # Apply user filter
        if user_id:
            query = query.filter(URL.user_id == user_id)
        
        # Apply status filter
        if status:
            if status == 'active':
                query = query.filter_by(is_active=True)
            elif status == 'disabled':
                query = query.filter_by(is_active=False)
        
        # Apply sorting
        if sort_by == 'clicks':
            order_column = URL.click_count
        elif sort_by == 'short_code':
            order_column = URL.short_code
        else:
            order_column = URL.created_at
        
        if sort_order == 'desc':
            query = query.order_by(order_column.desc())
        else:
            query = query.order_by(order_column.asc())
        
        # Paginate
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Prepare URL data with owner information
        urls_data = []
        for url in pagination.items:
            url_data = url.to_dict()
            url_data['owner'] = {
                'id': url.user.id,
                'username': url.user.username,
                'is_verified': url.user.is_verified
            }
            urls_data.append(url_data)
        
        return {
            'urls': urls_data,
            'pagination': {
                'page': pagination.page,
                'per_page': pagination.per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_prev': pagination.has_prev,
                'has_next': pagination.has_next,
                'prev_num': pagination.prev_num,
                'next_num': pagination.next_num
            }
        }
    
    @staticmethod
    def disable_url(admin_id, url_id, reason):
        """Disable a URL."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        url = URL.query.get(url_id)
        if not url:
            raise ResourceNotFoundError("URL not found")
        
        if not url.is_active:
            raise ValidationError("URL is already disabled")
        
        try:
            url.is_active = False
            db.session.commit()
            
            # Log admin action
            AdminService.log_admin_action(
                admin_user.id,
                "URL_DISABLED",
                target_url_id=url_id,
                target_user_id=url.user_id,
                details=f"URL {url.short_code} disabled by admin. Reason: {reason}"
            )
            
            current_app.logger.info(f"URL {url.short_code} disabled by admin {admin_user.username}")
            
            return url.to_dict()
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error disabling URL: {e}")
            raise DatabaseError("Failed to disable URL")
    
    @staticmethod
    def enable_url(admin_id, url_id):
        """Enable a previously disabled URL."""
        from ..services.auth_service import AuthService
        admin_user = AuthService.get_user_by_id(admin_id)
        AdminService.verify_admin_access(admin_user)
        
        url = URL.query.get(url_id)
        if not url:
            raise ResourceNotFoundError("URL not found")
        
        if url.is_active:
            raise ValidationError("URL is already enabled")
        
        try:
            url.is_active = True
            db.session.commit()
            
            # Log admin action
            AdminService.log_admin_action(
                admin_user.id,
                "URL_ENABLED",
                target_url_id=url_id,
                target_user_id=url.user_id,
                details=f"URL {url.short_code} enabled by admin"
            )
            
            current_app.logger.info(f"URL {url.short_code} enabled by admin {admin_user.username}")
            
            return url.to_dict()
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error enabling URL: {e}")
            raise DatabaseError("Failed to enable URL")
