"""
URL service for handling URL shortening, validation, and management.
Implements enterprise-grade URL handling with analytics tracking and security features.
"""

import validators
import secrets
import string
import qrcode
import io
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse
from flask import current_app
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_, or_, func

from ..models import db, URL, User, Analytics
from ..utils.exceptions import (
    ValidationError, URLValidationError, ShortCodeError, 
    ResourceNotFoundError, AuthorizationError, ConflictError
)


class URLService:
    """Service class for URL operations."""
    
    # List of blocked/malicious domains (basic implementation)
    BLOCKED_DOMAINS = {
        'malware.com', 'virus.com', 'spam.com', 'phishing.com',
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co'  # Block other shorteners
    }
    
    # List of blocked URL patterns
    BLOCKED_PATTERNS = [
        'javascript:', 'data:', 'file:', 'ftp:'
    ]
    
    @staticmethod
    def validate_url(url):
        """Validate URL format and security."""
        if not url or len(url.strip()) == 0:
            raise URLValidationError("URL is required")
        
        url = url.strip()
        
        # Basic URL validation
        if not validators.url(url):
            raise URLValidationError("Invalid URL format")
        
        # Parse URL for security checks
        parsed = urlparse(url)
        
        # Check for blocked schemes
        if parsed.scheme.lower() in ['javascript', 'data', 'file', 'ftp']:
            raise URLValidationError("URL scheme not allowed")
        
        # Ensure HTTP or HTTPS
        if parsed.scheme.lower() not in ['http', 'https']:
            raise URLValidationError("Only HTTP and HTTPS URLs are allowed")
        
        # Check for blocked domains
        domain = parsed.netloc.lower()
        if domain in URLService.BLOCKED_DOMAINS:
            raise URLValidationError("Domain is blocked")
        
        # Check for localhost/private IPs (basic check)
        if domain in ['localhost', '127.0.0.1', '0.0.0.0'] or domain.startswith('192.168.') or domain.startswith('10.'):
            raise URLValidationError("Private/localhost URLs are not allowed")
        
        # URL length check
        if len(url) > 2048:
            raise URLValidationError("URL is too long (maximum 2048 characters)")
        
        # Normalize URL
        normalized_url = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        return normalized_url
    
    @staticmethod
    def validate_custom_alias(alias, user_id=None, url_id=None):
        """Validate custom alias format and availability."""
        if not alias:
            return None
        
        alias = alias.strip()
        
        if len(alias) < 3:
            raise ShortCodeError("Custom alias must be at least 3 characters long")
        
        if len(alias) > 50:
            raise ShortCodeError("Custom alias must be no more than 50 characters long")
        
        # Check format (alphanumeric, hyphens, underscores only)
        if not all(c.isalnum() or c in '-_' for c in alias):
            raise ShortCodeError("Custom alias can only contain letters, numbers, hyphens, and underscores")
        
        # Check for reserved aliases
        reserved_aliases = ['api', 'admin', 'www', 'mail', 'ftp', 'localhost', 'root', 'support', 'help', 'about', 'contact', 's']
        if alias.lower() in reserved_aliases:
            raise ShortCodeError("This alias is reserved and cannot be used")
        
        # Check availability
        query = URL.query.filter(
            or_(URL.custom_alias == alias, URL.short_code == alias)
        )
        
        # Exclude current URL if updating
        if url_id:
            query = query.filter(URL.id != url_id)
        
        existing_url = query.first()
        if existing_url:
            raise ShortCodeError("This alias is already taken")
        
        return alias
    
    @staticmethod
    def generate_short_code(length=6, max_attempts=10):
        """Generate a unique short code."""
        characters = string.ascii_letters + string.digits
        
        for _ in range(max_attempts):
            code = ''.join(secrets.choice(characters) for _ in range(length))
            
            # Check if code already exists
            if not URL.query.filter(
                or_(URL.short_code == code, URL.custom_alias == code)
            ).first():
                return code
        
        # If we couldn't generate a unique code, try with longer length
        if length < 10:
            return URLService.generate_short_code(length + 1, max_attempts)
        
        raise ValidationError("Unable to generate unique short code")
    
    @staticmethod
    def create_short_url(user_id, original_url, custom_alias=None, title=None, description=None, expires_at=None):
        """Create a new short URL."""
        try:
            # Validate inputs
            normalized_url = URLService.validate_url(original_url)
            validated_alias = URLService.validate_custom_alias(custom_alias)
            
            # Check if user already has this URL
            existing_url = URL.query.filter_by(
                user_id=user_id,
                original_url=normalized_url
            ).first()
            
            if existing_url and existing_url.is_active:
                current_app.logger.info(f"User {user_id} attempted to create duplicate URL: {normalized_url}")
                return existing_url
            
            # Generate short code
            short_code = URLService.generate_short_code()
            
            # Create URL record
            url = URL(
                user_id=user_id,
                original_url=normalized_url,
                short_code=short_code,
                custom_alias=validated_alias,
                title=title[:255] if title else None,
                description=description[:1000] if description else None,
                expires_at=expires_at
            )
            
            db.session.add(url)
            db.session.commit()
            
            current_app.logger.info(f"Short URL created: {short_code} -> {normalized_url} by user {user_id}")
            
            return url
            
        except IntegrityError as e:
            db.session.rollback()
            current_app.logger.error(f"Database integrity error creating URL: {e}")
            
            # Check if it's a duplicate short code/alias
            if 'short_code' in str(e) or 'custom_alias' in str(e):
                # Retry with new short code
                return URLService.create_short_url(user_id, original_url, custom_alias, title, description, expires_at)
            
            raise ConflictError("URL creation failed due to conflict")
        
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating short URL: {e}")
            raise
    
    @staticmethod
    def get_url_by_code(code, include_inactive=False):
        """Get URL by short code or custom alias."""
        if not code:
            raise ValidationError("URL code is required")
        
        query = URL.query.filter(
            or_(URL.short_code == code, URL.custom_alias == code)
        )
        
        if not include_inactive:
            query = query.filter(URL.is_active == True)
        
        url = query.first()
        
        if not url:
            raise ResourceNotFoundError("Short URL not found", resource_type='url')
        
        return url
    
    @staticmethod
    def get_user_urls(user_id, page=1, per_page=20, include_inactive=False):
        """Get paginated list of user's URLs."""
        query = URL.query.filter_by(user_id=user_id)
        
        if not include_inactive:
            query = query.filter(URL.is_active == True)
        
        urls = query.order_by(URL.created_at.desc()).paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return urls
    
    @staticmethod
    def get_url_by_id(url_id, user_id=None):
        """Get URL by ID with optional user ownership check."""
        url = URL.query.get(url_id)
        
        if not url:
            raise ResourceNotFoundError("URL not found", resource_type='url')
        
        # Check ownership if user_id provided
        if user_id is not None and url.user_id != user_id:
            raise AuthorizationError("You don't have access to this URL")
        
        return url
    
    @staticmethod
    def update_url(url_id, user_id, **kwargs):
        """Update URL with validation."""
        url = URLService.get_url_by_id(url_id, user_id)
        
        # Validate and update original URL if provided
        if 'original_url' in kwargs:
            url.original_url = URLService.validate_url(kwargs['original_url'])
        
        # Validate and update custom alias if provided
        if 'custom_alias' in kwargs:
            url.custom_alias = URLService.validate_custom_alias(kwargs['custom_alias'], user_id, url_id)
        
        # Update other fields
        allowed_fields = ['title', 'description', 'is_active', 'expires_at']
        for field in allowed_fields:
            if field in kwargs:
                value = kwargs[field]
                if field == 'title' and value:
                    value = value[:255]
                elif field == 'description' and value:
                    value = value[:1000]
                setattr(url, field, value)
        
        url.updated_at = datetime.now(timezone.utc)
        
        try:
            db.session.commit()
            current_app.logger.info(f"URL updated: {url.short_code} by user {user_id}")
            return url
        
        except IntegrityError:
            db.session.rollback()
            raise ConflictError("Update failed due to conflict")
    
    @staticmethod
    def delete_url(url_id, user_id):
        """Delete URL (soft delete by deactivating)."""
        url = URLService.get_url_by_id(url_id, user_id)
        
        url.is_active = False
        url.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        current_app.logger.info(f"URL deleted: {url.short_code} by user {user_id}")
    
    @staticmethod
    def resolve_url(code, request_data=None):
        """Resolve short URL and track analytics."""
        url = URLService.get_url_by_code(code)
        
        # Check if URL is accessible
        if not url.is_accessible():
            if url.is_expired:
                raise ResourceNotFoundError("Short URL has expired")
            else:
                raise ResourceNotFoundError("Short URL is not active")
        
        # Track analytics if request data provided
        if request_data:
            URLService.track_analytics(url.id, request_data)
        
        return url.original_url
    
    @staticmethod
    def track_analytics(url_id, request_data):
        """Track analytics for URL click."""
        try:
            from user_agents import parse
            
            user_agent_string = request_data.get('user_agent', '')
            user_agent = parse(user_agent_string) if user_agent_string else None
            
            # Extract analytics data
            analytics_data = {
                'url_id': url_id,
                'user_agent': user_agent_string[:500] if user_agent_string else None,
                'ip_address': request_data.get('ip_address'),
                'referer': request_data.get('referer', '')[:500] if request_data.get('referer') else None,
                'country': request_data.get('country'),
                'city': request_data.get('city'),
                'device_type': user_agent.device.family if user_agent else None,
                'browser': user_agent.browser.family if user_agent else None
            }
            
            analytics = Analytics(**analytics_data)
            db.session.add(analytics)
            db.session.commit()
            
        except Exception as e:
            # Don't fail URL resolution if analytics tracking fails
            current_app.logger.error(f"Analytics tracking failed: {e}")
    
    @staticmethod
    def generate_qr_code(code):
        """Generate QR code for short URL."""
        try:
            domain = current_app.config.get('SHORT_DOMAIN')
            url = f"https://{domain}/{code}"
            
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(url)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_data = base64.b64encode(buffer.getvalue()).decode()
            
            return f"data:image/png;base64,{img_data}"
            
        except Exception as e:
            current_app.logger.error(f"QR code generation failed: {e}")
            return None
    
    @staticmethod
    def get_url_analytics(url_id, user_id, days=30):
        """Get analytics for a specific URL."""
        url = URLService.get_url_by_id(url_id, user_id)
        
        # Date range filter
        end_date = datetime.now(timezone.utc)
        start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
        start_date = start_date.replace(day=start_date.day - days) if start_date.day > days else start_date.replace(month=start_date.month - 1, day=30 - (days - start_date.day))
        
        # Basic analytics query
        analytics_query = Analytics.query.filter(
            and_(
                Analytics.url_id == url_id,
                Analytics.clicked_at >= start_date
            )
        )
        
        # Total clicks
        total_clicks = analytics_query.count()
        
        # Clicks by day
        daily_clicks = db.session.query(
            func.date(Analytics.clicked_at).label('date'),
            func.count(Analytics.id).label('clicks')
        ).filter(
            and_(
                Analytics.url_id == url_id,
                Analytics.clicked_at >= start_date
            )
        ).group_by(func.date(Analytics.clicked_at)).all()
        
        # Top countries
        top_countries = db.session.query(
            Analytics.country,
            func.count(Analytics.id).label('clicks')
        ).filter(
            and_(
                Analytics.url_id == url_id,
                Analytics.clicked_at >= start_date,
                Analytics.country.isnot(None)
            )
        ).group_by(Analytics.country).order_by(func.count(Analytics.id).desc()).limit(10).all()
        
        # Top browsers
        top_browsers = db.session.query(
            Analytics.browser,
            func.count(Analytics.id).label('clicks')
        ).filter(
            and_(
                Analytics.url_id == url_id,
                Analytics.clicked_at >= start_date,
                Analytics.browser.isnot(None)
            )
        ).group_by(Analytics.browser).order_by(func.count(Analytics.id).desc()).limit(10).all()
        
        # Top devices
        top_devices = db.session.query(
            Analytics.device_type,
            func.count(Analytics.id).label('clicks')
        ).filter(
            and_(
                Analytics.url_id == url_id,
                Analytics.clicked_at >= start_date,
                Analytics.device_type.isnot(None)
            )
        ).group_by(Analytics.device_type).order_by(func.count(Analytics.id).desc()).limit(10).all()
        
        return {
            'url': url.to_dict(),
            'total_clicks': total_clicks,
            'daily_clicks': [{'date': str(row.date), 'clicks': row.clicks} for row in daily_clicks],
            'top_countries': [{'country': row.country, 'clicks': row.clicks} for row in top_countries],
            'top_browsers': [{'browser': row.browser, 'clicks': row.clicks} for row in top_browsers],
            'top_devices': [{'device': row.device_type, 'clicks': row.clicks} for row in top_devices],
            'period_days': days
        }
    
    @staticmethod
    def get_user_analytics_summary(user_id, days=30):
        """Get analytics summary for all user URLs."""
        # Date range filter
        end_date = datetime.now(timezone.utc)
        start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
        start_date = start_date.replace(day=start_date.day - days) if start_date.day > days else start_date.replace(month=start_date.month - 1, day=30 - (days - start_date.day))
        
        # User's active URLs
        user_urls = URL.query.filter_by(user_id=user_id, is_active=True).all()
        url_ids = [url.id for url in user_urls]
        
        if not url_ids:
            return {
                'total_urls': 0,
                'total_clicks': 0,
                'daily_clicks': [],
                'top_urls': [],
                'period_days': days
            }
        
        # Total clicks
        total_clicks = Analytics.query.filter(
            and_(
                Analytics.url_id.in_(url_ids),
                Analytics.clicked_at >= start_date
            )
        ).count()
        
        # Daily clicks
        daily_clicks = db.session.query(
            func.date(Analytics.clicked_at).label('date'),
            func.count(Analytics.id).label('clicks')
        ).filter(
            and_(
                Analytics.url_id.in_(url_ids),
                Analytics.clicked_at >= start_date
            )
        ).group_by(func.date(Analytics.clicked_at)).all()
        
        # Top performing URLs
        top_urls = db.session.query(
            URL.id,
            URL.short_code,
            URL.custom_alias,
            URL.original_url,
            URL.title,
            func.count(Analytics.id).label('clicks')
        ).join(Analytics).filter(
            and_(
                URL.user_id == user_id,
                URL.is_active == True,
                Analytics.clicked_at >= start_date
            )
        ).group_by(URL.id).order_by(func.count(Analytics.id).desc()).limit(10).all()
        
        return {
            'total_urls': len(user_urls),
            'total_clicks': total_clicks,
            'daily_clicks': [{'date': str(row.date), 'clicks': row.clicks} for row in daily_clicks],
            'top_urls': [{
                'id': row.id,
                'short_code': row.short_code,
                'custom_alias': row.custom_alias,
                'original_url': row.original_url,
                'title': row.title,
                'clicks': row.clicks
            } for row in top_urls],
            'period_days': days
        }
    
    @staticmethod
    def resolve_short_code(short_code, analytics_data=None):
        """Resolve short code to original URL and track analytics."""
        # Find URL by short code or custom alias
        url = URL.query.filter(
            or_(
                URL.short_code == short_code,
                URL.custom_alias == short_code
            )
        ).first()
        
        if not url:
            raise ResourceNotFoundError("Short URL not found")
        
        # Check if URL is active
        if not url.is_active:
            raise ValidationError("This URL has been disabled")
        
        # Check if URL is expired
        if url.is_expired:
            raise ValidationError("This URL has expired")
        
        # Track analytics if provided
        if analytics_data:
            analytics = Analytics(
                url_id=url.id,
                ip_address=analytics_data.get('ip_address'),
                user_agent=analytics_data.get('user_agent'),
                referer=analytics_data.get('referer'),
                device_type=analytics_data.get('device_type'),
                browser=analytics_data.get('browser'),
                clicked_at=datetime.now(timezone.utc)
            )
            db.session.add(analytics)
            db.session.commit()
        
        return {
            'original_url': url.original_url,
            'title': url.title,
            'url_id': url.id
        }
    
    @staticmethod
    def get_public_url_info(short_code):
        """Get public information about a URL without tracking."""
        url = URL.query.filter(
            or_(
                URL.short_code == short_code,
                URL.custom_alias == short_code
            )
        ).first()
        
        if not url:
            raise ResourceNotFoundError("Short URL not found")
        
        if not url.is_active:
            raise ValidationError("This URL has been disabled")
        
        if url.is_expired:
            raise ValidationError("This URL has expired")
        
        return {
            'short_code': short_code,
            'title': url.title,
            'description': url.description,
            'created_at': url.created_at.isoformat(),
            'click_count': url.click_count,
            'is_active': url.is_active
        }
    
    @staticmethod
    def get_public_url_stats(short_code):
        """Get public statistics for a URL."""
        url = URL.query.filter(
            or_(
                URL.short_code == short_code,
                URL.custom_alias == short_code
            )
        ).first()
        
        if not url:
            raise ResourceNotFoundError("Short URL not found")
        
        if not url.is_active:
            raise ValidationError("This URL has been disabled")
        
        if url.is_expired:
            raise ValidationError("This URL has expired")
        
        # Get basic statistics (last 30 days)
        end_date = datetime.now(timezone.utc)
        start_date = end_date.replace(day=end_date.day - 30) if end_date.day > 30 else end_date.replace(month=end_date.month - 1, day=30 - (30 - end_date.day))
        
        recent_clicks = Analytics.query.filter(
            and_(
                Analytics.url_id == url.id,
                Analytics.clicked_at >= start_date
            )
        ).count()
        
        return {
            'short_code': short_code,
            'total_clicks': url.click_count,
            'recent_clicks': recent_clicks,
            'created_at': url.created_at.isoformat()
        }
    
    @staticmethod
    def get_batch_url_info(short_codes):
        """Get information for multiple URLs in batch."""
        results = {}
        
        for short_code in short_codes:
            try:
                url_info = URLService.get_public_url_info(short_code)
                results[short_code] = {
                    'success': True,
                    'data': url_info
                }
            except (ResourceNotFoundError, ValidationError) as e:
                results[short_code] = {
                    'success': False,
                    'error': e.message,
                    'error_code': e.error_code
                }
            except Exception as e:
                current_app.logger.error(f"Batch URL info error for {short_code}: {e}")
                results[short_code] = {
                    'success': False,
                    'error': 'Failed to retrieve URL information',
                    'error_code': 'URL_INFO_FAILED'
                }
        
        return results
    
    @staticmethod
    def create_temporary_url(original_url, client_ip, expires_in_minutes=15):
        """Create a temporary URL that expires after specified minutes."""
        try:
            # Validate URL
            URLService.validate_url(original_url)
            
            # Generate unique short code (try multiple times if needed)
            max_retries = 5
            for retry in range(max_retries):
                try:
                    # Generate short code with increasing length on retries
                    short_code = URLService.generate_short_code(length=6 + retry)
                    
                    # Calculate expiration time
                    from datetime import timedelta
                    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
                    
                    # Create temporary URL entry (no user association)
                    temp_url = URL(
                        user_id=None,  # No user for temporary URLs
                        original_url=original_url,
                        short_code=short_code,
                        title=f"Temporary URL ({expires_in_minutes}min)",
                        description=f"Temporary URL created from IP {client_ip}",
                        expires_at=expires_at,
                        is_active=True
                    )
                    
                    db.session.add(temp_url)
                    db.session.commit()
                    
                    current_app.logger.info(f"Temporary URL created: {short_code} -> {original_url}")
                    
                    return {
                        'id': temp_url.id,
                        'short_code': short_code,
                        'original_url': original_url,
                        'expires_at': expires_at.isoformat(),
                        'created_at': temp_url.created_at.isoformat()
                    }
                    
                except IntegrityError:
                    db.session.rollback()
                    if retry == max_retries - 1:
                        current_app.logger.error(f"Failed to create temporary URL after {max_retries} retries: {original_url}")
                        raise ValidationError("Unable to generate unique short code")
                    # Continue to next retry with longer code
                    continue
            
        except ValidationError:
            raise
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Temporary URL creation failed: {e}")
            raise ValidationError("Failed to create temporary URL")
    
    @staticmethod
    def generate_public_qr_code(short_code, size=200, format_type='png', base_url=''):
        """Generate QR code for public URLs."""
        try:
            # Verify URL exists and is active
            url = URL.query.filter(
                or_(
                    URL.short_code == short_code,
                    URL.custom_alias == short_code
                )
            ).first()
            
            if not url:
                raise ResourceNotFoundError("Short URL not found")
            
            if not url.is_active:
                raise ValidationError("This URL has been disabled")
            
            if url.is_expired:
                raise ValidationError("This URL has expired")
            
            # Construct full URL
            full_url = f"{base_url}/{short_code}"
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=max(1, size // 25),  # Adjust box size based on requested size
                border=4,
            )
            qr.add_data(full_url)
            qr.make(fit=True)
            
            if format_type == 'svg':
                # Generate SVG format
                from qrcode.image.svg import SvgPathImage
                img = qr.make_image(image_factory=SvgPathImage)
                svg_buffer = io.BytesIO()
                img.save(svg_buffer)
                return svg_buffer.getvalue()
            else:
                # Generate PNG format
                img = qr.make_image(fill_color="black", back_color="white")
                
                # Resize to requested size
                if img.size[0] != size:
                    img = img.resize((size, size))
                
                img_buffer = io.BytesIO()
                img.save(img_buffer, format='PNG')
                return img_buffer.getvalue()
                
        except Exception as e:
            current_app.logger.error(f"QR code generation failed: {e}")
            raise ValidationError("Failed to generate QR code")
    
    @staticmethod
    def cleanup_expired_urls():
        """Clean up expired URLs (for scheduled tasks)."""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Find expired URLs
            expired_urls = URL.query.filter(
                and_(
                    URL.expires_at.isnot(None),
                    URL.expires_at <= current_time,
                    URL.is_active == True
                )
            ).all()
            
            # Deactivate expired URLs
            for url in expired_urls:
                url.is_active = False
            
            db.session.commit()
            
            current_app.logger.info(f"Cleaned up {len(expired_urls)} expired URLs")
            
            return len(expired_urls)
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"URL cleanup failed: {e}")
            return 0
