"""
Custom exceptions for the Io URL Shortener application.
Provides specific exception types for better error handling and user feedback.
"""


class IoError(Exception):
    """Base exception class for all Io application errors."""
    
    def __init__(self, message, status_code=500, error_code=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
    
    def to_dict(self):
        """Convert exception to dictionary for JSON responses."""
        response = {
            'error': True,
            'message': self.message,
            'status_code': self.status_code
        }
        
        if self.error_code:
            response['error_code'] = self.error_code
        
        return response


class ValidationError(IoError):
    """Exception raised for validation errors."""
    
    def __init__(self, message, field=None):
        super().__init__(message, status_code=400, error_code='VALIDATION_ERROR')
        self.field = field
    
    def to_dict(self):
        response = super().to_dict()
        if self.field:
            response['field'] = self.field
        return response


class AuthenticationError(IoError):
    """Exception raised for authentication errors."""
    
    def __init__(self, message="Authentication failed"):
        super().__init__(message, status_code=401, error_code='AUTHENTICATION_ERROR')


class AuthorizationError(IoError):
    """Exception raised for authorization errors."""
    
    def __init__(self, message="Access denied"):
        super().__init__(message, status_code=403, error_code='AUTHORIZATION_ERROR')


class ResourceNotFoundError(IoError):
    """Exception raised when a requested resource is not found."""
    
    def __init__(self, message="Resource not found", resource_type=None):
        super().__init__(message, status_code=404, error_code='RESOURCE_NOT_FOUND')
        self.resource_type = resource_type
    
    def to_dict(self):
        response = super().to_dict()
        if self.resource_type:
            response['resource_type'] = self.resource_type
        return response


class ConflictError(IoError):
    """Exception raised for resource conflicts."""
    
    def __init__(self, message="Resource conflict"):
        super().__init__(message, status_code=409, error_code='CONFLICT_ERROR')


class RateLimitExceededError(IoError):
    """Exception raised when rate limits are exceeded."""
    
    def __init__(self, message="Rate limit exceeded", retry_after=None):
        super().__init__(message, status_code=429, error_code='RATE_LIMIT_EXCEEDED')
        self.retry_after = retry_after
    
    def to_dict(self):
        response = super().to_dict()
        if self.retry_after:
            response['retry_after'] = self.retry_after
        return response


class ExternalServiceError(IoError):
    """Exception raised for external service errors."""
    
    def __init__(self, message="External service error", service_name=None):
        super().__init__(message, status_code=502, error_code='EXTERNAL_SERVICE_ERROR')
        self.service_name = service_name
    
    def to_dict(self):
        response = super().to_dict()
        if self.service_name:
            response['service_name'] = self.service_name
        return response


class DatabaseError(IoError):
    """Exception raised for database operation errors."""
    
    def __init__(self, message="Database operation failed"):
        super().__init__(message, status_code=500, error_code='DATABASE_ERROR')


class ConfigurationError(IoError):
    """Exception raised for configuration errors."""
    
    def __init__(self, message="Configuration error"):
        super().__init__(message, status_code=500, error_code='CONFIGURATION_ERROR')


class SecurityError(IoError):
    """Exception raised for security-related errors."""
    
    def __init__(self, message="Security error"):
        super().__init__(message, status_code=403, error_code='SECURITY_ERROR')


class URLValidationError(ValidationError):
    """Exception raised for URL validation errors."""
    
    def __init__(self, message="Invalid URL"):
        super().__init__(message, field='url')
        self.error_code = 'URL_VALIDATION_ERROR'


class ShortCodeError(ValidationError):
    """Exception raised for short code errors."""
    
    def __init__(self, message="Invalid short code"):
        super().__init__(message, field='short_code')
        self.error_code = 'SHORT_CODE_ERROR'


class ApiKeyError(AuthenticationError):
    """Exception raised for API key errors."""
    
    def __init__(self, message="Invalid API key"):
        super().__init__(message)
        self.error_code = 'API_KEY_ERROR'


class TokenError(AuthenticationError):
    """Exception raised for JWT token errors."""
    
    def __init__(self, message="Invalid token"):
        super().__init__(message)
        self.error_code = 'TOKEN_ERROR'


class PermissionError(AuthorizationError):
    """Exception raised for permission errors."""
    
    def __init__(self, message="Insufficient permissions", required_permission=None):
        super().__init__(message)
        self.required_permission = required_permission
        self.error_code = 'PERMISSION_ERROR'
    
    def to_dict(self):
        response = super().to_dict()
        if self.required_permission:
            response['required_permission'] = self.required_permission
        return response


class QuotaExceededError(RateLimitExceededError):
    """Exception raised when user quota is exceeded."""
    
    def __init__(self, message="Quota exceeded", quota_type=None, limit=None, current=None):
        super().__init__(message)
        self.quota_type = quota_type
        self.limit = limit
        self.current = current
        self.error_code = 'QUOTA_EXCEEDED'
    
    def to_dict(self):
        response = super().to_dict()
        if self.quota_type:
            response['quota_type'] = self.quota_type
        if self.limit is not None:
            response['limit'] = self.limit
        if self.current is not None:
            response['current'] = self.current
        return response
