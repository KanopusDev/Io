/**
 * API Client for Io URL Shortener
 * Enterprise-grade frontend API client with proper error handling and authentication
 * Version: 2.0.1 - Fixed URL construction
 */

class APIClient {
    constructor() {
        // Configure based on environment
        this.baseURL = this.getAPIBaseURL();
        this.token = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
    }

    /**
     * Get API base URL based on environment
     */
    getAPIBaseURL() {
        // Production API URL
        return 'https://knps.dev';
    }

    /**
     * Make authenticated API request
     */
    async request(methodOrEndpoint, endpointOrOptions = {}, options = {}) {
        let method, endpoint, config;
        
        // Handle both calling patterns:
        // 1. request(endpoint, options) - legacy
        // 2. request(method, endpoint, options) - new
        if (typeof endpointOrOptions === 'string') {
            // New pattern: request(method, endpoint, options)
            method = methodOrEndpoint.toUpperCase();
            endpoint = endpointOrOptions;
            config = options;
        } else {
            // Legacy pattern: request(endpoint, options)
            method = 'GET';
            endpoint = methodOrEndpoint;
            config = endpointOrOptions;
        }
        
        const url = `${this.baseURL}${endpoint}`;
        
        const requestConfig = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...config.headers
            },
            ...config
        };

        // Handle body data - if body is an object, stringify it
        if (config.body && typeof config.body === 'object') {
            requestConfig.body = JSON.stringify(config.body);
        } else if (config.data) {
            // Support both 'body' and 'data' properties
            requestConfig.body = JSON.stringify(config.data);
        }

        // Add authentication token if available
        if (this.token && !requestConfig.headers.Authorization) {
            requestConfig.headers.Authorization = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, requestConfig);
            
            // Handle different response types
            let data;
            const contentType = response.headers.get('content-type');
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                data = await response.text();
            }

            // Handle authentication errors
            if (response.status === 401 && this.refreshToken) {
                const refreshed = await this.refreshAccessToken();
                if (refreshed) {
                    // Retry the original request with new token
                    requestConfig.headers.Authorization = `Bearer ${this.token}`;
                    const retryResponse = await fetch(url, requestConfig);
                    
                    if (retryResponse.headers.get('content-type')?.includes('application/json')) {
                        return await retryResponse.json();
                    } else {
                        return await retryResponse.text();
                    }
                } else {
                    // Refresh failed, redirect to login
                    this.logout();
                    throw new Error('Session expired. Please log in again.');
                }
            }

            if (!response.ok) {
                throw new APIError(
                    data.message || `HTTP ${response.status}`,
                    response.status,
                    data.error_code,
                    data.errors
                );
            }

            return data;
        } catch (error) {
            if (error instanceof APIError) {
                throw error;
            }
            
            // Network or other errors
            console.error('API Request failed:', error);
            throw new APIError('Network error. Please check your connection.', 0);
        }
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken() {
        if (!this.refreshToken) {
            return false;
        }

        try {
            const response = await fetch(`${this.baseURL}/api/v1/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.refreshToken}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.setAuthTokens(data.access_token, data.refresh_token);
                return true;
            } else {
                this.logout();
                return false;
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.logout();
            return false;
        }
    }

    /**
     * Set authentication tokens
     */
    setAuthTokens(accessToken, refreshToken) {
        this.token = accessToken;
        this.refreshToken = refreshToken;
        
        localStorage.setItem('access_token', accessToken);
        if (refreshToken) {
            localStorage.setItem('refresh_token', refreshToken);
        }
    }

    /**
     * Clear authentication tokens
     */
    logout() {
        this.token = null;
        this.refreshToken = null;
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user_data');
        
        // Redirect to home page
        if (window.location.pathname !== '/') {
            window.location.href = '/';
        }
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.token;
    }

    // Authentication endpoints
    async register(userData) {
        return this.request('/api/v1/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    async login(credentials) {
        const response = await this.request('/api/v1/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials)
        });
        
        if (response.success) {
            this.setAuthTokens(response.data.access_token, response.data.refresh_token);
            localStorage.setItem('user_data', JSON.stringify(response.data.user));
        }
        
        return response;
    }

    async logoutUser() {
        try {
            await this.request('/api/v1/auth/logout', {
                method: 'POST'
            });
        } catch (error) {
            console.error('Logout API call failed:', error);
        } finally {
            this.logout();
        }
    }

    async getProfile() {
        return this.request('/api/v1/auth/profile');
    }

    async updateProfile(profileData) {
        return this.request('/api/v1/auth/profile', {
            method: 'PUT',
            body: JSON.stringify(profileData)
        });
    }

    async changePassword(passwordData) {
        return this.request('/api/v1/auth/change-password', {
            method: 'POST',
            body: JSON.stringify(passwordData)
        });
    }

    // URL management endpoints
    async createURL(urlData) {
        return this.request('/api/v1/urls', {
            method: 'POST',
            body: JSON.stringify(urlData)
        });
    }

    async getURLs(page = 1, perPage = 20) {
        return this.request(`/api/v1/urls?page=${page}&per_page=${perPage}`);
    }

    async getURL(urlId) {
        return this.request(`/api/v1/urls/${urlId}`);
    }

    async updateURL(urlId, urlData) {
        return this.request(`/api/v1/urls/${urlId}`, {
            method: 'PUT',
            body: JSON.stringify(urlData)
        });
    }

    async deleteURL(urlId) {
        return this.request(`/api/v1/urls/${urlId}`, {
            method: 'DELETE'
        });
    }

    async getQRCode(urlId) {
        return this.request(`/api/v1/urls/${urlId}/qr`, {
            headers: {
                'Accept': 'image/png'
            }
        });
    }

    // Analytics endpoints
    async getURLAnalytics(urlId, days = 30) {
        return this.request(`/api/v1/analytics/${urlId}?days=${days}`);
    }

    async getAnalyticsSummary(days = 30) {
        return this.request(`/api/v1/analytics/summary?days=${days}`);
    }

    async getDashboardData(days = 30) {
        return this.request(`/api/v1/analytics/dashboard?days=${days}`);
    }

    async exportAnalytics(urlId, days = 30, format = 'json') {
        return this.request(`/api/v1/analytics/export/${urlId}?days=${days}&format=${format}`);
    }

    // Public endpoints (no authentication required)
    async shortenURLGuest(url) {
        return this.request('/api/v1/public/shorten', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ original_url: url })
        });
    }

    async getURLInfo(shortCode) {
        return this.request(`/api/v1/info/${shortCode}`);
    }

    async getURLStats(shortCode) {
        return this.request(`/api/v1/stats/${shortCode}`);
    }

    async getBatchURLInfo(shortCodes) {
        return this.request('/api/v1/batch/info', {
            method: 'POST',
            body: JSON.stringify({ short_codes: shortCodes })
        });
    }

    // Health and status endpoints
    async getHealth() {
        return this.request('/health');
    }

    async getStatus() {
        return this.request('/status');
    }

    // Custom API endpoints (for verified users)
    async getUserURLs(username, page = 1, perPage = 20) {
        return this.request(`/api/v1/${username}/urls?page=${page}&per_page=${perPage}`, {
            headers: {
                'X-API-Key': this.getAPIKey()
            }
        });
    }

    async createUserURL(username, urlData) {
        return this.request(`/api/v1/${username}/shorten`, {
            method: 'POST',
            headers: {
                'X-API-Key': this.getAPIKey()
            },
            body: JSON.stringify(urlData)
        });
    }

    async getUserAnalytics(username, days = 30) {
        return this.request(`/api/v1/${username}/analytics?days=${days}`, {
            headers: {
                'X-API-Key': this.getAPIKey()
            }
        });
    }

    /**
     * Get API key from user data
     */
    getAPIKey() {
        const userData = localStorage.getItem('user_data');
        if (userData) {
            const user = JSON.parse(userData);
            return user.api_key;
        }
        return null;
    }

    /**
     * Get current user data
     */
    getCurrentUser() {
        const userData = localStorage.getItem('user_data');
        return userData ? JSON.parse(userData) : null;
    }

    /**
     * Format error message for display
     */
    formatError(error) {
        if (error instanceof APIError) {
            if (error.errors && typeof error.errors === 'object') {
                // Validation errors
                const messages = Object.values(error.errors).flat();
                return messages.join(', ');
            }
            return error.message;
        }
        return error.message || 'An unexpected error occurred';
    }
}

/**
 * Custom API Error class
 */
class APIError extends Error {
    constructor(message, status = 0, errorCode = null, errors = null) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.errorCode = errorCode;
        this.errors = errors;
    }
}

// Create global API client instance
window.apiClient = new APIClient();

// Export for modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { APIClient, APIError };
}
