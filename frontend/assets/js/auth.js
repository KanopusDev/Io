/**
 * Authentication module for Io URL Shortener
 * Handles user authentication, registration, and session management
 */

// Global showToast function
window.showToast = function(message, type = 'info') {
    const container = document.getElementById('toastContainer') || document.body;
    
    // Create container if it doesn't exist
    if (!document.getElementById('toastContainer')) {
        const toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'fixed bottom-4 right-4 z-50 space-y-2';
        document.body.appendChild(toastContainer);
    }

    const toast = document.createElement('div');
    toast.className = `flex items-center p-4 mb-4 text-sm rounded-lg shadow-lg transition-all duration-300 transform translate-y-full opacity-0 ${
        type === 'success' ? 'text-green-800 bg-green-50 border border-green-200' :
        type === 'error' ? 'text-red-800 bg-red-50 border border-red-200' :
        type === 'warning' ? 'text-yellow-800 bg-yellow-50 border border-yellow-200' :
        'text-blue-800 bg-blue-50 border border-blue-200'
    }`;

    const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : type === 'warning' ? '⚠' : 'ℹ';

    toast.innerHTML = `
        <span class="inline-flex items-center justify-center w-5 h-5 mr-3 text-xs font-bold rounded-full ${
            type === 'success' ? 'bg-green-200' :
            type === 'error' ? 'bg-red-200' :
            type === 'warning' ? 'bg-yellow-200' :
            'bg-blue-200'
        }">${icon}</span>
        <span class="flex-1">${message}</span>
        <button onclick="this.parentElement.remove()" class="ml-auto text-lg leading-none">&times;</button>
    `;

    document.getElementById('toastContainer').appendChild(toast);

    // Animate in
    setTimeout(() => {
        toast.classList.remove('translate-y-full', 'opacity-0');
        toast.classList.add('translate-y-0', 'opacity-100');
    }, 100);

    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.classList.add('translate-y-full', 'opacity-0');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
};

class AuthManager {
    constructor() {
        this.apiClient = window.apiClient;
        this.currentUser = null;
        this.authState = 'unauthenticated'; // 'unauthenticated', 'authenticated', 'loading'
        
        this.init();
    }

    /**
     * Initialize authentication manager
     */
    init() {
        // Check if user is already authenticated
        if (this.apiClient.isAuthenticated()) {
            this.loadUserData();
        }
        
        // Set up auth state change listeners
        this.setupAuthListeners();
    }

    /**
     * Load user data from localStorage or API
     */
    async loadUserData() {
        const storedUser = this.apiClient.getCurrentUser();
        if (storedUser) {
            this.currentUser = storedUser;
            this.authState = 'authenticated';
            this.updateUI();
            
            // Refresh user data from API in background
            try {
                const response = await this.apiClient.getProfile();
                if (response.success) {
                    this.currentUser = response.data;
                    localStorage.setItem('user_data', JSON.stringify(this.currentUser));
                    this.updateUI();
                }
            } catch (error) {
                console.error('Failed to refresh user data:', error);
                // Don't logout on profile fetch failure
            }
        }
    }

    /**
     * Set up authentication event listeners
     */
    setupAuthListeners() {
        // Login button events
        document.querySelectorAll('#loginBtn, #mobileLoginBtn').forEach(btn => {
            btn.addEventListener('click', () => this.showLoginModal());
        });

        // Register button events
        document.querySelectorAll('#registerBtn, #mobileRegisterBtn, #heroGetStartedBtn, #ctaRegisterBtn').forEach(btn => {
            btn.addEventListener('click', () => this.showRegisterModal());
        });

        // Modal close events
        document.getElementById('closeLoginModal')?.addEventListener('click', () => this.hideLoginModal());
        document.getElementById('closeRegisterModal')?.addEventListener('click', () => this.hideRegisterModal());

        // Modal switch events
        document.getElementById('switchToRegister')?.addEventListener('click', () => {
            this.hideLoginModal();
            this.showRegisterModal();
        });

        document.getElementById('switchToLogin')?.addEventListener('click', () => {
            this.hideRegisterModal();
            this.showLoginModal();
        });

        // Form submit events
        document.getElementById('loginForm')?.addEventListener('submit', (e) => this.handleLogin(e));
        document.getElementById('registerForm')?.addEventListener('submit', (e) => this.handleRegister(e));

        // Close modals on outside click
        document.getElementById('loginModal')?.addEventListener('click', (e) => {
            if (e.target.id === 'loginModal') {
                this.hideLoginModal();
            }
        });

        document.getElementById('registerModal')?.addEventListener('click', (e) => {
            if (e.target.id === 'registerModal') {
                this.hideRegisterModal();
            }
        });

        // Escape key to close modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideLoginModal();
                this.hideRegisterModal();
            }
        });
    }

    /**
     * Show login modal
     */
    showLoginModal() {
        const modal = document.getElementById('loginModal');
        if (modal) {
            modal.classList.remove('hidden');
            document.getElementById('loginEmail')?.focus();
        }
    }

    /**
     * Hide login modal
     */
    hideLoginModal() {
        const modal = document.getElementById('loginModal');
        if (modal) {
            modal.classList.add('hidden');
            this.clearLoginForm();
        }
    }

    /**
     * Show register modal
     */
    showRegisterModal() {
        const modal = document.getElementById('registerModal');
        if (modal) {
            modal.classList.remove('hidden');
            document.getElementById('registerUsername')?.focus();
        }
    }

    /**
     * Hide register modal
     */
    hideRegisterModal() {
        const modal = document.getElementById('registerModal');
        if (modal) {
            modal.classList.add('hidden');
            this.clearRegisterForm();
        }
    }

    /**
     * Clear login form
     */
    clearLoginForm() {
        const form = document.getElementById('loginForm');
        if (form) {
            form.reset();
            this.clearFormErrors(form);
        }
    }

    /**
     * Clear register form
     */
    clearRegisterForm() {
        const form = document.getElementById('registerForm');
        if (form) {
            form.reset();
            this.clearFormErrors(form);
        }
    }

    /**
     * Clear form errors
     */
    clearFormErrors(form) {
        form.querySelectorAll('.error-message').forEach(el => el.remove());
        form.querySelectorAll('.border-red-500').forEach(el => {
            el.classList.remove('border-red-500');
            el.classList.add('border-gray-300');
        });
    }

    /**
     * Display form error
     */
    displayFormError(form, fieldName, message) {
        const field = form.querySelector(`#${fieldName}`);
        if (field) {
            field.classList.remove('border-gray-300');
            field.classList.add('border-red-500');
            
            // Remove existing error message
            const existingError = field.parentNode.querySelector('.error-message');
            if (existingError) {
                existingError.remove();
            }
            
            // Add new error message
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-message text-red-500 text-xs mt-1';
            errorDiv.textContent = message;
            field.parentNode.appendChild(errorDiv);
        }
    }

    /**
     * Handle login form submission
     */
    async handleLogin(event) {
        event.preventDefault();
        
        const form = event.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        
        // Clear previous errors
        this.clearFormErrors(form);
        
        // Get form data
        const formData = new FormData(form);
        const credentials = {
            login: formData.get('loginEmail') || document.getElementById('loginEmail').value,
            password: formData.get('loginPassword') || document.getElementById('loginPassword').value
        };

        // Validate form
        let hasErrors = false;
        
        if (!credentials.login.trim()) {
            this.displayFormError(form, 'loginEmail', 'Email or username is required');
            hasErrors = true;
        }
        
        if (!credentials.password) {
            this.displayFormError(form, 'loginPassword', 'Password is required');
            hasErrors = true;
        }

        if (hasErrors) {
            return;
        }

        try {
            // Update button state
            submitBtn.disabled = true;
            submitBtn.textContent = 'Signing In...';
            
            const response = await this.apiClient.login(credentials);
            
            if (response.success) {
                this.currentUser = response.data.user;
                this.authState = 'authenticated';
                
                // Close modal and update UI
                this.hideLoginModal();
                this.updateUI();
                
                // Show success message
                window.showToast('Welcome back! You have been signed in successfully.', 'success');
                
                // Redirect based on user role and current page
                this.handlePostLoginRedirect();
                
            } else {
                throw new Error(response.message || 'Login failed');
            }
            
        } catch (error) {
            console.error('Login error:', error);
            
            if (error.status === 401) {
                this.displayFormError(form, 'loginPassword', 'Invalid email/username or password');
            } else if (error.status === 429) {
                window.showToast('Too many login attempts. Please try again later.', 'error');
            } else if (error.errors) {
                // Handle validation errors
                Object.entries(error.errors).forEach(([field, messages]) => {
                    const fieldName = field === 'login' ? 'loginEmail' : `login${field.charAt(0).toUpperCase() + field.slice(1)}`;
                    this.displayFormError(form, fieldName, Array.isArray(messages) ? messages[0] : messages);
                });
            } else {
                window.showToast(this.apiClient.formatError(error), 'error');
            }
            
        } finally {
            // Restore button state
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }

    /**
     * Handle register form submission
     */
    async handleRegister(event) {
        event.preventDefault();
        
        const form = event.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        
        // Clear previous errors
        this.clearFormErrors(form);
        
        // Get form data
        const formData = new FormData(form);
        const userData = {
            username: formData.get('registerUsername') || document.getElementById('registerUsername').value,
            email: formData.get('registerEmail') || document.getElementById('registerEmail').value,
            password: formData.get('registerPassword') || document.getElementById('registerPassword').value
        };
        
        const confirmPassword = formData.get('confirmPassword') || document.getElementById('confirmPassword').value;
        const agreeTerms = document.getElementById('agreeTerms').checked;

        // Client-side validation
        let hasErrors = false;
        
        if (!userData.username.trim()) {
            this.displayFormError(form, 'registerUsername', 'Username is required');
            hasErrors = true;
        } else if (userData.username.length < 3) {
            this.displayFormError(form, 'registerUsername', 'Username must be at least 3 characters');
            hasErrors = true;
        } else if (!/^[a-zA-Z0-9_-]+$/.test(userData.username)) {
            this.displayFormError(form, 'registerUsername', 'Username can only contain letters, numbers, hyphens, and underscores');
            hasErrors = true;
        }
        
        if (!userData.email.trim()) {
            this.displayFormError(form, 'registerEmail', 'Email is required');
            hasErrors = true;
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userData.email)) {
            this.displayFormError(form, 'registerEmail', 'Please enter a valid email address');
            hasErrors = true;
        }
        
        if (!userData.password) {
            this.displayFormError(form, 'registerPassword', 'Password is required');
            hasErrors = true;
        } else if (userData.password.length < 8) {
            this.displayFormError(form, 'registerPassword', 'Password must be at least 8 characters');
            hasErrors = true;
        } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/.test(userData.password)) {
            this.displayFormError(form, 'registerPassword', 'Password must contain uppercase, lowercase, number, and special character');
            hasErrors = true;
        }
        
        if (!confirmPassword) {
            this.displayFormError(form, 'confirmPassword', 'Please confirm your password');
            hasErrors = true;
        } else if (userData.password !== confirmPassword) {
            this.displayFormError(form, 'confirmPassword', 'Passwords do not match');
            hasErrors = true;
        }
        
        if (!agreeTerms) {
            window.showToast('You must agree to the Terms of Service and Privacy Policy', 'error');
            hasErrors = true;
        }

        if (hasErrors) {
            return;
        }

        try {
            // Update button state
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating Account...';
            
            const response = await this.apiClient.register(userData);
            
            if (response.success) {
                // Close modal
                this.hideRegisterModal();
                
                // Show success message
                window.showToast('Account created successfully! Please sign in to continue.', 'success');
                
                // Show login modal
                setTimeout(() => {
                    this.showLoginModal();
                    // Pre-fill email
                    document.getElementById('loginEmail').value = userData.email;
                }, 1000);
                
            } else {
                throw new Error(response.message || 'Registration failed');
            }
            
        } catch (error) {
            console.error('Registration error:', error);
            
            if (error.status === 409) {
                if (error.message.includes('username')) {
                    this.displayFormError(form, 'registerUsername', 'Username is already taken');
                } else if (error.message.includes('email')) {
                    this.displayFormError(form, 'registerEmail', 'Email is already registered');
                }
            } else if (error.status === 429) {
                window.showToast('Too many registration attempts. Please try again later.', 'error');
            } else if (error.errors) {
                // Handle validation errors
                Object.entries(error.errors).forEach(([field, messages]) => {
                    const fieldName = `register${field.charAt(0).toUpperCase() + field.slice(1)}`;
                    this.displayFormError(form, fieldName, Array.isArray(messages) ? messages[0] : messages);
                });
            } else {
                window.showToast(this.apiClient.formatError(error), 'error');
            }
            
        } finally {
            // Restore button state
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }

    /**
     * Logout user
     */
    async logout() {
        try {
            await this.apiClient.logoutUser();
        } catch (error) {
            console.error('Logout error:', error);
        }
        
        this.currentUser = null;
        this.authState = 'unauthenticated';
        this.updateUI();
        
        window.showToast('You have been signed out successfully.', 'success');
        
        // Redirect to home page if on protected page
        if (window.location.pathname !== '/' && window.location.pathname !== '/index.html') {
            setTimeout(() => {
                window.location.href = '/';
            }, 1000);
        }
    }

    /**
     * Update UI based on authentication state
     */
    updateUI() {
        const isAuthenticated = this.authState === 'authenticated';
        
        // Update navigation buttons
        const loginBtns = document.querySelectorAll('#loginBtn, #mobileLoginBtn');
        const registerBtns = document.querySelectorAll('#registerBtn, #mobileRegisterBtn');
        
        loginBtns.forEach(btn => {
            if (isAuthenticated) {
                if (this.isAdmin()) {
                    btn.textContent = 'Admin Dashboard';
                    btn.onclick = () => window.location.href = '/admin.html';
                } else {
                    btn.textContent = 'Dashboard';
                    btn.onclick = () => window.location.href = '/dashboard.html';
                }
            } else {
                btn.textContent = 'Sign In';
                btn.onclick = () => this.showLoginModal();
            }
        });
        
        registerBtns.forEach(btn => {
            if (isAuthenticated) {
                btn.textContent = 'Sign Out';
                btn.onclick = () => this.logout();
                btn.classList.remove('bg-primary-600', 'hover:bg-primary-700');
                btn.classList.add('bg-red-600', 'hover:bg-red-700');
            } else {
                btn.textContent = 'Get Started';
                btn.onclick = () => this.showRegisterModal();
                btn.classList.remove('bg-red-600', 'hover:bg-red-700');
                btn.classList.add('bg-primary-600', 'hover:bg-primary-700');
            }
        });
        
        // Update user info display if elements exist
        if (isAuthenticated && this.currentUser) {
            const userElements = document.querySelectorAll('[data-user-field]');
            userElements.forEach(el => {
                const field = el.getAttribute('data-user-field');
                if (this.currentUser[field] !== undefined) {
                    el.textContent = this.currentUser[field];
                }
            });
            
            // Update verification status
            const verificationElements = document.querySelectorAll('[data-user-verified]');
            verificationElements.forEach(el => {
                if (this.currentUser.is_verified) {
                    el.classList.add('text-green-600');
                    el.classList.remove('text-yellow-600');
                    el.textContent = 'Verified';
                } else {
                    el.classList.add('text-yellow-600');
                    el.classList.remove('text-green-600');
                    el.textContent = 'Unverified';
                }
            });
        }
        
        // Dispatch auth state change event
        window.dispatchEvent(new CustomEvent('authStateChanged', {
            detail: {
                isAuthenticated,
                user: this.currentUser,
                state: this.authState
            }
        }));
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return this.authState === 'authenticated';
    }

    /**
     * Get current user
     */
    getCurrentUser() {
        return this.currentUser;
    }

    /**
     * Check if user is verified
     */
    isVerified() {
        return this.currentUser?.is_verified || false;
    }

    /**
     * Check if user is admin
     */
    isAdmin() {
        return this.currentUser?.is_admin || false;
    }

    /**
     * Require authentication
     */
    requireAuth() {
        if (!this.isAuthenticated()) {
            window.showToast('Please sign in to access this feature.', 'error');
            this.showLoginModal();
            return false;
        }
        return true;
    }

    /**
     * Require verification
     */
    requireVerification() {
        if (!this.requireAuth()) {
            return false;
        }
        
        if (!this.isVerified()) {
            window.showToast('This feature requires account verification. Please contact support.', 'error');
            return false;
        }
        
        return true;
    }

    /**
     * Handle post-login redirect based on user role and current location
     */
    handlePostLoginRedirect() {
        const isOnHomePage = window.location.pathname === '/' || window.location.pathname === '/index.html';
        const isOnLoginPage = window.location.pathname.includes('login');
        
        // Determine redirect target based on user role
        let redirectTarget = null;
        
        if (this.isAdmin()) {
            // Admin users always go to admin dashboard
            redirectTarget = '/admin.html';
            window.showToast('Welcome back, Administrator! Redirecting to admin dashboard...', 'success');
        } else if (this.isVerified()) {
            // Verified users go to dashboard
            redirectTarget = '/dashboard.html';
        } else {
            // Unverified users go to dashboard with verification notice
            redirectTarget = '/dashboard.html';
            setTimeout(() => {
                window.showToast('Your account is not yet verified. Some features may be limited.', 'warning');
            }, 2000);
        }
        
        // Only redirect if on home page or login page
        if ((isOnHomePage || isOnLoginPage) && redirectTarget) {
            setTimeout(() => {
                window.location.href = redirectTarget;
            }, 1500);
        }
        
        // Log the successful login for audit purposes
        this.logUserActivity('login', {
            role: this.isAdmin() ? 'admin' : 'user',
            verified: this.isVerified(),
            redirect_target: redirectTarget
        });
    }

    /**
     * Log user activity for audit and analytics
     */
    logUserActivity(action, details = {}) {
        try {
            const activityLog = {
                timestamp: new Date().toISOString(),
                action: action,
                user_id: this.currentUser?.id,
                username: this.currentUser?.username,
                is_admin: this.isAdmin(),
                is_verified: this.isVerified(),
                page: window.location.pathname,
                user_agent: navigator.userAgent,
                ...details
            };
            
            // Store in session storage for current session tracking
            const sessionLogs = JSON.parse(sessionStorage.getItem('user_activity_logs') || '[]');
            sessionLogs.push(activityLog);
            
            // Keep only last 50 activities
            if (sessionLogs.length > 50) {
                sessionLogs.splice(0, sessionLogs.length - 50);
            }
            
            sessionStorage.setItem('user_activity_logs', JSON.stringify(sessionLogs));
            
            // For admin users, also send to backend for audit logging
            if (this.isAdmin() && action === 'login') {
                this.sendAdminLoginAudit(activityLog);
            }
            
        } catch (error) {
            console.error('Failed to log user activity:', error);
        }
    }

    /**
     * Send admin login audit to backend
     */
    async sendAdminLoginAudit(activityLog) {
        try {
            await this.apiClient.request('POST', '/api/v1/admin/audit-log', {
                action_type: 'admin_login',
                details: JSON.stringify({
                    login_time: activityLog.timestamp,
                    page: activityLog.page,
                    redirect_target: activityLog.redirect_target
                })
            });
        } catch (error) {
            console.error('Failed to send admin login audit:', error);
        }
    }
}

// Initialize authentication manager when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.authManager = new AuthManager();
});

// Export for modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthManager;
}
