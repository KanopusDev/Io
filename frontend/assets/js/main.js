/**
 * Main JavaScript for Io URL Shortener Landing Page
 * Handles URL shortening, UI interactions, and page functionality
 */

class IoApp {
    constructor() {
        this.apiClient = window.apiClient;
        this.authManager = null;
        this.init();
    }

    /**
     * Initialize the application
     */
    init() {
        // Wait for auth manager to be ready
        this.waitForAuthManager().then(() => {
            this.setupEventListeners();
            this.setupURLShortener();
            this.setupMobileMenu();
            this.setupToast();
            this.setupSmoothScrolling();
        });
    }

    /**
     * Wait for auth manager to be initialized
     */
    waitForAuthManager() {
        return new Promise((resolve) => {
            const checkAuthManager = () => {
                if (window.authManager) {
                    this.authManager = window.authManager;
                    resolve();
                } else {
                    setTimeout(checkAuthManager, 100);
                }
            };
            checkAuthManager();
        });
    }

    /**
     * Set up event listeners
     */
    setupEventListeners() {
        // URL shortener form
        const shortenBtn = document.getElementById('shortenBtn');
        const urlInput = document.getElementById('urlInput');
        
        if (shortenBtn && urlInput) {
            shortenBtn.addEventListener('click', () => this.handleShortenURL());
            urlInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.handleShortenURL();
                }
            });
        }

        // Copy button
        const copyBtn = document.getElementById('copyBtn');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => this.copyToClipboard());
        }

        // Toast close button
        const closeToast = document.getElementById('closeToast');
        if (closeToast) {
            closeToast.addEventListener('click', () => this.hideToast());
        }

        // Auth state change listener
        window.addEventListener('authStateChanged', (e) => {
            this.handleAuthStateChange(e.detail);
        });

        // Page visibility change
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                this.refreshData();
            }
        });
    }

    /**
     * Set up URL shortener functionality
     */
    setupURLShortener() {
        const urlInput = document.getElementById('urlInput');
        
        if (urlInput) {
            // URL validation on input
            urlInput.addEventListener('input', () => {
                this.validateURL(urlInput.value);
            });
        }
    }

    /**
     * Set up mobile menu
     */
    setupMobileMenu() {
        const mobileMenuBtn = document.getElementById('mobileMenuBtn');
        const mobileMenu = document.getElementById('mobileMenu');
        
        if (mobileMenuBtn && mobileMenu) {
            mobileMenuBtn.addEventListener('click', () => {
                mobileMenu.classList.toggle('hidden');
            });
            
            // Close mobile menu when clicking outside
            document.addEventListener('click', (e) => {
                if (!mobileMenuBtn.contains(e.target) && !mobileMenu.contains(e.target)) {
                    mobileMenu.classList.add('hidden');
                }
            });
        }
    }

    /**
     * Set up toast notification system
     */
    setupToast() {
        // Create global toast function
        window.showToast = (message, type = 'info', duration = 5000) => {
            this.showToast(message, type, duration);
        };
    }

    /**
     * Set up smooth scrolling for anchor links
     */
    setupSmoothScrolling() {
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }

    /**
     * Handle URL shortening
     */
    async handleShortenURL() {
        const urlInput = document.getElementById('urlInput');
        const shortenBtn = document.getElementById('shortenBtn');
        const urlResult = document.getElementById('urlResult');
        
        if (!urlInput || !shortenBtn) return;
        
        const url = urlInput.value.trim();
        
        // Validate URL
        if (!this.isValidURL(url)) {
            this.showToast('Please enter a valid URL', 'error');
            this.highlightInput(urlInput, false);
            return;
        }
        
        // Reset input styling
        this.highlightInput(urlInput, true);
        
        // Update button state
        const originalText = shortenBtn.textContent;
        shortenBtn.disabled = true;
        shortenBtn.textContent = 'Shortening...';
        
        try {
            let response;
            
            if (this.authManager.isAuthenticated()) {
                // Use authenticated endpoint for permanent URLs
                response = await this.apiClient.createURL({
                    original_url: url
                });
            } else {
                // Use temporary URL endpoint for demo (15 minutes expiration)
                response = await this.apiClient.shortenURLGuest(url);
            }
            
            if (response.success) {
                this.displayShortenedURL(response.data);
                
                if (!this.authManager.isAuthenticated()) {
                    this.showToast('Temporary URL created (expires in 15 minutes). Sign up for permanent URLs!', 'warning', 8000);
                } else {
                    this.showToast('URL shortened successfully!', 'success');
                }
                
                // Clear input
                urlInput.value = '';
            } else {
                throw new Error(response.message || 'Failed to shorten URL');
            }
            
        } catch (error) {
            console.error('URL shortening error:', error);
            
            if (error.status === 401) {
                this.showToast('Please sign in to create permanent URLs', 'error');
                this.authManager.showLoginModal();
            } else if (error.status === 429) {
                this.showToast('Rate limit exceeded. Please try again later.', 'error');
            } else if (error.status === 400 && error.message.includes('blocked')) {
                this.showToast('This URL is blocked for security reasons', 'error');
            } else {
                this.showToast(this.apiClient.formatError(error), 'error');
            }
            
        } finally {
            // Restore button state
            shortenBtn.disabled = false;
            shortenBtn.textContent = originalText;
        }
    }

    /**
     * Display shortened URL result
     */
    displayShortenedURL(urlData) {
        const urlResult = document.getElementById('urlResult');
        const shortUrlInput = document.getElementById('shortUrl');
        
        if (!urlResult || !shortUrlInput) return;
        
        // Build short URL
        let shortUrl;
        if (urlData.custom_alias) {
            shortUrl = `${window.location.origin}/${urlData.custom_alias}`;
        } else {
            shortUrl = `${window.location.origin}/${urlData.short_code}`;
        }
        
        // Display result
        shortUrlInput.value = shortUrl;
        urlResult.classList.remove('hidden');
        
        // Hide guest message if user is authenticated
        const guestMessage = document.getElementById('guestMessage');
        if (guestMessage && this.authManager.isAuthenticated()) {
            guestMessage.style.display = 'none';
        }
        
        // Auto-select the shortened URL
        setTimeout(() => {
            shortUrlInput.select();
        }, 100);
    }

    /**
     * Copy shortened URL to clipboard
     */
    async copyToClipboard() {
        const shortUrlInput = document.getElementById('shortUrl');
        const copyBtn = document.getElementById('copyBtn');
        
        if (!shortUrlInput || !copyBtn) return;
        
        try {
            await navigator.clipboard.writeText(shortUrlInput.value);
            
            // Update button text temporarily
            const originalText = copyBtn.textContent;
            copyBtn.textContent = 'Copied!';
            copyBtn.classList.add('bg-green-100', 'text-green-700');
            copyBtn.classList.remove('bg-gray-100', 'text-gray-700');
            
            setTimeout(() => {
                copyBtn.textContent = originalText;
                copyBtn.classList.remove('bg-green-100', 'text-green-700');
                copyBtn.classList.add('bg-gray-100', 'text-gray-700');
            }, 2000);
            
            this.showToast('URL copied to clipboard!', 'success', 2000);
            
        } catch (error) {
            console.error('Copy failed:', error);
            
            // Fallback to select and copy
            shortUrlInput.select();
            try {
                document.execCommand('copy');
                this.showToast('URL copied to clipboard!', 'success', 2000);
            } catch (fallbackError) {
                this.showToast('Failed to copy URL. Please copy manually.', 'error');
            }
        }
    }

    /**
     * Validate URL format
     */
    isValidURL(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    }

    /**
     * Validate URL and provide visual feedback
     */
    validateURL(url) {
        const urlInput = document.getElementById('urlInput');
        if (!urlInput) return;
        
        if (url.length === 0) {
            this.highlightInput(urlInput, null);
            return;
        }
        
        const isValid = this.isValidURL(url);
        this.highlightInput(urlInput, isValid);
    }

    /**
     * Highlight input based on validation
     */
    highlightInput(input, isValid) {
        input.classList.remove('border-green-500', 'border-red-500', 'border-gray-300');
        
        if (isValid === true) {
            input.classList.add('border-green-500');
        } else if (isValid === false) {
            input.classList.add('border-red-500');
        } else {
            input.classList.add('border-gray-300');
        }
    }

    /**
     * Show toast notification
     */
    showToast(message, type = 'info', duration = 5000) {
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        const toastIcon = document.getElementById('toastIcon');
        
        if (!toast || !toastMessage || !toastIcon) return;
        
        // Set message
        toastMessage.textContent = message;
        
        // Set icon and colors based on type
        let iconHTML = '';
        let bgClass = 'bg-white';
        let borderClass = 'border-gray-200';
        let textClass = 'text-gray-900';
        
        switch (type) {
            case 'success':
                iconHTML = `<svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                </svg>`;
                borderClass = 'border-green-200';
                bgClass = 'bg-green-50';
                break;
                
            case 'error':
                iconHTML = `<svg class="w-5 h-5 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                </svg>`;
                borderClass = 'border-red-200';
                bgClass = 'bg-red-50';
                break;
                
            case 'warning':
                iconHTML = `<svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                </svg>`;
                borderClass = 'border-yellow-200';
                bgClass = 'bg-yellow-50';
                break;
                
            default:
                iconHTML = `<svg class="w-5 h-5 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                </svg>`;
                borderClass = 'border-blue-200';
                bgClass = 'bg-blue-50';
        }
        
        // Set icon
        toastIcon.innerHTML = iconHTML;
        
        // Update toast classes
        toast.className = `fixed bottom-4 right-4 ${bgClass} border ${borderClass} rounded-lg shadow-lg p-4 transform translate-y-full transition-transform duration-300 z-50`;
        
        // Show toast
        toast.classList.remove('hidden');
        setTimeout(() => {
            toast.classList.remove('translate-y-full');
        }, 10);
        
        // Auto-hide after duration
        if (duration > 0) {
            setTimeout(() => {
                this.hideToast();
            }, duration);
        }
    }

    /**
     * Hide toast notification
     */
    hideToast() {
        const toast = document.getElementById('toast');
        if (toast) {
            toast.classList.add('translate-y-full');
            setTimeout(() => {
                toast.classList.add('hidden');
            }, 300);
        }
    }

    /**
     * Handle authentication state changes
     */
    handleAuthStateChange(authData) {
        const { isAuthenticated, user } = authData;
        
        // Update guest message visibility
        const guestMessage = document.getElementById('guestMessage');
        if (guestMessage) {
            guestMessage.style.display = isAuthenticated ? 'none' : 'block';
        }
        
        // Update any user-specific UI elements
        if (isAuthenticated && user) {
            this.updateUserUI(user);
        }
    }

    /**
     * Update UI elements with user data
     */
    updateUserUI(user) {
        // Update any user-specific elements on the landing page
        const userElements = document.querySelectorAll('[data-user-field]');
        userElements.forEach(el => {
            const field = el.getAttribute('data-user-field');
            if (user[field] !== undefined) {
                el.textContent = user[field];
            }
        });
    }

    /**
     * Refresh data when page becomes visible
     */
    async refreshData() {
        if (this.authManager.isAuthenticated()) {
            try {
                // Refresh user data
                const response = await this.apiClient.getProfile();
                if (response.success) {
                    this.authManager.currentUser = response.data;
                    localStorage.setItem('user_data', JSON.stringify(response.data));
                    this.updateUserUI(response.data);
                }
            } catch (error) {
                console.error('Failed to refresh user data:', error);
            }
        }
    }

    /**
     * Handle page errors gracefully
     */
    handleError(error, context = 'Application') {
        console.error(`${context} error:`, error);
        
        // Don't show error toast for certain types of errors
        if (error.name === 'AbortError' || error.message.includes('aborted')) {
            return;
        }
        
        this.showToast(`${context} error: ${error.message}`, 'error');
    }
}

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    try {
        window.ioApp = new IoApp();
    } catch (error) {
        console.error('Failed to initialize Io App:', error);
    }
});

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    event.preventDefault();
});

// Handle global errors
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
});

// Export for modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = IoApp;
}
