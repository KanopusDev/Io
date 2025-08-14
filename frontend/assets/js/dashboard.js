/**
 * Dashboard JavaScript Module
 * Handles dashboard functionality, analytics, and link management
 * Version: 2.0.1 - Fixed API calls
 */

class Dashboard {
    constructor() {
        this.apiClient = new APIClient();

        this.charts = {};
        this.auth = new AuthManager();
        this.currentUser = null;
        this.links = [];
        this.stats = {};
        
        this.init();
    }

    async init() {
        try {
            // Check authentication
            if (!this.auth.isAuthenticated()) {
                window.location.href = '/';
                return;
            }

            // Initialize components
            this.setupEventListeners();
            this.setupNavigation();
            
            // Load user data
            await this.loadUserData();
            
            // Load dashboard data
            await this.loadDashboardData();
            
            // Initialize charts
            this.initializeCharts();
            
        } catch (error) {
            console.error('Failed to initialize dashboard:', error);
            this.showToast('Failed to load dashboard', 'error');
        }
    }

    setupEventListeners() {
        // User menu
        const userMenuBtn = document.getElementById('userMenuBtn');
        const userMenu = document.getElementById('userMenu');
        
        if (userMenuBtn && userMenu) {
            userMenuBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                userMenu.classList.toggle('hidden');
            });

            // Close menu when clicking outside
            document.addEventListener('click', () => {
                userMenu.classList.add('hidden');
            });
        }

        // Mobile menu
        const mobileMenuBtn = document.getElementById('mobileMenuBtn');
        const mobileMenu = document.getElementById('mobileMenu');
        
        if (mobileMenuBtn && mobileMenu) {
            mobileMenuBtn.addEventListener('click', () => {
                mobileMenu.classList.toggle('hidden');
            });
        }

        // Logout
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
        }

        // Create link modal
        const createLinkBtn = document.getElementById('createLinkBtn');
        const createLinkModal = document.getElementById('createLinkModal');
        const cancelCreateLink = document.getElementById('cancelCreateLink');
        const createLinkForm = document.getElementById('createLinkForm');

        if (createLinkBtn && createLinkModal) {
            createLinkBtn.addEventListener('click', () => this.showCreateLinkModal());
        }

        if (cancelCreateLink && createLinkModal) {
            cancelCreateLink.addEventListener('click', () => this.hideCreateLinkModal());
            
            // Close modal when clicking backdrop
            createLinkModal.addEventListener('click', (e) => {
                if (e.target === createLinkModal) {
                    this.hideCreateLinkModal();
                }
            });
        }

        if (createLinkForm) {
            createLinkForm.addEventListener('submit', (e) => this.handleCreateLink(e));
        }

        // Link details modal
        const linkDetailsModal = document.getElementById('linkDetailsModal');
        const closeLinkDetails = document.getElementById('closeLinkDetails');

        if (closeLinkDetails && linkDetailsModal) {
            closeLinkDetails.addEventListener('click', () => this.hideLinkDetailsModal());
            
            linkDetailsModal.addEventListener('click', (e) => {
                if (e.target === linkDetailsModal) {
                    this.hideLinkDetailsModal();
                }
            });
        }

        // Navigation links
        document.querySelectorAll('.nav-link, .mobile-nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = link.getAttribute('href').substring(1);
                this.navigateToSection(section);
            });
        });
    }

    setupNavigation() {
        // Set active navigation based on hash
        const hash = window.location.hash.substring(1) || 'overview';
        this.navigateToSection(hash);

        // Handle browser back/forward
        window.addEventListener('hashchange', () => {
            const section = window.location.hash.substring(1) || 'overview';
            this.navigateToSection(section);
        });
    }

    navigateToSection(section) {
        // Update URL hash
        window.location.hash = section;

        // Update active navigation
        document.querySelectorAll('.nav-link, .mobile-nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${section}`) {
                link.classList.add('active');
            }
        });

        // Hide mobile menu
        const mobileMenu = document.getElementById('mobileMenu');
        if (mobileMenu) {
            mobileMenu.classList.add('hidden');
        }

        // Load section content
        this.loadSectionContent(section);
    }

    async loadSectionContent(section) {
        switch (section) {
            case 'overview':
                await this.loadOverviewContent();
                break;
            case 'links':
                await this.loadLinksContent();
                break;
            case 'analytics':
                await this.loadAnalyticsContent();
                break;
            case 'settings':
                await this.loadSettingsContent();
                break;
            default:
                await this.loadOverviewContent();
        }
    }

    async loadUserData() {
        try {
            const response = await this.apiClient.request('/api/v1/auth/profile');
            this.currentUser = response.data;
            
            // Update user info in UI
            const userInitials = document.getElementById('userInitials');
            const userName = document.getElementById('userName');
            
            if (userInitials && this.currentUser.username) {
                userInitials.textContent = this.currentUser.username.charAt(0).toUpperCase();
            }
            
            if (userName && this.currentUser.username) {
                userName.textContent = this.currentUser.username;
            }
            
        } catch (error) {
            console.error('Failed to load user data:', error);
        }
    }

    async loadDashboardData() {
        try {
            this.showLoading();

            // Load stats and links in parallel
            const [statsResponse, linksResponse] = await Promise.all([
                this.apiClient.request('/api/v1/analytics/dashboard'),
                this.apiClient.request('/api/v1/urls')
            ]);

            this.stats = statsResponse.data;
            this.links = linksResponse.data.items || [];

            this.updateStatsDisplay();
            this.updateLinksTable();

        } catch (error) {
            console.error('Failed to load dashboard data:', error);
            this.showToast('Failed to load dashboard data', 'error');
        } finally {
            this.hideLoading();
        }
    }

    async loadOverviewContent() {
        // Overview is the default view, already loaded
        this.showDashboardContent();
        this.updateChartsVisibility(true);
    }

    async loadLinksContent() {
        this.showDashboardContent();
        this.updateChartsVisibility(false);
        await this.loadLinks();
    }

    async loadAnalyticsContent() {
        this.showDashboardContent();
        this.updateChartsVisibility(true);
        await this.loadAnalytics();
    }
    
    showDashboardContent() {
        // Show original dashboard content
        const statsSection = document.querySelector('.grid.grid-cols-1.md\\:grid-cols-2.lg\\:grid-cols-4');
        const tableSection = document.querySelector('.bg-white.shadow-sm.rounded-lg.border.border-gray-200');
        const settingsSection = document.getElementById('settingsSection');
        
        if (statsSection) statsSection.style.display = 'grid';
        if (tableSection) tableSection.style.display = 'block';
        if (settingsSection) settingsSection.style.display = 'none';
    }

    async loadSettingsContent() {
        this.updateChartsVisibility(false);
        
        // Hide other sections and show settings
        const mainContent = document.querySelector('main');
        if (!mainContent) return;
        
        // Find the stats section and table to hide them
        const statsSection = document.querySelector('.grid.grid-cols-1.md\\:grid-cols-2.lg\\:grid-cols-4');
        const tableSection = document.querySelector('.bg-white.shadow-sm.rounded-lg.border.border-gray-200');
        
        if (statsSection) statsSection.style.display = 'none';
        if (tableSection) tableSection.style.display = 'none';
        
        // Check if settings content already exists
        let settingsSection = document.getElementById('settingsSection');
        if (!settingsSection) {
            settingsSection = document.createElement('div');
            settingsSection.id = 'settingsSection';
            settingsSection.className = 'space-y-6';
            mainContent.appendChild(settingsSection);
        }
        
        // Load user profile data for settings
        try {
            const response = await this.apiClient.request('/api/v1/auth/profile');
            const user = response.data;
            
            settingsSection.innerHTML = `
                <div class="bg-white shadow-sm rounded-lg border border-gray-200">
                    <div class="px-6 py-4 border-b border-gray-200">
                        <h3 class="text-lg font-medium text-gray-900">API Settings</h3>
                        <p class="mt-1 text-sm text-gray-500">Manage your API access for custom endpoints</p>
                    </div>
                    
                    <div class="px-6 py-4 space-y-6">
                        <!-- API Key Section -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Your API Key</label>
                            <div class="flex items-center space-x-3">
                                <input type="password" id="apiKeyDisplay" value="${user.api_key || 'Not generated'}" 
                                       class="flex-1 px-3 py-2 border border-gray-300 rounded-md bg-gray-50" readonly>
                                <button id="toggleApiKey" class="btn-secondary">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                                    </svg>
                                </button>
                                <button id="copyApiKey" class="btn-secondary">Copy</button>
                                <button id="regenerateApiKey" class="btn-danger">Regenerate</button>
                            </div>
                            <p class="mt-2 text-sm text-gray-500">
                                Use this API key to access your custom endpoint: <code class="bg-gray-100 px-2 py-1 rounded">/api/v1/${user.username}/*</code>
                            </p>
                        </div>
                        
                        <!-- Account Status -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Account Status</label>
                            <div class="flex items-center space-x-3">
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${user.is_verified ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}">
                                    ${user.is_verified ? 'Verified' : 'Unverified'}
                                </span>
                                <span class="text-sm text-gray-500">
                                    ${user.is_verified ? 'Unlimited API requests' : 'Limited to 1000 requests/month'}
                                </span>
                            </div>
                        </div>
                        
                        <!-- API Usage -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">API Usage</label>
                            <div class="bg-gray-50 rounded-lg p-4">
                                <div class="flex justify-between items-center mb-2">
                                    <span class="text-sm text-gray-600">Monthly Requests</span>
                                    <span class="text-sm font-medium text-gray-900">${user.monthly_requests || 0}${user.is_verified ? '' : ' / 1000'}</span>
                                </div>
                                ${!user.is_verified ? `
                                <div class="w-full bg-gray-200 rounded-full h-2">
                                    <div class="bg-primary-600 h-2 rounded-full" style="width: ${Math.min((user.monthly_requests || 0) / 10, 100)}%"></div>
                                </div>
                                ` : ''}
                            </div>
                        </div>
                        
                        <!-- API Documentation -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Custom API Endpoints</label>
                            <div class="bg-gray-50 rounded-lg p-4 space-y-2">
                                <div class="text-sm">
                                    <strong>Shorten URL:</strong> <code>POST /api/v1/${user.username}/shorten</code>
                                </div>
                                <div class="text-sm">
                                    <strong>List URLs:</strong> <code>GET /api/v1/${user.username}/urls</code>
                                </div>
                                <div class="text-sm">
                                    <strong>Get Analytics:</strong> <code>GET /api/v1/${user.username}/analytics</code>
                                </div>
                                <p class="text-xs text-gray-500 mt-2">
                                    Include your API key in the <code>X-API-Key</code> header for authentication.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white shadow-sm rounded-lg border border-gray-200">
                    <div class="px-6 py-4 border-b border-gray-200">
                        <h3 class="text-lg font-medium text-gray-900">Account Information</h3>
                    </div>
                    
                    <div class="px-6 py-4 space-y-4">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">Username</label>
                                <p class="text-sm text-gray-900">${user.username}</p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
                                <p class="text-sm text-gray-900">${user.email}</p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">Member Since</label>
                                <p class="text-sm text-gray-900">${this.formatDate(user.created_at)}</p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">Last Updated</label>
                                <p class="text-sm text-gray-900">${this.formatDate(user.updated_at)}</p>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Add event listeners for settings actions
            this.setupSettingsEventListeners();
            
        } catch (error) {
            console.error('Failed to load settings:', error);
            settingsSection.innerHTML = `
                <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
                    <div class="text-center text-red-600">
                        Failed to load settings. Please try again.
                    </div>
                </div>
            `;
        }
    }
    
    setupSettingsEventListeners() {
        // Toggle API key visibility
        const toggleBtn = document.getElementById('toggleApiKey');
        const apiKeyDisplay = document.getElementById('apiKeyDisplay');
        
        if (toggleBtn && apiKeyDisplay) {
            toggleBtn.addEventListener('click', () => {
                if (apiKeyDisplay.type === 'password') {
                    apiKeyDisplay.type = 'text';
                } else {
                    apiKeyDisplay.type = 'password';
                }
            });
        }
        
        // Copy API key
        const copyBtn = document.getElementById('copyApiKey');
        if (copyBtn && apiKeyDisplay) {
            copyBtn.addEventListener('click', async () => {
                try {
                    await this.copyToClipboard(apiKeyDisplay.value);
                    this.showToast('API key copied to clipboard', 'success');
                } catch (error) {
                    this.showToast('Failed to copy API key', 'error');
                }
            });
        }
        
        // Regenerate API key
        const regenerateBtn = document.getElementById('regenerateApiKey');
        if (regenerateBtn) {
            regenerateBtn.addEventListener('click', async () => {
                if (confirm('Are you sure you want to regenerate your API key? This will invalidate the current key.')) {
                    try {
                        const response = await this.apiClient.request('/api/v1/auth/regenerate-api-key', {
                            method: 'POST'
                        });
                        
                        if (response.success) {
                            apiKeyDisplay.value = response.data.api_key;
                            this.showToast('API key regenerated successfully', 'success');
                        }
                    } catch (error) {
                        console.error('Failed to regenerate API key:', error);
                        this.showToast('Failed to regenerate API key', 'error');
                    }
                }
            });
        }
    }

    updateChartsVisibility(show) {
        const chartsSection = document.querySelector('.grid.grid-cols-1.lg\\:grid-cols-2.gap-8.mb-8');
        if (chartsSection) {
            chartsSection.style.display = show ? 'grid' : 'none';
        }
    }

    updateStatsDisplay() {
        const totalLinks = document.getElementById('totalLinks');
        const totalClicks = document.getElementById('totalClicks');
        const clickRate = document.getElementById('clickRate');
        const activeLinks = document.getElementById('activeLinks');

        if (totalLinks) {
            totalLinks.textContent = this.stats.total_urls || '0';
        }

        if (totalClicks) {
            totalClicks.textContent = this.stats.total_clicks || '0';
        }

        if (clickRate) {
            const rate = this.stats.total_urls > 0 
                ? ((this.stats.total_clicks / this.stats.total_urls)).toFixed(1)
                : '0';
            clickRate.textContent = `${rate}/link`;
        }

        if (activeLinks) {
            const active = this.links.filter(link => !link.is_disabled).length;
            activeLinks.textContent = active.toString();
        }
    }

    updateLinksTable() {
        const tableBody = document.getElementById('linksTableBody');
        if (!tableBody) return;

        if (this.links.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="px-6 py-8 text-center text-gray-500">
                        <div class="flex flex-col items-center">
                            <svg class="w-12 h-12 text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
                            </svg>
                            <p class="text-lg font-medium text-gray-900 mb-2">No links yet</p>
                            <p class="text-gray-500">Create your first short link to get started</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tableBody.innerHTML = this.links.slice(0, 10).map(link => `
            <tr class="hover:bg-gray-50 cursor-pointer" onclick="dashboard.showLinkDetails('${link.id}')">
                <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                        <div class="text-sm font-medium text-gray-900">${link.short_code}</div>
                        <button onclick="event.stopPropagation(); dashboard.copyToClipboard('${window.location.origin}/${link.short_code}')" 
                                class="ml-2 text-gray-400 hover:text-gray-600">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                            </svg>
                        </button>
                    </div>
                </td>
                <td class="px-6 py-4">
                    <div class="text-sm text-gray-900 truncate max-w-xs" title="${link.original_url}">
                        ${link.original_url}
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${link.click_count || 0}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${this.formatDate(link.created_at)}
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                        link.is_disabled 
                            ? 'bg-red-100 text-red-800' 
                            : 'bg-green-100 text-green-800'
                    }">
                        ${link.is_disabled ? 'Disabled' : 'Active'}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button onclick="event.stopPropagation(); dashboard.toggleLinkStatus('${link.id}')" 
                            class="text-primary-600 hover:text-primary-900 mr-2">
                        ${link.is_disabled ? 'Enable' : 'Disable'}
                    </button>
                    <button onclick="event.stopPropagation(); dashboard.deleteLink('${link.id}')" 
                            class="text-red-600 hover:text-red-900">
                        Delete
                    </button>
                </td>
            </tr>
        `).join('');
    }

    initializeCharts() {
        this.initializeClicksChart();
        this.initializeTopLinksChart();
    }

    initializeClicksChart() {
        const ctx = document.getElementById('clicksChart');
        if (!ctx) return;

        // Generate sample data for the last 7 days
        const days = [];
        const clicks = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            days.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
            clicks.push(Math.floor(Math.random() * 50) + 10);
        }

        this.charts.clicks = new Chart(ctx, {
            type: 'line',
            data: {
                labels: days,
                datasets: [{
                    label: 'Clicks',
                    data: clicks,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            borderDash: [5, 5]
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    }

    initializeTopLinksChart() {
        const ctx = document.getElementById('topLinksChart');
        if (!ctx) return;

        // Use actual links data or sample data
        const topLinks = this.links
            .sort((a, b) => (b.click_count || 0) - (a.click_count || 0))
            .slice(0, 5);

        const labels = topLinks.length > 0 
            ? topLinks.map(link => link.short_code)
            : ['No data'];
            
        const data = topLinks.length > 0 
            ? topLinks.map(link => link.click_count || 0)
            : [0];

        this.charts.topLinks = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#3b82f6',
                        '#10b981',
                        '#f59e0b',
                        '#ef4444',
                        '#8b5cf6'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    async loadLinks() {
        try {
            const response = await this.apiClient.request('/api/v1/urls');
            this.links = response.urls || [];
            this.updateLinksTable();
        } catch (error) {
            console.error('Failed to load links:', error);
            this.showToast('Failed to load links', 'error');
        }
    }

    async loadAnalytics() {
        try {
            // Load detailed analytics data
            const response = await this.apiClient.request('/api/v1/analytics/summary');
            // Update charts with real data
            // TODO: Implement detailed analytics
        } catch (error) {
            console.error('Failed to load analytics:', error);
        }
    }

    showCreateLinkModal() {
        const modal = document.getElementById('createLinkModal');
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('modal-enter');
            
            setTimeout(() => {
                modal.classList.remove('modal-enter');
                modal.classList.add('modal-enter-active');
            }, 10);

            // Focus on the URL input
            const urlInput = document.getElementById('originalUrl');
            if (urlInput) {
                setTimeout(() => urlInput.focus(), 100);
            }
        }
    }

    hideCreateLinkModal() {
        const modal = document.getElementById('createLinkModal');
        const form = document.getElementById('createLinkForm');
        
        if (modal) {
            modal.classList.add('hidden');
            modal.classList.remove('modal-enter-active');
        }
        
        if (form) {
            form.reset();
        }
    }

    async handleCreateLink(event) {
        event.preventDefault();
        
        const form = event.target;
        const formData = new FormData(form);
        
        const data = {
            original_url: formData.get('original_url'),
            custom_alias: formData.get('custom_alias') || undefined,
            description: formData.get('description') || undefined
        };

        try {
            this.showLoading();
            
            const response = await this.apiClient.request('/api/v1/urls', {
                method: 'POST',
                body: JSON.stringify(data)
            });
            
            this.showToast('Link created successfully!', 'success');
            this.hideCreateLinkModal();
            
            // Refresh data
            await this.loadDashboardData();
            
        } catch (error) {
            console.error('Failed to create link:', error);
            this.showToast(error.message || 'Failed to create link', 'error');
        } finally {
            this.hideLoading();
        }
    }

    async showLinkDetails(linkId) {
        try {
            const response = await this.apiClient.request(`/api/v1/urls/${linkId}`);
            const link = response.url;
            
            const modal = document.getElementById('linkDetailsModal');
            const content = document.getElementById('linkDetailsContent');
            
            if (content) {
                content.innerHTML = `
                    <div class="space-y-6">
                        <div>
                            <h4 class="text-sm font-medium text-gray-500 mb-2">Short URL</h4>
                            <div class="flex items-center space-x-2">
                                <code class="text-lg font-mono bg-gray-100 px-3 py-2 rounded">${window.location.origin}/${link.short_code}</code>
                                <button onclick="dashboard.copyToClipboard('${window.location.origin}/${link.short_code}')" 
                                        class="btn-secondary">Copy</button>
                            </div>
                        </div>
                        
                        <div>
                            <h4 class="text-sm font-medium text-gray-500 mb-2">Original URL</h4>
                            <p class="text-gray-900 break-all">${link.original_url}</p>
                        </div>
                        
                        ${link.description ? `
                            <div>
                                <h4 class="text-sm font-medium text-gray-500 mb-2">Description</h4>
                                <p class="text-gray-900">${link.description}</p>
                            </div>
                        ` : ''}
                        
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <h4 class="text-sm font-medium text-gray-500 mb-2">Total Clicks</h4>
                                <p class="text-2xl font-bold text-gray-900">${link.click_count || 0}</p>
                            </div>
                            <div>
                                <h4 class="text-sm font-medium text-gray-500 mb-2">Created</h4>
                                <p class="text-gray-900">${this.formatDate(link.created_at)}</p>
                            </div>
                        </div>
                        
                        <div class="flex space-x-3 pt-4 border-t border-gray-200">
                            <button onclick="dashboard.toggleLinkStatus('${link.id}')" 
                                    class="btn-secondary">
                                ${link.is_disabled ? 'Enable' : 'Disable'} Link
                            </button>
                            <button onclick="dashboard.deleteLink('${link.id}')" 
                                    class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md">
                                Delete Link
                            </button>
                        </div>
                    </div>
                `;
            }
            
            if (modal) {
                modal.classList.remove('hidden');
            }
            
        } catch (error) {
            console.error('Failed to load link details:', error);
            this.showToast('Failed to load link details', 'error');
        }
    }

    hideLinkDetailsModal() {
        const modal = document.getElementById('linkDetailsModal');
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    async toggleLinkStatus(linkId) {
        try {
            const link = this.links.find(l => l.id === linkId);
            if (!link) return;

            const action = link.is_disabled ? 'enable' : 'disable';
            await this.apiClient.request(`/api/v1/urls/${linkId}/${action}`, {
                method: 'PUT'
            });
            
            this.showToast(`Link ${action}d successfully`, 'success');
            
            // Refresh data
            await this.loadDashboardData();
            this.hideLinkDetailsModal();
            
        } catch (error) {
            console.error('Failed to toggle link status:', error);
            this.showToast('Failed to update link status', 'error');
        }
    }

    async deleteLink(linkId) {
        if (!confirm('Are you sure you want to delete this link? This action cannot be undone.')) {
            return;
        }

        try {
            await this.apiClient.request(`/api/v1/urls/${linkId}`, {
                method: 'DELETE'
            });
            
            this.showToast('Link deleted successfully', 'success');
            
            // Refresh data
            await this.loadDashboardData();
            this.hideLinkDetailsModal();
            
        } catch (error) {
            console.error('Failed to delete link:', error);
            this.showToast('Failed to delete link', 'error');
        }
    }

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast('Copied to clipboard!', 'success');
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            this.showToast('Failed to copy to clipboard', 'error');
        }
    }

    async handleLogout() {
        try {
            await this.auth.logout();
            window.location.href = '/';
        } catch (error) {
            console.error('Logout failed:', error);
            // Force logout even if API call fails
            this.apiClient.logout();
            window.location.href = '/';
        }
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    showLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.remove('hidden');
        }
    }

    hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.add('hidden');
        }
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

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

        container.appendChild(toast);

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
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new Dashboard();
});
