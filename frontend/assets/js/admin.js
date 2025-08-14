/**
 * Admin Dashboard JavaScript
 * Enterprise-grade admin interface for Io URL Shortener
 * Handles user management, analytics, and platform administration
 */

class AdminDashboard {
    constructor() {
        this.apiClient = new APIClient();
        this.currentSection = 'dashboard';
        this.currentPage = 1;
        this.itemsPerPage = 20;
        this.charts = {};
        this.currentUserId = null;
        
        this.init();
    }
    
    async init() {
        // Wait for auth manager to be available
        await this.waitForAuthManager();
        
        this.setupEventListeners();
        await this.checkAuthAndLoadDashboard();
    }
    
    async waitForAuthManager() {
        return new Promise((resolve) => {
            const checkAuthManager = () => {
                if (window.authManager) {
                    resolve();
                } else {
                    setTimeout(checkAuthManager, 100);
                }
            };
            checkAuthManager();
        });
    }
    
    setupEventListeners() {
        // Navigation
        document.querySelectorAll('nav a[href^="#"]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const href = e.target.getAttribute('href').substring(1);
                // Convert href to section name (remove -section suffix if present, or add it if needed)
                let section;
                if (href.endsWith('-section')) {
                    section = href.replace('-section', '');
                } else {
                    section = href;
                }
                this.showSection(section);
            });
        });
        
        // Logout
        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.logout();
        });
        
        // User management
        document.getElementById('userSearch').addEventListener('input', 
            this.debounce(() => this.loadUsers(), 300));
        document.getElementById('userStatusFilter').addEventListener('change', () => this.loadUsers());
        document.getElementById('userVerificationFilter').addEventListener('change', () => this.loadUsers());
        
        // URL management
        document.getElementById('urlUserFilter').addEventListener('change', () => this.loadUrls());
        document.getElementById('urlStatusFilter').addEventListener('change', () => this.loadUrls());
        
        // Audit log
        document.getElementById('auditActionFilter').addEventListener('change', () => this.loadAuditLog());
        document.getElementById('auditDateFilter').addEventListener('change', () => this.loadAuditLog());
        
        // Modal events
        document.getElementById('closeUserModal').addEventListener('click', () => this.closeUserModal());
        document.getElementById('verifyUserBtn').addEventListener('click', () => this.verifyUser());
        document.getElementById('suspendUserBtn').addEventListener('click', () => this.suspendUser());
        document.getElementById('unsuspendUserBtn').addEventListener('click', () => this.unsuspendUser());
        
        // Close modal on backdrop click
        document.getElementById('userModal').addEventListener('click', (e) => {
            if (e.target.id === 'userModal') {
                this.closeUserModal();
            }
        });
    }
    
    async checkAuthAndLoadDashboard() {
        console.log('Starting admin dashboard authentication check...');
        
        // Check if user is authenticated
        if (!window.authManager.isAuthenticated()) {
            console.error('User not authenticated');
            window.showToast && window.showToast('Please sign in to access the admin dashboard.', 'error');
            setTimeout(() => {
                window.location.href = '/';
            }, 2000);
            return;
        }
        
        console.log('User is authenticated, checking admin privileges...');
        
        // Check if user has admin privileges
        if (!window.authManager.isAdmin()) {
            console.error('User does not have admin privileges');
            const currentUser = window.authManager.getCurrentUser();
            console.log('Current user data:', currentUser);
            window.showToast && window.showToast('Admin privileges required to access this dashboard.', 'error');
            setTimeout(() => {
                window.location.href = '/dashboard.html';
            }, 2000);
            return;
        }
        
        console.log('User has admin privileges, proceeding with dashboard initialization...');
        
        const token = localStorage.getItem('access_token');
        if (!token) {
            console.error('No authentication token found');
            window.location.href = '/';
            return;
        }
        
        try {
            // Verify admin access with backend
            const response = await this.apiClient.request('GET', '/api/v1/admin/verify-access');
            
            if (response.success) {
                // Update admin info display
                const adminData = response.data;
                document.getElementById('adminUsername').textContent = adminData.username;
                
                // Show verification status
                const verificationStatus = adminData.is_verified ? 
                    '<span class="text-green-600 font-medium">✓ Verified Admin</span>' : 
                    '<span class="text-yellow-600 font-medium">⚠ Unverified Admin</span>';
                
                document.getElementById('adminStatus').innerHTML = verificationStatus;
                console.log('Backend verification successful');
            } else {
                // If backend verification fails, use auth manager data
                const currentUser = window.authManager.getCurrentUser();
                document.getElementById('adminUsername').textContent = currentUser.username;
                document.getElementById('adminStatus').innerHTML = '<span class="text-blue-600 font-medium">ℹ Admin User</span>';
                console.log('Backend verification failed, using local data');
            }
            
        } catch (error) {
            console.error('Admin auth check failed:', error);
            
            // Fallback to auth manager data without redirecting
            const currentUser = window.authManager.getCurrentUser();
            if (currentUser) {
                document.getElementById('adminUsername').textContent = currentUser.username;
                document.getElementById('adminStatus').innerHTML = '<span class="text-yellow-600 font-medium">⚠ Offline Mode</span>';
                window.showToast && window.showToast('Backend connection failed. Some features may be limited.', 'warning');
                console.log('Using offline mode with user data:', currentUser);
            } else {
                // If no user data, redirect
                localStorage.removeItem('access_token');
                localStorage.removeItem('refresh_token');
                
                window.showToast && window.showToast('Session expired. Please sign in again.', 'error');
                
                setTimeout(() => {
                    window.location.href = '/';
                }, 2000);
                return;
            }
        }
        
        console.log('Initializing dashboard...');
        // Initialize dashboard section by default
        this.showSection('dashboard');
    }
    
    showSection(section) {
        // Hide all sections
        document.querySelectorAll('[id$="-section"]').forEach(el => {
            el.classList.add('hidden');
        });
        
        // Show selected section
        const sectionElement = document.getElementById(`${section}-section`);
        if (sectionElement) {
            sectionElement.classList.remove('hidden');
            this.currentSection = section;
            
            // Load section data
            switch (section) {
                case 'dashboard':
                    this.loadDashboardData();
                    break;
                case 'users':
                    this.loadUsers();
                    break;
                case 'urls':
                    this.loadUrls();
                    break;
                case 'analytics':
                    this.loadAnalytics();
                    break;
                case 'audit':
                    this.loadAuditLog();
                    break;
            }
        } else {
            console.error(`Section not found: ${section}-section`);
        }
        
        // Update navigation
        document.querySelectorAll('nav a').forEach(link => {
            link.classList.remove('text-admin-600', 'bg-admin-50');
            link.classList.add('text-gray-600');
        });
        
        // Find and activate the correct navigation link
        const activeLink = document.querySelector(`nav a[href="#${section}"]`) || 
                          document.querySelector(`nav a[href="#${section}-section"]`);
        if (activeLink) {
            activeLink.classList.remove('text-gray-600');
            activeLink.classList.add('text-admin-600', 'bg-admin-50');
        }
    }
    
    async loadDashboardData() {
        this.showLoading(true);
        
        try {
            const [statistics, analytics] = await Promise.all([
                this.apiClient.request('GET', '/api/v1/admin/statistics'),
                this.apiClient.request('GET', '/api/v1/admin/analytics?days=30')
            ]);
            
            if (statistics.success && analytics.success) {
                this.updateStatistics(statistics.data);
                this.updateCharts(analytics.data);
            } else {
                throw new Error('Failed to load dashboard data from API');
            }
            
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
            this.showError('Failed to load dashboard data. Please check your connection and try again.');
            
            // Initialize empty dashboard
            this.updateStatistics({
                total_users: 0,
                total_urls: 0,
                total_clicks: 0,
                verified_users: 0
            });
        } finally {
            this.showLoading(false);
        }
    }
    
    updateStatistics(stats) {
        document.getElementById('totalUsers').textContent = stats.total_users.toLocaleString();
        document.getElementById('totalUrls').textContent = stats.total_urls.toLocaleString();
        document.getElementById('totalClicks').textContent = stats.total_clicks.toLocaleString();
        document.getElementById('verifiedUsers').textContent = stats.verified_users.toLocaleString();
    }
    
    updateCharts(analytics) {
        if (!analytics || !analytics.daily_registrations || !analytics.daily_url_creation) {
            console.warn('Analytics data incomplete, skipping chart update');
            return;
        }

        // User Registration Chart
        const userCtx = document.getElementById('userRegistrationChart');
        if (!userCtx) {
            console.error('User registration chart canvas not found');
            return;
        }
        
        const userContext = userCtx.getContext('2d');
        if (this.charts.userRegistration) {
            this.charts.userRegistration.destroy();
        }
        
        this.charts.userRegistration = new Chart(userContext, {
            type: 'line',
            data: {
                labels: analytics.daily_registrations.map(item => item.date),
                datasets: [{
                    label: 'New Users',
                    data: analytics.daily_registrations.map(item => item.count),
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // URL Creation Chart
        const urlCtx = document.getElementById('urlCreationChart');
        if (!urlCtx) {
            console.error('URL creation chart canvas not found');
            return;
        }
        
        const urlContext = urlCtx.getContext('2d');
        if (this.charts.urlCreation) {
            this.charts.urlCreation.destroy();
        }
        
        this.charts.urlCreation = new Chart(urlContext, {
            type: 'bar',
            data: {
                labels: analytics.daily_url_creation.map(item => item.date),
                datasets: [{
                    label: 'URLs Created',
                    data: analytics.daily_url_creation.map(item => item.count),
                    backgroundColor: '#10b981'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    async loadUsers() {
        this.showLoading(true);
        
        try {
            const params = new URLSearchParams({
                page: this.currentPage,
                per_page: this.itemsPerPage
            });
            
            const search = document.getElementById('userSearch').value.trim();
            if (search) params.append('search', search);
            
            const status = document.getElementById('userStatusFilter').value;
            if (status) params.append('status', status);
            
            const verified = document.getElementById('userVerificationFilter').value;
            if (verified) params.append('verified', verified);
            
            const response = await this.apiClient.request('GET', `/api/v1/admin/users?${params}`);
            
            if (response.success) {
                this.displayUsers(response.data.users);
                this.updatePagination(response.data.pagination);
            } else {
                throw new Error('Failed to load users from API');
            }
            
        } catch (error) {
            console.error('Failed to load users:', error);
            this.showError('Failed to load users. Please check your connection and try again.');
            
            // Clear the table
            document.getElementById('usersTableBody').innerHTML = '<tr><td colspan="6" class="px-6 py-4 text-center text-gray-500">No users available</td></tr>';
        } finally {
            this.showLoading(false);
        }
    }
    
    displayUsers(users) {
        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = '';
        
        users.forEach(user => {
            const row = document.createElement('tr');
            row.className = 'table-row cursor-pointer';
            row.onclick = () => this.showUserDetails(user.id);
            
            const statusClass = user.is_active ? 'status-active' : 'status-suspended';
            const verifiedClass = user.is_verified ? 'status-verified' : 'status-unverified';
            
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                        <div>
                            <div class="text-sm font-medium text-gray-900">${this.escapeHtml(user.username)}</div>
                            <div class="text-sm text-gray-500">${this.escapeHtml(user.email)}</div>
                        </div>
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="status-badge ${statusClass}">${user.is_active ? 'Active' : 'Suspended'}</span>
                    <span class="status-badge ${verifiedClass} ml-1">${user.is_verified ? 'Verified' : 'Unverified'}</span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${user.url_count || 0}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${user.monthly_requests || 0} / ${user.monthly_limit || (user.is_verified ? 'Unlimited' : '1000')}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${new Date(user.created_at).toLocaleDateString()}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button class="text-admin-600 hover:text-admin-900" onclick="event.stopPropagation(); adminDashboard.showUserDetails(${user.id})">
                        View Details
                    </button>
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    async showUserDetails(userId) {
        try {
            const response = await this.apiClient.request('GET', `/api/v1/admin/users/${userId}`);
            
            if (!response.success) {
                throw new Error('Failed to load user details');
            }
            
            const user = response.data;
            
            document.getElementById('modalUserTitle').textContent = `User: ${user.username}`;
            
            document.getElementById('modalUserContent').innerHTML = `
                <div class="space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Username</label>
                            <p class="mt-1 text-sm text-gray-900">${this.escapeHtml(user.username)}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Email</label>
                            <p class="mt-1 text-sm text-gray-900">${this.escapeHtml(user.email)}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Status</label>
                            <p class="mt-1 text-sm text-gray-900">${user.is_active ? 'Active' : 'Suspended'}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Verification</label>
                            <p class="mt-1 text-sm text-gray-900">${user.is_verified ? 'Verified' : 'Unverified'}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Admin Status</label>
                            <p class="mt-1 text-sm text-gray-900">${user.is_admin ? 'Admin' : 'Regular User'}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">URLs Created</label>
                            <p class="mt-1 text-sm text-gray-900">${user.url_count || 0}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Active URLs</label>
                            <p class="mt-1 text-sm text-gray-900">${user.active_url_count || 0}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Total Clicks</label>
                            <p class="mt-1 text-sm text-gray-900">${user.total_clicks || 0}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Monthly Requests</label>
                            <p class="mt-1 text-sm text-gray-900">${user.monthly_requests || 0} / ${user.monthly_limit || 1000}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Joined</label>
                            <p class="mt-1 text-sm text-gray-900">${new Date(user.created_at).toLocaleString()}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Last Activity</label>
                            <p class="mt-1 text-sm text-gray-900">${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">API Key</label>
                            <p class="mt-1 text-sm text-gray-900 font-mono text-xs">${user.api_key ? `${user.api_key.substring(0, 8)}...` : 'Not generated'}</p>
                        </div>
                    </div>
                    
                    ${user.recent_urls && user.recent_urls.length > 0 ? `
                    <div class="mt-6">
                        <h4 class="text-sm font-medium text-gray-700 mb-2">Recent URLs</h4>
                        <div class="space-y-2">
                            ${user.recent_urls.map(url => `
                                <div class="p-2 bg-gray-50 rounded text-xs">
                                    <div class="font-mono">${this.escapeHtml(url.short_code)}</div>
                                    <div class="text-gray-600 truncate">${this.escapeHtml(url.original_url)}</div>
                                    <div class="text-gray-500">${url.click_count || 0} clicks</div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                    
                    ${user.recent_actions && user.recent_actions.length > 0 ? `
                    <div class="mt-6">
                        <h4 class="text-sm font-medium text-gray-700 mb-2">Recent Admin Actions</h4>
                        <div class="space-y-2">
                            ${user.recent_actions.map(action => `
                                <div class="p-2 bg-gray-50 rounded text-xs">
                                    <div class="font-medium">${this.formatActionType(action.action_type)}</div>
                                    <div class="text-gray-600">${this.escapeHtml(action.details || 'No details')}</div>
                                    <div class="text-gray-500">${new Date(action.created_at).toLocaleString()}</div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                </div>
            `;
            
            // Show/hide action buttons based on user status
            document.getElementById('verifyUserBtn').classList.toggle('hidden', user.is_verified);
            document.getElementById('suspendUserBtn').classList.toggle('hidden', !user.is_active);
            document.getElementById('unsuspendUserBtn').classList.toggle('hidden', user.is_active);
            
            // Store current user ID for actions
            this.currentUserId = userId;
            
            document.getElementById('userModal').classList.remove('hidden');
            
        } catch (error) {
            console.error('Failed to load user details:', error);
            this.showError('Failed to load user details');
        }
    }
    
    closeUserModal() {
        document.getElementById('userModal').classList.add('hidden');
        this.currentUserId = null;
    }
    
    async verifyUser() {
        if (!this.currentUserId) return;
        
        if (!confirm('Are you sure you want to verify this user?')) return;
        
        try {
            const response = await this.apiClient.request('POST', `/api/v1/admin/users/${this.currentUserId}/verify`);
            
            if (response.success) {
                this.showSuccess('User verified successfully');
                this.closeUserModal();
                this.loadUsers();
            } else {
                throw new Error(response.message || 'Verification failed');
            }
        } catch (error) {
            console.error('Failed to verify user:', error);
            this.showError('Failed to verify user: ' + error.message);
        }
    }
    
    async suspendUser() {
        if (!this.currentUserId) return;
        
        const reason = prompt('Please provide a reason for suspension:');
        if (!reason) return;
        
        try {
            const response = await this.apiClient.request('POST', `/api/v1/admin/users/${this.currentUserId}/suspend`, { 
                data: { reason } 
            });
            
            if (response.success) {
                this.showSuccess('User suspended successfully');
                this.closeUserModal();
                this.loadUsers();
            } else {
                throw new Error(response.message || 'Suspension failed');
            }
        } catch (error) {
            console.error('Failed to suspend user:', error);
            this.showError('Failed to suspend user: ' + error.message);
        }
    }
    
    async unsuspendUser() {
        if (!this.currentUserId) return;
        
        if (!confirm('Are you sure you want to unsuspend this user?')) return;
        
        try {
            const response = await this.apiClient.request('POST', `/api/v1/admin/users/${this.currentUserId}/unsuspend`);
            
            if (response.success) {
                this.showSuccess('User unsuspended successfully');
                this.closeUserModal();
                this.loadUsers();
            } else {
                throw new Error(response.message || 'Unsuspension failed');
            }
        } catch (error) {
            console.error('Failed to unsuspend user:', error);
            this.showError('Failed to unsuspend user: ' + error.message);
        }
    }
    
    async loadUrls() {
        this.showLoading(true);
        
        try {
            const params = new URLSearchParams({
                page: this.currentPage,
                per_page: this.itemsPerPage
            });
            
            const userFilter = document.getElementById('urlUserFilter').value;
            if (userFilter) params.append('user_id', userFilter);
            
            const statusFilter = document.getElementById('urlStatusFilter').value;
            if (statusFilter) params.append('status', statusFilter);
            
            const response = await this.apiClient.request('GET', `/api/v1/admin/urls?${params}`);
            
            if (response.success) {
                this.displayUrls(response.data.urls);
                this.updatePagination(response.data.pagination);
            } else {
                throw new Error('Failed to load URLs from API');
            }
            
        } catch (error) {
            console.error('Failed to load URLs:', error);
            this.showError('Failed to load URLs. Please check your connection and try again.');
            
            // Clear the table
            document.getElementById('urlsTableBody').innerHTML = '<tr><td colspan="7" class="px-6 py-4 text-center text-gray-500">No URLs available</td></tr>';
        } finally {
            this.showLoading(false);
        }
    }
    
    displayUrls(urls) {
        const tbody = document.getElementById('urlsTableBody');
        tbody.innerHTML = '';
        
        urls.forEach(url => {
            const row = document.createElement('tr');
            row.className = 'table-row';
            
            const statusClass = url.is_active ? 'status-active' : 'status-suspended';
            
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap">
                    <div class="text-sm font-medium text-gray-900">${this.escapeHtml(url.short_code)}</div>
                </td>
                <td class="px-6 py-4">
                    <div class="text-sm text-gray-900 truncate max-w-xs" title="${this.escapeHtml(url.original_url)}">
                        ${this.escapeHtml(url.original_url)}
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${this.escapeHtml(url.owner ? url.owner.username : 'Anonymous')}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${url.click_count || 0}
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="status-badge ${statusClass}">${url.is_active ? 'Active' : 'Disabled'}</span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${new Date(url.created_at).toLocaleDateString()}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    ${url.is_active ? 
                        `<button class="text-red-600 hover:text-red-900" onclick="adminDashboard.disableUrl(${url.id})">Disable</button>` :
                        `<button class="text-green-600 hover:text-green-900" onclick="adminDashboard.enableUrl(${url.id})">Enable</button>`
                    }
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    async disableUrl(urlId) {
        const reason = prompt('Please provide a reason for disabling this URL:');
        if (!reason) return;
        
        try {
            const response = await this.apiClient.request('POST', `/api/v1/admin/urls/${urlId}/disable`, { 
                data: { reason } 
            });
            
            if (response.success) {
                this.showSuccess('URL disabled successfully');
                this.loadUrls();
            } else {
                throw new Error(response.message || 'Failed to disable URL');
            }
        } catch (error) {
            console.error('Failed to disable URL:', error);
            this.showError('Failed to disable URL: ' + error.message);
        }
    }
    
    async enableUrl(urlId) {
        if (!confirm('Are you sure you want to enable this URL?')) return;
        
        try {
            const response = await this.apiClient.request('POST', `/api/v1/admin/urls/${urlId}/enable`);
            
            if (response.success) {
                this.showSuccess('URL enabled successfully');
                this.loadUrls();
            } else {
                throw new Error(response.message || 'Failed to enable URL');
            }
        } catch (error) {
            console.error('Failed to enable URL:', error);
            this.showError('Failed to enable URL: ' + error.message);
        }
    }
    
    async loadAnalytics() {
        this.showLoading(true);
        
        try {
            const response = await this.apiClient.request('GET', '/api/v1/admin/analytics?days=30');
            
            if (response.success) {
                this.displayAnalyticsCharts(response.data);
            } else {
                throw new Error('Failed to load analytics from API');
            }
            
        } catch (error) {
            console.error('Failed to load analytics:', error);
            this.showError('Failed to load analytics. Please check your connection and try again.');
        } finally {
            this.showLoading(false);
        }
    }
    
    displayAnalyticsCharts(analytics) {
        if (!analytics || !analytics.daily_clicks || !analytics.top_countries) {
            console.warn('Analytics data incomplete for charts');
            return;
        }

        // Traffic Chart
        const trafficCtx = document.getElementById('trafficChart');
        if (!trafficCtx) {
            console.error('Traffic chart canvas not found');
            return;
        }
        
        const trafficContext = trafficCtx.getContext('2d');
        if (this.charts.traffic) {
            this.charts.traffic.destroy();
        }
        
        this.charts.traffic = new Chart(trafficContext, {
            type: 'line',
            data: {
                labels: analytics.daily_clicks.map(item => item.date),
                datasets: [{
                    label: 'Total Clicks',
                    data: analytics.daily_clicks.map(item => item.clicks),
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Geographic Chart
        const geoCtx = document.getElementById('geographicChart');
        if (!geoCtx) {
            console.error('Geographic chart canvas not found');
            return;
        }
        
        const geoContext = geoCtx.getContext('2d');
        if (this.charts.geographic) {
            this.charts.geographic.destroy();
        }
        
        this.charts.geographic = new Chart(geoContext, {
            type: 'doughnut',
            data: {
                labels: analytics.top_countries.map(item => item.country),
                datasets: [{
                    data: analytics.top_countries.map(item => item.clicks),
                    backgroundColor: [
                        '#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4',
                        '#6366f1', '#8b5cf6', '#ec4899', '#f43f5e', '#84cc16'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }
    
    async loadAuditLog() {
        this.showLoading(true);
        
        try {
            const params = new URLSearchParams({
                page: this.currentPage,
                per_page: this.itemsPerPage
            });
            
            const actionFilter = document.getElementById('auditActionFilter').value;
            if (actionFilter) params.append('action_type', actionFilter);
            
            const dateFilter = document.getElementById('auditDateFilter').value;
            if (dateFilter) {
                const days = Math.ceil((new Date() - new Date(dateFilter)) / (1000 * 60 * 60 * 24));
                params.append('days', days);
            }
            
            const response = await this.apiClient.request('GET', `/api/v1/admin/audit-log?${params}`);
            
            if (response.success) {
                this.displayAuditLog(response.data.audit_log);
                this.updatePagination(response.data.pagination);
            } else {
                throw new Error('Failed to load audit log from API');
            }
            
        } catch (error) {
            console.error('Failed to load audit log:', error);
            this.showError('Failed to load audit log. Please check your connection and try again.');
            
            // Clear the table
            document.getElementById('auditTableBody').innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-center text-gray-500">No audit entries available</td></tr>';
        } finally {
            this.showLoading(false);
        }
    }
    
    displayAuditLog(entries) {
        const tbody = document.getElementById('auditTableBody');
        tbody.innerHTML = '';
        
        entries.forEach(entry => {
            const row = document.createElement('tr');
            row.className = 'table-row';
            
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="text-sm font-medium text-gray-900">${this.formatActionType(entry.action_type)}</span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${this.escapeHtml(entry.admin_username || 'Unknown')}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    ${entry.target_user_username ? this.escapeHtml(entry.target_user_username) : 'N/A'}
                </td>
                <td class="px-6 py-4 text-sm text-gray-900">
                    ${this.escapeHtml(entry.details || 'No details')}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    ${new Date(entry.created_at).toLocaleString()}
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    updatePagination(pagination) {
        document.getElementById('showingFrom').textContent = ((pagination.page - 1) * pagination.per_page + 1);
        document.getElementById('showingTo').textContent = Math.min(pagination.page * pagination.per_page, pagination.total);
        document.getElementById('totalItems').textContent = pagination.total;
        
        // Update pagination navigation
        const nav = document.getElementById('paginationNav');
        nav.innerHTML = '';
        
        // Previous button
        const prevBtn = document.createElement('button');
        prevBtn.className = `relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 ${pagination.page === 1 ? 'cursor-not-allowed' : ''}`;
        prevBtn.disabled = pagination.page === 1;
        prevBtn.innerHTML = '<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M12.707 5.293a1 1 0 010 1.414L9.414 10l3.293 3.293a1 1 0 01-1.414 1.414l-4-4a1 1 0 010-1.414l4-4a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>';
        prevBtn.onclick = () => {
            if (pagination.page > 1) {
                this.currentPage = pagination.page - 1;
                this.loadCurrentSectionData();
            }
        };
        nav.appendChild(prevBtn);
        
        // Page numbers
        for (let i = Math.max(1, pagination.page - 2); i <= Math.min(pagination.pages, pagination.page + 2); i++) {
            const pageBtn = document.createElement('button');
            pageBtn.className = `relative inline-flex items-center px-4 py-2 border text-sm font-medium ${
                i === pagination.page 
                    ? 'z-10 bg-admin-50 border-admin-500 text-admin-600' 
                    : 'bg-white border-gray-300 text-gray-500 hover:bg-gray-50'
            }`;
            pageBtn.textContent = i;
            pageBtn.onclick = () => {
                this.currentPage = i;
                this.loadCurrentSectionData();
            };
            nav.appendChild(pageBtn);
        }
        
        // Next button
        const nextBtn = document.createElement('button');
        nextBtn.className = `relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 ${pagination.page === pagination.pages ? 'cursor-not-allowed' : ''}`;
        nextBtn.disabled = pagination.page === pagination.pages;
        nextBtn.innerHTML = '<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd"/></svg>';
        nextBtn.onclick = () => {
            if (pagination.page < pagination.pages) {
                this.currentPage = pagination.page + 1;
                this.loadCurrentSectionData();
            }
        };
        nav.appendChild(nextBtn);
    }
    
    loadCurrentSectionData() {
        switch (this.currentSection) {
            case 'users':
                this.loadUsers();
                break;
            case 'urls':
                this.loadUrls();
                break;
            case 'audit':
                this.loadAuditLog();
                break;
        }
    }
    
    logout() {
        if (confirm('Are you sure you want to logout?')) {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            window.location.href = 'index.html';
        }
    }
    
    showLoading(show) {
        document.getElementById('loadingOverlay').classList.toggle('hidden', !show);
    }
    
    showSuccess(message) {
        this.showNotification(message, 'success');
    }
    
    showError(message) {
        this.showNotification(message, 'error');
        console.error('Admin Dashboard Error:', message);
    }
    
    showNotification(message, type) {
        // Use the global showToast function if available
        if (window.showToast) {
            window.showToast(message, type);
            return;
        }

        // Fallback notification system
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm ${
            type === 'success' ? 'bg-green-500 text-white' : 
            type === 'warning' ? 'bg-yellow-500 text-white' :
            'bg-red-500 text-white'
        }`;
        notification.innerHTML = `
            <div class="flex items-center">
                <span class="flex-1">${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-2 text-white hover:text-gray-200">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }
    
    formatActionType(actionType) {
        return actionType.split('_').map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    /**
     * Cleanup method to destroy charts and clear intervals
     */
    cleanup() {
        // Destroy all charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        this.charts = {};
        
        // Clear any intervals or timeouts
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        
        console.log('Admin dashboard cleaned up');
    }
    
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
}

// Initialize admin dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminDashboard = new AdminDashboard();
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (window.adminDashboard && typeof window.adminDashboard.cleanup === 'function') {
            window.adminDashboard.cleanup();
        }
    });
});
