// Main Dashboard Application
class AribaWAFDashboard {
    constructor() {
        this.currentPage = 'dashboard';
        this.isSidebarCollapsed = false;
        this.init();
    }

    init() {
        console.log('Initializing Ariba WAF Dashboard...');
        this.loadSidebar();
        this.loadPage(this.currentPage);
        this.setupEventListeners();
        this.setupRealTimeUpdates();
    }

    setupEventListeners() {
        // Menu toggle
        document.getElementById('menu-toggle')?.addEventListener('click', () => {
            this.toggleSidebar();
        });

        // Window resize handler
        window.addEventListener('resize', () => {
            this.handleResize();
        });

        // Initial resize check
        this.handleResize();
    }

    loadSidebar() {
        fetch('components/sidebar.html')
            .then(response => response.text())
            .then(html => {
                document.getElementById('sidebar-container').innerHTML = html;
                this.setupSidebarEvents();
            })
            .catch(error => {
                console.error('Error loading sidebar:', error);
            });
    }

    setupSidebarEvents() {
        // Sidebar navigation
        const navItems = document.querySelectorAll('.sidebar-nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const page = item.getAttribute('data-page');
                this.loadPage(page);
            });
        });
    }

    loadPage(page) {
        this.currentPage = page;
        console.log(`Loading page: ${page}`);

        // Show loading state
        this.showLoading();

        // Load page content
        fetch(`pages/${page}.html`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Page ${page} not found`);
                }
                return response.text();
            })
            .then(html => {
                document.getElementById('content-container').innerHTML = html;
                this.loadPageScripts(page);
                this.hideLoading();
            })
            .catch(error => {
                console.error(`Error loading page ${page}:`, error);
                this.showError(`Failed to load ${page} page`);
                this.hideLoading();
            });
    }

    loadPageScripts(page) {
        // Load page-specific JavaScript
        const script = document.createElement('script');
        script.src = `js/pages/${page}.js`;
        script.onload = () => {
            console.log(`${page} page script loaded`);
            // Initialize page-specific functionality
            if (window[`${page}Page`] && typeof window[`${page}Page`].init === 'function') {
                window[`${page}Page`].init();
            }
        };
        script.onerror = () => {
            console.error(`Error loading ${page} page script`);
        };
        document.body.appendChild(script);
    }

    toggleSidebar() {
        this.isSidebarCollapsed = !this.isSidebarCollapsed;
        const sidebar = document.querySelector('.sidebar');
        const mainContent = document.querySelector('.main-content');

        if (sidebar && mainContent) {
            if (this.isSidebarCollapsed) {
                sidebar.classList.add('collapsed');
                mainContent.classList.add('sidebar-collapsed');
            } else {
                sidebar.classList.remove('collapsed');
                mainContent.classList.remove('sidebar-collapsed');
            }
        }
    }

    handleResize() {
        // Auto-collapse sidebar on smaller screens
        if (window.innerWidth <= 1199) {
            this.isSidebarCollapsed = true;
            this.toggleSidebar();
        } else if (window.innerWidth > 1199 && this.isSidebarCollapsed) {
            this.isSidebarCollapsed = false;
            this.toggleSidebar();
        }
    }

    setupRealTimeUpdates() {
        // Connect to WebSocket for real-time updates
        this.connectWebSocket();

        // Set up periodic data refresh
        this.refreshInterval = setInterval(() => {
            this.refreshDashboardData();
        }, 30000); // Refresh every 30 seconds
    }

    connectWebSocket() {
        // WebSocket connection will be implemented based on backend API
        console.log('WebSocket connection will be established when backend is available');
    }

    refreshDashboardData() {
        console.log('Refreshing dashboard data...');
        // This will be implemented to refresh data from API
    }

    showLoading() {
        const contentContainer = document.getElementById('content-container');
        contentContainer.innerHTML = `
            <div class="loading-overlay">
                <div class="spinner"></div>
            </div>
        `;
    }

    hideLoading() {
        const loadingOverlay = document.querySelector('.loading-overlay');
        if (loadingOverlay) {
            loadingOverlay.remove();
        }
    }

    showError(message) {
        const contentContainer = document.getElementById('content-container');
        contentContainer.innerHTML = `
            <div class="card">
                <div class="empty-state">
                    <i class="fas fa-exclamation-triangle empty-state-icon"></i>
                    <h3>Error</h3>
                    <p>${message}</p>
                    <button class="btn btn-secondary mt-2" onclick="window.location.reload()">Retry</button>
                </div>
            </div>
        `;
    }

    // Utility methods
    formatNumber(num) {
        return new Intl.NumberFormat().format(num);
    }

    formatDate(dateString) {
        return new Date(dateString).toLocaleString();
    }

    getStatusBadge(status) {
        const statusMap = {
            'active': 'badge-success',
            'inactive': 'badge-warning',
            'blocked': 'badge-danger',
            'pending': 'badge-info'
        };
        return `<span class="badge ${statusMap[status] || 'badge-info'}">${status}</span>`;
    }
}

// Initialize the dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new AribaWAFDashboard();
});