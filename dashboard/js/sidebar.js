// Sidebar Navigation Logic
class DashboardSidebar {
    constructor() {
        this.sidebar = document.querySelector('.sidebar');
        this.mainContent = document.querySelector('.main-content');
        this.navItems = document.querySelectorAll('.sidebar-nav-item');
        this.currentPage = 'dashboard';
        this.init();
    }

    init() {
        console.log('Initializing Dashboard Sidebar');
        this.setupEventListeners();
        this.setActivePage();
        this.handleInitialState();
    }

    setupEventListeners() {
        // Navigation item clicks
        this.navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleNavigation(item);
            });
        });
    }

    handleNavigation(item) {
        const page = item.getAttribute('data-page');
        if (page === this.currentPage) return;

        // Update active state
        this.navItems.forEach(navItem => {
            navItem.classList.remove('active');
        });
        item.classList.add('active');

        this.currentPage = page;

        // Load the page through the main dashboard
        if (window.dashboard) {
            window.dashboard.loadPage(page);
        }

        // Auto-collapse sidebar on mobile after navigation
        if (window.innerWidth <= 767) {
            window.dashboard.toggleSidebar();
        }
    }

    setActivePage() {
        // Set active page based on current URL or default
        const activeItem = document.querySelector(`.sidebar-nav-item[data-page="${this.currentPage}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
        }
    }

    handleInitialState() {
        // Handle initial sidebar state based on screen size
        if (window.innerWidth <= 1199) {
            // Collapse sidebar on tablet and mobile by default
            if (this.sidebar && this.mainContent) {
                this.sidebar.classList.add('collapsed');
                this.mainContent.classList.add('sidebar-collapsed');
            }
        }
    }

    // Utility method to set active page programmatically
    setActivePageByName(pageName) {
        this.currentPage = pageName;
        this.navItems.forEach(navItem => {
            navItem.classList.remove('active');
            if (navItem.getAttribute('data-page') === pageName) {
                navItem.classList.add('active');
            }
        });
    }
}

// Initialize sidebar when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.sidebar')) {
        window.dashboardSidebar = new DashboardSidebar();
    }
});