const liveTrafficPage = {
    trafficFeed: null,
    trafficDistributionChart: null,
    feedInterval: null,
    feedPaused: false,

    init: function() {
        console.log('Initializing Live Traffic Page');
        this.setupEventListeners();
        this.setupCharts();
        this.startTrafficFeed();
    },

    setupEventListeners: function() {
        // Pause/Resume feed
        document.getElementById('pause-feed')?.addEventListener('click', () => {
            this.toggleFeed();
        });

        // Clear feed
        document.getElementById('clear-feed')?.addEventListener('click', () => {
            this.clearFeed();
        });
    },

    setupCharts: function() {
        this.setupTrafficDistributionChart();
    },

    setupTrafficDistributionChart: function() {
        const ctx = document.getElementById('trafficDistributionChart');
        if (!ctx) return;

        const data = {
            labels: ['GET', 'POST', 'PUT', 'DELETE', 'OTHER'],
            datasets: [{
                data: [45, 30, 15, 5, 5],
                backgroundColor: [
                    'var(--accent-blue)',
                    'var(--accent-green)',
                    'var(--accent-yellow)',
                    'var(--accent-red)',
                    '#9966ff'
                ]
            }]
        };

        this.trafficDistributionChart = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: 'var(--text-primary)',
                            font: { size: 12 },
                            padding: 15,
                            usePointStyle: true
                        }
                    }
                }
            }
        });
    },

    startTrafficFeed: function() {
        this.loadSampleTrafficData();
        this.feedInterval = setInterval(() => {
            if (!this.feedPaused) {
                this.addTrafficItem();
                this.updateTrafficStats();
            }
        }, 2000);
    },

    loadSampleTrafficData: function() {
        // Update traffic stats
        document.getElementById('total-requests').textContent = '1,245';
        document.getElementById('requests-per-minute').textContent = '48';
        document.getElementById('peak-traffic').textContent = '72';
        document.getElementById('unique-ips').textContent = '145';

        // Load sample recent activity
        this.loadSampleRecentActivity();
    },

    addTrafficItem: function() {
        const feed = document.getElementById('traffic-feed');
        if (!feed) return;

        const trafficItem = document.createElement('div');
        trafficItem.className = 'traffic-item';

        const methods = ['GET', 'POST', 'PUT', 'DELETE'];
        const endpoints = ['/api/users', '/api/data', '/api/auth', '/api/settings', '/'];
        const statuses = ['200', '404', '500', '403', '201'];

        const method = methods[Math.floor(Math.random() * methods.length)];
        const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
        const status = statuses[Math.floor(Math.random() * statuses.length)];
        const ip = this.generateRandomIP();

        const statusClass = status === '200' || status === '201' ? 'status-success' :
                          status === '404' ? 'status-warning' : 'status-danger';

        trafficItem.innerHTML = `
            <div class="traffic-item-header">
                <span class="traffic-time">${new Date().toLocaleTimeString()}</span>
                <span class="traffic-method ${method.toLowerCase()}">${method}</span>
                <span class="traffic-status ${statusClass}">${status}</span>
            </div>
            <div class="traffic-item-content">
                <span class="traffic-ip">${ip}</span>
                <span class="traffic-endpoint">${endpoint}</span>
            </div>
        `;

        // Add to top of feed
        if (feed.firstChild) {
            feed.insertBefore(trafficItem, feed.firstChild);
        } else {
            feed.appendChild(trafficItem);
        }

        // Limit feed to 20 items
        if (feed.children.length > 20) {
            feed.removeChild(feed.lastChild);
        }
    },

    loadSampleRecentActivity: function() {
        const tableBody = document.getElementById('recent-activity-table');
        if (!tableBody) return;

        const activities = [];
        const methods = ['GET', 'POST', 'PUT', 'DELETE'];
        const endpoints = ['/api/users', '/api/data', '/api/auth', '/api/settings', '/'];
        const statuses = ['200', '404', '500', '403', '201'];

        for (let i = 0; i < 10; i++) {
            const timestamp = new Date(Date.now() - i * 300000).toLocaleString();
            const method = methods[Math.floor(Math.random() * methods.length)];
            const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
            const status = statuses[Math.floor(Math.random() * statuses.length)];
            const ip = this.generateRandomIP();

            const statusClass = status === '200' || status === '201' ? 'badge-success' :
                              status === '404' ? 'badge-warning' : 'badge-danger';

            activities.push(`
                <tr>
                    <td>${timestamp}</td>
                    <td>${ip}</td>
                    <td><span class="badge badge-info">${method}</span></td>
                    <td>${endpoint}</td>
                    <td><span class="badge ${statusClass}">${status}</span></td>
                </tr>
            `);
        }

        tableBody.innerHTML = activities.join('');
    },

    updateTrafficStats: function() {
        // Update stats with slight variations
        const totalRequests = parseInt(document.getElementById('total-requests').textContent.replace(',', '')) + 1;
        document.getElementById('total-requests').textContent = totalRequests.toLocaleString();

        const requestsPerMinute = Math.floor(Math.random() * 20) + 30;
        document.getElementById('requests-per-minute').textContent = requestsPerMinute;

        // Update peak traffic occasionally
        if (Math.random() > 0.8) {
            const peakTraffic = Math.floor(Math.random() * 30) + 50;
            document.getElementById('peak-traffic').textContent = peakTraffic;
        }
    },

    toggleFeed: function() {
        this.feedPaused = !this.feedPaused;
        const button = document.getElementById('pause-feed');
        if (button) {
            button.textContent = this.feedPaused ? 'Resume' : 'Pause';
            button.innerHTML = this.feedPaused ?
                '<i class="fas fa-play"></i> Resume' :
                '<i class="fas fa-pause"></i> Pause';
        }
    },

    clearFeed: function() {
        const feed = document.getElementById('traffic-feed');
        if (feed) {
            feed.innerHTML = '<div class="empty-state"><i class="fas fa-check"></i> Feed cleared</div>';
        }
    },

    generateRandomIP: function() {
        return `${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    },

    cleanup: function() {
        if (this.feedInterval) {
            clearInterval(this.feedInterval);
        }
    }
};

// Initialize the live traffic page
if (typeof window.liveTrafficPage === 'undefined') {
    window.liveTrafficPage = liveTrafficPage;
}