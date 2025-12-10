// Dashboard Page Logic
const dashboardPage = {
    trafficChart: null,
    attackTypesChart: null,
    realTimeDataInterval: null,

    init: function() {
        console.log('Initializing Dashboard Page');
        this.setupEventListeners();
        this.loadSampleData();
        this.setupCharts();
        this.startRealTimeUpdates();
    },

    setupEventListeners: function() {
        // Refresh buttons
        document.getElementById('refresh-traffic')?.addEventListener('click', () => {
            this.refreshTrafficData();
        });

        document.getElementById('refresh-alerts')?.addEventListener('click', () => {
            this.refreshAlertsData();
        });

        document.getElementById('view-all-alerts')?.addEventListener('click', () => {
            window.dashboard.loadPage('logs-reports');
        });

        // Timeframe selector
        document.getElementById('attack-type-timeframe')?.addEventListener('change', (e) => {
            this.updateAttackTypesChart(e.target.value);
        });
    },

    setupCharts: function() {
        this.setupTrafficChart();
        this.setupAttackTypesChart();
    },

    setupTrafficChart: function() {
        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;

        const trafficData = this.generateSampleTrafficData();

        this.trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: trafficData.labels,
                datasets: [{
                    label: 'Requests per minute',
                    data: trafficData.values,
                    borderColor: 'var(--accent-blue)',
                    backgroundColor: 'rgba(76, 201, 240, 0.1)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 3,
                    pointBackgroundColor: 'var(--accent-blue)',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: 'var(--text-secondary)',
                            font: {
                                size: 12
                            }
                        },
                        grid: {
                            color: 'var(--border-color)'
                        }
                    },
                    x: {
                        ticks: {
                            color: 'var(--text-secondary)',
                            font: {
                                size: 12
                            }
                        },
                        grid: {
                            color: 'var(--border-color)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: 'var(--text-primary)',
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'var(--bg-secondary)',
                        titleColor: 'var(--text-primary)',
                        bodyColor: 'var(--text-primary)',
                        borderColor: 'var(--border-color)',
                        borderWidth: 1
                    }
                }
            }
        });
    },

    setupAttackTypesChart: function() {
        const ctx = document.getElementById('attackTypesChart');
        if (!ctx) return;

        const attackData = this.generateSampleAttackData();

        this.attackTypesChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: attackData.labels,
                datasets: [{
                    data: attackData.values,
                    backgroundColor: [
                        'var(--accent-red)',
                        'var(--accent-yellow)',
                        'var(--accent-blue)',
                        'var(--accent-green)',
                        '#9966ff'
                    ],
                    borderWidth: 0,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: 'var(--text-primary)',
                            font: {
                                size: 12
                            },
                            padding: 15,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        backgroundColor: 'var(--bg-secondary)',
                        titleColor: 'var(--text-primary)',
                        bodyColor: 'var(--text-primary)',
                        borderColor: 'var(--border-color)',
                        borderWidth: 1
                    }
                }
            }
        });
    },

    generateSampleTrafficData: function() {
        const labels = [];
        const values = [];

        const now = new Date();
        for (let i = 29; i >= 0; i--) {
            const time = new Date(now.getTime() - i * 60000);
            labels.push(time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
            values.push(Math.floor(Math.random() * 100) + 20); // 20-120 requests per minute
        }

        return { labels, values };
    },

    generateSampleAttackData: function() {
        return {
            labels: ['SQL Injection', 'XSS', 'RFI', 'Directory Traversal', 'Other'],
            values: [45, 25, 15, 10, 5]
        };
    },

    loadSampleData: function() {
        // Update panel values
        document.getElementById('live-traffic-value').textContent = Math.floor(Math.random() * 50) + 30;
        document.getElementById('blocked-requests-value').textContent = Math.floor(Math.random() * 200) + 50;
        document.getElementById('active-rules-value').textContent = Math.floor(Math.random() * 50) + 20;
        document.getElementById('whitelisted-ips-value').textContent = Math.floor(Math.random() * 20) + 5;

        // Update rate limiting stats
        document.getElementById('top-limited-ip').textContent = this.generateRandomIP();
        document.getElementById('rate-limited-blocked').textContent = Math.floor(Math.random() * 100) + 10;
        document.getElementById('active-endpoints').textContent = Math.floor(Math.random() * 15) + 5;

        // Update system health
        document.getElementById('system-uptime').textContent = `${Math.floor(Math.random() * 30) + 1} days`;
        const memoryUsage = Math.floor(Math.random() * 60) + 10;
        const cpuLoad = Math.floor(Math.random() * 80) + 5;

        document.getElementById('memory-usage').textContent = `${memoryUsage}%`;
        document.getElementById('cpu-load').textContent = `${cpuLoad}%`;

        document.querySelector('.progress-fill-blue').style.width = `${memoryUsage}%`;
        document.querySelector('.progress-fill-green').style.width = `${cpuLoad}%`;

        // Load sample alerts
        this.loadSampleAlerts();
    },

    loadSampleAlerts: function() {
        const alerts = [];
        const attackTypes = ['SQL Injection', 'XSS', 'RFI', 'Directory Traversal', 'Malicious Payload'];
        const statuses = ['Blocked', 'Quarantined', 'Logged', 'Alerted'];

        for (let i = 0; i < 10; i++) {
            const timestamp = new Date(Date.now() - i * 300000).toLocaleString();
            const ip = this.generateRandomIP();
            const requestType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
            const status = statuses[Math.floor(Math.random() * statuses.length)];
            const action = status === 'Blocked' ? 'Dropped' : 'Logged';

            const riskLevel = Math.random() > 0.7 ? 'high-risk' :
                           Math.random() > 0.4 ? 'medium-risk' : 'low-risk';

            alerts.push(`
                <tr class="alert-row ${riskLevel}">
                    <td>${timestamp}</td>
                    <td>${ip}</td>
                    <td>${requestType}</td>
                    <td>${this.getStatusBadge(status)}</td>
                    <td>${action}</td>
                </tr>
            `);
        }

        document.getElementById('alerts-table-body').innerHTML = alerts.join('');
    },

    refreshTrafficData: function() {
        console.log('Refreshing traffic data');
        const trafficData = this.generateSampleTrafficData();
        this.trafficChart.data.labels = trafficData.labels;
        this.trafficChart.data.datasets[0].data = trafficData.values;
        this.trafficChart.update();

        // Update live traffic value
        document.getElementById('live-traffic-value').textContent = trafficData.values[trafficData.values.length - 1];
    },

    refreshAlertsData: function() {
        console.log('Refreshing alerts data');
        this.loadSampleAlerts();
    },

    updateAttackTypesChart: function(timeframe) {
        console.log(`Updating attack types chart for ${timeframe}`);
        // In a real implementation, this would fetch data based on timeframe
        // For demo, we'll just regenerate random data
        const attackData = this.generateSampleAttackData();
        this.attackTypesChart.data.datasets[0].data = attackData.values;
        this.attackTypesChart.update();
    },

    startRealTimeUpdates: function() {
        // Simulate real-time updates every 5 seconds
        this.realTimeDataInterval = setInterval(() => {
            this.refreshTrafficData();
            this.refreshAlertsData();
        }, 5000);
    },

    generateRandomIP: function() {
        return `${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    },

    getStatusBadge: function(status) {
        const statusMap = {
            'Blocked': 'badge-danger',
            'Quarantined': 'badge-warning',
            'Logged': 'badge-info',
            'Alerted': 'badge-success'
        };
        return `<span class="badge ${statusMap[status] || 'badge-info'}">${status}</span>`;
    },

    cleanup: function() {
        if (this.realTimeDataInterval) {
            clearInterval(this.realTimeDataInterval);
        }
    }
};

// Initialize the dashboard page
if (typeof window.dashboardPage === 'undefined') {
    window.dashboardPage = dashboardPage;
}