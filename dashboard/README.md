# Ariba WAF Dashboard

🚀 **Modern, Professional Web Application Firewall Dashboard**

A comprehensive, full-featured dashboard for managing the Ariba Web Application Firewall with real-time monitoring, security rule management, and advanced analytics.

## 🎯 Features

- **Real-time Traffic Monitoring**: Live charts and statistics
- **Security Rule Management**: Add, edit, delete security rules
- **IP Management**: Whitelist/blacklist with geographic visualization
- **Rate Limiting**: Configure per-IP and per-endpoint limits
- **Logs & Reports**: Advanced filtering and export capabilities
- **Dark Theme UI**: Professional interface with accent colors
- **Responsive Design**: Optimized for desktop and tablet screens

## 🚀 Quick Start

### Method 1: Using the Python Server (Recommended)

```bash
# Navigate to the dashboard directory
cd dashboard

# Run the server
python server.py

# The dashboard will automatically open in your browser at:
# http://localhost:8000
```

### Method 2: Using Python's Built-in HTTP Server

```bash
# Navigate to the dashboard directory
cd dashboard

# Run the built-in server
python -m http.server 8000

# Open your browser and go to:
# http://localhost:8000
```

### Method 3: Direct File Access

Simply open `dashboard/index.html` in any modern web browser.

## 📁 Project Structure

```
dashboard/
├── index.html                  # Main dashboard entry point
├── server.py                   # Development server
├── README.md                   # This file
├── css/                        # Stylesheets
│   ├── main.css                # Base styles and dark theme
│   ├── dashboard.css           # Dashboard-specific styles
│   ├── sidebar.css             # Sidebar navigation styles
│   └── modal.css               # Modal dialog styles
├── js/                         # JavaScript
│   ├── main.js                 # Main application logic
│   ├── sidebar.js              # Sidebar navigation
│   └── pages/                  # Page-specific scripts
│       └── dashboard.js        # Dashboard page functionality
├── components/                 # Reusable UI components
│   └── sidebar.html            # Sidebar component
├── pages/                      # Page templates
│   ├── dashboard.html          # Main dashboard overview
│   ├── live-traffic.html       # Live traffic monitor
│   └── rule-management.html    # Rule management interface
└── test-files/                 # Testing and validation
    ├── test-dashboard.html     # Component tests
    ├── test-responsive.html    # Responsive tests
    └── test-validation.html    # Comprehensive validation
```

## 🛠️ Customization

### Port Configuration

To run on a different port:

```bash
python server.py 3000  # Runs on port 3000
```

### Development Mode

For development with auto-refresh:

```bash
# Install live-server globally (if not installed)
npm install -g live-server

# Run in development mode
live-server dashboard --port=8000
```

## 📱 Responsive Design

The dashboard is optimized for:
- **Desktop**: ≥1200px (full navigation and multi-column layouts)
- **Tablet**: 768px-1199px (collapsed sidebar, adaptive grid)
- **Mobile**: <768px (mobile-optimized single column)

## 🔧 Browser Support

✅ **Fully Supported**: Chrome, Firefox, Safari, Edge
✅ **Modern Browsers**: Latest versions recommended

## 🎨 Dark Theme

The dashboard features a professional dark theme with:
- **Primary Background**: Deep blue/navy colors
- **Accent Colors**: Blue (#4cc9f0), Green (#43aa8b), Red (#f87171)
- **Accessibility**: WCAG-compliant contrast ratios

## 📊 Real-time Features

- **Live Traffic Charts**: Updated every 5 seconds (simulated)
- **Alert Notifications**: Real-time security alerts
- **System Health**: CPU, memory, and uptime monitoring

## 🔒 Security Notes

This is a **frontend-only** dashboard. For production use:
1. Connect to your Ariba WAF backend API
2. Implement proper authentication (JWT recommended)
3. Enable HTTPS for secure communication
4. Configure CORS appropriately

## 🚀 Deployment

For production deployment:
1. Build and minify assets
2. Configure proper backend integration
3. Set up authentication and authorization
4. Enable HTTPS with valid certificates
5. Implement monitoring and logging

## 🤝 Contributing

This dashboard is designed to be easily extended. To add new features:
1. Create new page templates in `pages/`
2. Add corresponding JavaScript in `js/pages/`
3. Update the sidebar navigation
4. Add any required CSS styles

## 📞 Support

For issues or questions:
- Check the architecture documentation
- Review the integration specification
- Examine the wireframes and mockups

---

**Ariba WAF Dashboard** - Modern Security Management for Your Web Applications 🛡️