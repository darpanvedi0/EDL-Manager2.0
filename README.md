# 🛡️ EDL Manager

A comprehensive **External Dynamic List (EDL) management system** for cybersecurity teams to securely manage and distribute IP addresses, domains, and URLs for firewall blocking and threat mitigation.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP Version](https://img.shields.io/badge/php-%3E%3D7.4-blue)
![Security](https://img.shields.io/badge/security-enterprise%20grade-green)
![SSO](https://img.shields.io/badge/SSO-Okta%20Ready-orange)

## 🌟 Project Overview

EDL Manager provides a secure, enterprise-ready web interface for managing threat intelligence blocklists that integrate seamlessly with firewalls and security appliances. Built with cybersecurity best practices, it features complete approval workflows, role-based access control, and enterprise SSO integration.

**🎯 Perfect for**: Security Operations Centers (SOCs), cybersecurity teams, network administrators, and enterprise environments requiring centralized threat intelligence management.

## ✨ Key Features

### 🔒 Core Security Features
- **🎯 Threat Intelligence Management**: Submit and manage IP addresses, domains, and URLs for blocking
- **✅ Approval Workflow**: Complete request submission and multi-level approval system
- **👥 Role-Based Access Control**: Four permission levels (Admin, Approver, Operator, Viewer)
- **🔄 Real-time EDL Generation**: Automatic blocklist file updates upon approval/denial
- **🔍 Advanced Search & Filtering**: Comprehensive filtering across all entries
- **📊 Audit Logging**: Complete activity tracking for compliance and forensics

### 🏢 Enterprise Integrations
- **🔐 Okta SSO Integration**: Full OIDC/OAuth 2.0 support with group-based role mapping
- **📱 Microsoft Teams Notifications**: Real-time webhook notifications for security events
- **🎫 ServiceNow Integration**: Ticket validation and incident tracking
- **🛡️ SSL/TLS Configuration**: Built-in certificate management and security hardening
- **⚡ High Availability**: Designed for enterprise-scale deployments

### 🔧 Technical Security Features
- **🛡️ CSRF Protection**: All forms protected with security tokens
- **✅ Input Validation**: Comprehensive validation for IPs, domains, and URLs
- **⏱️ Session Management**: Secure session handling with configurable timeouts
- **🔒 HTTPS Enforcement**: Configurable SSL/TLS with HSTS support
- **💾 Data Integrity**: JSON-based storage with automated backup capabilities
- **📝 Comprehensive Logging**: Full audit trail with detailed activity tracking

## 🚀 Quick Start

### 📋 Prerequisites
- **PHP 7.4+** with extensions: `json`, `session`, `filter`, `curl`
- **Web Server**: Apache/Nginx with `mod_rewrite` enabled
- **SSL Certificate** (recommended for production)
- **Okta Developer Account** (optional, for SSO)

### ⚡ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/darpanvedi0/edl-manager.git
   cd edl-manager
   ```

2. **Set up permissions**
   ```bash
   chmod 755 -R .
   chmod 777 data/ edl-files/
   ```

3. **Run initial setup**
   ```bash
   php setup.php
   ```

4. **Create user accounts**
   ```bash
   php user_setup.php
   ```
   Follow the interactive prompts to set custom passwords for each role:
   - **Admin**: System Administrator (full access)
   - **Approver**: Security Approver (approve/deny requests)
   - **Operator**: Security Operator (submit requests)
   - **Viewer**: Security Viewer (read-only access)

5. **Configure web server**
   - Point document root to the EDL Manager directory
   - Ensure `mod_rewrite` is enabled for Apache
   - Configure SSL certificates (see SSL Configuration section)

6. **Access the application**
   - Navigate to your domain/IP in a web browser
   - Login with the credentials you created during user setup
   - **Important**: Use the custom passwords you set in step 4

## 📁 Project Structure

```
edl-manager/
├── 📁 config/
│   └── config.php              # Main application configuration
├── 📁 includes/
│   ├── auth.php               # Core authentication system
│   ├── functions.php          # Utility functions
│   ├── validation.php         # Input validation
│   ├── header.php            # UI header template
│   ├── footer.php            # UI footer template
│   ├── okta_auth.php         # Standard Okta SSO integration
│   ├── okta_auth_org.php     # Enterprise Okta integration
│   └── teams_notifications.php # Microsoft Teams webhooks
├── 📁 pages/
│   ├── submit_request.php     # Threat submission interface
│   ├── approvals.php         # Request approval workflow
│   ├── edl_viewer.php        # EDL entries management
│   ├── request_history.php   # User request tracking
│   ├── denied_entries.php    # Denied requests management
│   ├── okta_config.php       # SSO configuration
│   ├── teams_config.php      # Teams integration setup
│   ├── ssl_config.php        # SSL/TLS management
│   └── audit_log.php         # Security audit interface
├── 📁 data/
│   ├── users.json            # User accounts & permissions
│   ├── pending_requests.json # Pending approval queue
│   ├── approved_entries.json # Active blocklist entries
│   ├── denied_entries.json   # Rejected requests
│   └── audit_logs.json       # Complete audit trail
├── 📁 edl-files/
│   ├── ip_blocklist.txt      # IP address blocklist
│   ├── domain_blocklist.txt  # Domain blocklist
│   └── url_blocklist.txt     # URL blocklist
├── 📁 assets/
│   ├── css/                  # Application stylesheets
│   └── js/                   # JavaScript functionality
├── 📁 okta/                  # SSO callback handlers
│   ├── login.php            # Okta login initiation
│   └── callback.php         # OAuth callback handler
├── 📁 api/                   # Future API endpoints
├── setup.php                # Initial system setup
├── user_setup.php           # User account creation
├── debug.php                # System diagnostics
└── index.php                # Main dashboard
```

## 👥 User Roles & Security Permissions

| Role            | Submit Requests | Approve/Deny | View EDL | System Management | Audit Access |
|-----------------|:---------------:|:------------:|:--------:|:-----------------:|:------------:|
| **🔑 Admin**    |        ✅       |       ✅     |    ✅    |         ✅        |      ✅      |
| **✅ Approver** |        ❌       |       ✅     |    ✅    |         ❌        |      ❌      |
| **📝 Operator** |        ✅       |       ❌     |    ✅    |         ❌        |      ❌      |
| **👁️ Viewer**   |        ❌       |       ❌     |    ✅    |         ❌        |      ❌      |

### 🔐 Permission Details
- **Submit**: Create new blocking requests with justification
- **Approve**: Review and approve/deny pending security requests
- **View**: Access EDL entries and download blocklist files
- **Manage**: System configuration, user management, integrations
- **Audit**: Access security logs and compliance reports

## 🔧 Enterprise Configuration

### 🔐 Okta SSO Setup

1. **Create Okta Application**
   ```
   Application Type: Web Application
   Grant Types: Authorization Code
   Sign-in redirect URIs: https://your-domain/okta/callback.php
   Scopes: openid, profile, email, groups
   ```

2. **Configure Group Mapping**
   - Navigate to Admin → Okta Configuration
   - Map Okta groups to EDL Manager roles
   - Test SSO connection and group assignments

3. **Enable SSO Authentication**
   - Configure domain and client credentials
   - Set group-based role mappings
   - Test authentication flow

### 📱 Microsoft Teams Integration

1. **Create Incoming Webhook**
   ```
   Teams Channel → Connectors → Incoming Webhook
   Copy webhook URL for configuration
   ```

2. **Configure Notifications**
   - Navigate to Admin → Teams Configuration
   - Enter webhook URL and select notification types
   - Test webhook functionality

### 🛡️ SSL/TLS Configuration

1. **Generate Certificate Signing Request (CSR)**
   - Use built-in CSR generator in Admin → SSL Configuration
   - Download CSR for submission to Certificate Authority

2. **Install SSL Certificate**
   - Upload certificate files via configuration interface
   - Configure Apache/Nginx virtual hosts
   - Enable HTTPS redirect and HSTS headers

## 📡 Firewall Integration

### 🔗 EDL File Endpoints
```
IP Blocklist:     https://your-domain/edl-files/ip_blocklist.txt
Domain Blocklist: https://your-domain/edl-files/domain_blocklist.txt
URL Blocklist:    https://your-domain/edl-files/url_blocklist.txt
```

### 🔥 Firewall Configuration Examples

**Palo Alto Networks**
```
Objects → External Dynamic Lists → Add
Name: EDL-IP-Blocklist
Type: IP List/Domain List/URL List
Source: https://your-domain/edl-files/ip_blocklist.txt
Check for updates: Every hour
```

**Fortinet FortiGate**
```
Security Fabric → External Connectors → Create New
Name: EDL-Manager
URL: https://your-domain/edl-files/ip_blocklist.txt
Update Rate: 60 minutes
```

**Cisco ASA**
```
object-group network BLOCKED_IPS
 description EDL Manager Blocked IPs
 group-object EDL_BLOCKLIST
```

## 🔍 API Reference

### 📥 EDL File Access
- `GET /edl-files/ip_blocklist.txt` - Download IP address blocklist
- `GET /edl-files/domain_blocklist.txt` - Download domain blocklist  
- `GET /edl-files/url_blocklist.txt` - Download URL blocklist

### 📋 Data Format
All EDL files contain one entry per line in plain text format:

```bash
# IP Blocklist Example
192.168.1.100
10.0.0.50
203.0.113.25

# Domain Blocklist Example
malicious-domain.com
suspicious-site.net
blocked-domain.org

# URL Blocklist Example
https://malicious-site.com/malware
http://suspicious-domain.net/phishing
https://blocked-site.org/badcontent
```

## 🛠️ Development & Debugging

### 🔍 Debug Tools
```bash
# System health check
curl https://your-domain/debug.php

# Authentication testing
curl https://your-domain/debug_auth.php

# User setup verification
php user_setup.php
```

### 📂 File Requirements
- `data/` directory must be writable by web server (755/777)
- `edl-files/` directory must be writable by web server (755/777)
- JSON data files are auto-created with proper permissions

### 🔧 Custom Validation
Extend validation in `includes/validation.php`:
```php
function validate_custom_format($entry) {
    // Your custom validation logic
    return ['valid' => true, 'type' => 'Custom'];
}
```

## 🔒 Security Best Practices

### 🏭 Production Deployment Checklist
- [ ] **Set strong passwords during initial user setup**
- [ ] **Enable HTTPS for all administrative interfaces**
- [ ] **Configure firewall rules to restrict admin access**
- [ ] **Implement automated backups of `data/` directory**
- [ ] **Keep PHP and web server updated to latest versions**
- [ ] **Review audit logs regularly for suspicious activity**
- [ ] **Configure proper file permissions (755/644)**
- [ ] **Enable web server security headers**

### 🌐 Network Architecture
```
Internet → Load Balancer/WAF → Web Server (HTTPS) → EDL Manager
                                      ↓
                              Firewall Devices (HTTP) ← EDL Files
```

**Recommended Setup:**
- Admin interface: HTTPS only with client certificate authentication
- EDL file access: HTTP allowed for firewall consumption
- Separate network zones for management and production traffic

## 📊 Monitoring & Maintenance

### 🩺 Health Monitoring
Monitor these critical endpoints:
- **Application Health**: `/debug.php` - System status and diagnostics
- **EDL File Availability**: `/edl-files/*.txt` - Blocklist accessibility
- **Authentication System**: Login functionality and SSO connectivity

### 📅 Maintenance Schedule
- **Daily**: Review audit logs and process pending requests
- **Weekly**: Verify system resources and backup integrity
- **Monthly**: Review user accounts, permissions, and access patterns
- **Quarterly**: Update SSL certificates and security configurations

### 📝 Log Files & Locations
```
📁 Application Logs:
├── data/audit_logs.json        # User activity and security events
├── data/teams_logs.json        # Teams notification history
└── Web server logs             # Check your web server's log directory

📁 Monitoring Endpoints:
├── /debug.php                  # System diagnostics
├── /debug_auth.php            # Authentication testing
└── /edl-files/                # Blocklist file availability
```

## 🤝 Contributing

I welcome contributions to improve EDL Manager! Here's how to get involved:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-amazing-feature`
3. **Commit your changes**: `git commit -am 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature-amazing-feature`
5. **Submit a Pull Request**

### 📋 Development Guidelines
- Follow PSR-4 autoloading standards for PHP
- Maintain backward compatibility with existing installations
- Add comprehensive error handling and logging
- Update documentation for any new features
- Test with multiple PHP versions (7.4, 8.0, 8.1+)
- Follow security best practices for all code changes

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for complete details.

## 📞 Support & Documentation

### 📚 Additional Resources
- [Okta PHP OIDC Integration Guide](https://github.com/okta/samples-php-oidc)
- [Bootstrap 5 Documentation](https://getbootstrap.com/docs/5.3/)
- [PHP Security Best Practices](https://www.php.net/manual/en/security.php)
- [Apache SSL/TLS Configuration](https://httpd.apache.org/docs/current/ssl/)

### 🔧 Troubleshooting Common Issues

| Issue                               | Solution |
|-------------------------------------|----------|
| **Permission denied errors**        | Check file permissions on `data/` and `edl-files/` directories |
| **Okta login failures**             | Verify redirect URI matches configuration exactly |
| **Teams notifications not working** | Test webhook URL independently in Teams |
| **Empty EDL files**                 | Ensure entries are approved and marked as active |
| **Session timeout issues**          | Adjust `SESSION_TIMEOUT` in configuration |

### 🐛 Debug Steps
1. Run `debug.php` to check system status and requirements
2. Review web server error logs for detailed error information
3. Verify file permissions and PHP extension availability
4. Test individual components (authentication, file generation, etc.)
5. Check network connectivity for external integrations

---

## 🏆 Project Stats

- **🔧 Built with**: PHP 7.4+, Bootstrap 5, vanilla JavaScript
- **🛡️ Security**: Enterprise-grade with SSO integration
- **📊 Version**: 2.0.0
- **📅 Last Updated**: 2025
- **⚡ Performance**: Optimized for high-availability deployments
- **🔗 Integration Ready**: Okta, Teams, ServiceNow compatible

**Developed by**: [Darpan Vedi](https://github.com/darpanvedi0)

---

*EDL Manager - Securing your network perimeter, one blocklist at a time.* 🛡️
