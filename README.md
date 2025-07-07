# EDL Manager

A comprehensive External Dynamic List (EDL) management system for cybersecurity teams to manage and distribute IP addresses, domains, and URLs for firewall blocking.

## 🛡️ Overview

EDL Manager provides a secure, web-based interface for managing blocklists that can be consumed by firewalls and security appliances. It features a complete approval workflow, role-based access control, and enterprise integrations.

## ✨ Key Features

### Core Functionality
- **Request Submission & Approval Workflow**: Submit IP addresses, domains, and URLs for blocking with justification and ServiceNow ticket integration
- **Role-Based Access Control**: Four permission levels (Admin, Approver, Operator, Viewer) with granular permissions
- **EDL File Generation**: Automatically generates separate blocklist files for IP addresses, domains, and URLs
- **Real-time Updates**: Instant EDL file updates upon approval/denial
- **Search & Filtering**: Advanced filtering and search capabilities across all entries
- **Audit Logging**: Comprehensive activity tracking for compliance and security

### Enterprise Integrations
- **Okta SSO Integration**: Full OIDC/OAuth 2.0 support with group-based role mapping
- **Microsoft Teams Notifications**: Real-time webhook notifications for request activities
- **ServiceNow Integration**: Ticket validation and tracking integration
- **SSL/TLS Configuration**: Built-in SSL certificate management and security configuration

### Security Features
- **CSRF Protection**: All forms protected with CSRF tokens
- **Input Validation**: Comprehensive validation for IPs, domains, and URLs
- **Session Management**: Secure session handling with timeout controls
- **HTTPS Enforcement**: Configurable SSL/TLS with HSTS support
- **Data Integrity**: JSON-based storage with backup capabilities

## 🚀 Quick Start

### Prerequisites
- **PHP 7.4+** with extensions: json, session, filter, curl
- **Web Server**: Apache/Nginx with mod_rewrite
- **SSL Certificate** (recommended for production)

### Installation

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

4. **Create default users**
   ```bash
   php user_setup.php
   ```

5. **Configure web server**
   - Point document root to the EDL Manager directory
   - Ensure mod_rewrite is enabled
   - Configure SSL (see SSL Configuration section)

6. **Access the application**
   - Navigate to your domain/IP in a web browser
   - Login with default credentials:
     - **Admin**: `admin` / `admin123`
     - **Approver**: `approver` / `approver123`
     - **Operator**: `operator` / `operator123`

### Directory Structure
```
edl-manager/
├── config/
│   └── config.php              # Main configuration
├── includes/
│   ├── auth.php               # Authentication system
│   ├── functions.php          # Core functions
│   ├── validation.php         # Input validation
│   ├── header.php            # UI header template
│   ├── footer.php            # UI footer template
│   ├── okta_auth.php         # Okta SSO integration
│   └── teams_notifications.php # Teams webhooks
├── pages/
│   ├── submit_request.php     # Request submission
│   ├── approvals.php         # Approval interface
│   ├── edl_viewer.php        # EDL entries viewer
│   ├── okta_config.php       # Okta configuration
│   ├── teams_config.php      # Teams configuration
│   ├── ssl_config.php        # SSL configuration
│   └── audit_log.php         # Audit log viewer
├── data/
│   ├── users.json            # User accounts
│   ├── pending_requests.json # Pending requests
│   ├── approved_entries.json # Approved entries
│   ├── denied_entries.json   # Denied entries
│   └── audit_logs.json       # Audit trail
├── edl-files/
│   ├── ip_blocklist.txt      # IP blocklist
│   ├── domain_blocklist.txt  # Domain blocklist
│   └── url_blocklist.txt     # URL blocklist
├── assets/
│   ├── css/
│   └── js/
├── api/                      # Future API endpoints
└── okta/                     # Okta callback handlers
```

## 👥 User Roles & Permissions

| Role | Submit | Approve | View | Manage | Audit |
|------|---------|---------|------|---------|-------|
| **Admin** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Approver** | ❌ | ✅ | ✅ | ❌ | ❌ |
| **Operator** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Viewer** | ❌ | ❌ | ✅ | ❌ | ❌ |

### Permission Details
- **Submit**: Create new blocking requests
- **Approve**: Approve/deny pending requests
- **View**: View EDL entries and download lists
- **Manage**: System configuration and user management
- **Audit**: Access audit logs and system reports

## 🔧 Configuration

### Okta SSO Setup

1. **Create Okta Application**
   - Application Type: Web Application
   - Grant Types: Authorization Code
   - Scopes: openid, profile, email, groups

2. **Configure Groups**
   - Create Okta groups: `EDL-Admins`, `EDL-Approvers`, `EDL-Operators`, `EDL-Viewers`
   - Add group claims to ID token

3. **EDL Manager Configuration**
   - Navigate to Admin → Okta Configuration
   - Enter your Okta domain, Client ID, and Client Secret
   - Map Okta groups to EDL Manager roles
   - Test the connection

### Microsoft Teams Integration

1. **Create Incoming Webhook**
   - In Teams: Channel → Connectors → Incoming Webhook
   - Copy webhook URL

2. **Configure Notifications**
   - Navigate to Admin → Teams Configuration
   - Enter webhook URL and configure notification types
   - Test the webhook connection

### SSL/TLS Configuration

1. **Generate CSR**
   - Use built-in CSR generator in Admin → SSL Configuration
   - Download CSR for certificate authority

2. **Install Certificate**
   - Upload certificate files via the configuration interface
   - Configure Apache/Nginx virtual hosts
   - Enable HTTPS redirect and HSTS

## 📡 EDL File Access

### File Endpoints
- **IP Blocklist**: `https://your-domain/edl-files/ip_blocklist.txt`
- **Domain Blocklist**: `https://your-domain/edl-files/domain_blocklist.txt`
- **URL Blocklist**: `https://your-domain/edl-files/url_blocklist.txt`

### Firewall Integration
Configure your firewalls to pull these URLs for automatic blocklist updates:

**Palo Alto Networks**
```
Objects → External Dynamic Lists → Add
Name: EDL-IP-Blocklist
Type: IP List
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

## 🔍 API Reference

### EDL Files
- `GET /edl-files/ip_blocklist.txt` - Download IP blocklist
- `GET /edl-files/domain_blocklist.txt` - Download domain blocklist  
- `GET /edl-files/url_blocklist.txt` - Download URL blocklist

### Data Format
All EDL files contain one entry per line:
```
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

## 🛠️ Development

### Debug Mode
Enable debug mode for troubleshooting:
```bash
# Access debug information
curl http://your-domain/debug.php

# Test basic functionality
curl http://your-domain/test_index.php
```

### File Structure Requirements
- `data/` directory must be writable by web server
- `edl-files/` directory must be writable by web server
- JSON files are auto-created with proper permissions

### Adding Custom Validation
Extend validation in `includes/validation.php`:
```php
function validate_custom_format($entry) {
    // Your custom validation logic
    return ['valid' => true, 'type' => 'Custom'];
}
```

## 🔒 Security Considerations

### Production Deployment
1. **Change Default Passwords**: Update all default user passwords
2. **Enable HTTPS**: Force HTTPS for all admin interfaces
3. **Configure Firewall**: Restrict admin access to authorized networks
4. **Regular Backups**: Implement automated backup for data/ directory
5. **Update Dependencies**: Keep PHP and web server updated
6. **Monitor Audit Logs**: Review audit logs regularly for suspicious activity

### Network Architecture
```
Internet → Load Balancer/WAF → Web Server (HTTPS) → EDL Manager
                                      ↓
                              Firewall (HTTP) ← EDL Files
```

- Admin interface: HTTPS only
- EDL file access: HTTP allowed for firewall consumption
- Separate network zones recommended

## 📊 Monitoring & Maintenance

### Health Checks
Monitor these endpoints:
- Application health: `/debug.php`
- EDL file availability: `/edl-files/*.txt`
- Authentication system: Login functionality

### Maintenance Tasks
- **Daily**: Review audit logs and pending requests
- **Weekly**: Check system resources and backup integrity
- **Monthly**: Review user accounts and permissions
- **Quarterly**: Update SSL certificates and review security configuration

### Log Files
- Audit logs: `data/audit_logs.json`
- Teams notifications: `data/teams_logs.json`
- Web server logs: Check your web server's log directory

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a Pull Request

### Development Guidelines
- Follow PSR-4 autoloading standards
- Maintain backward compatibility
- Add comprehensive error handling
- Update documentation for new features
- Test with different PHP versions

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

### Documentation
- [Okta PHP OIDC Samples](https://github.com/okta/samples-php-oidc)
- [Bootstrap 5 Documentation](https://getbootstrap.com/docs/5.3/)
- [PHP Security Best Practices](https://www.php.net/manual/en/security.php)

### Troubleshooting

**Common Issues:**
- **Permission denied errors**: Check file permissions on `data/` and `edl-files/`
- **Okta login fails**: Verify redirect URI matches exactly
- **Teams notifications not working**: Test webhook URL independently
- **EDL files empty**: Check if entries are approved and active

**Debug Steps:**
1. Check `debug.php` for system status
2. Review web server error logs
3. Verify file permissions and PHP extensions
4. Test individual components (auth, file generation, etc.)

---

**Version**: 2.0.0  
**Last Updated**: 2025
**Minimum PHP Version**: 7.4
**Recommended PHP Version**: 8.1+
