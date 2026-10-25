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
- **📈 Impact Metrics**: Time from request to approval, time until firewalls pull the update, and which firewalls are polling

### 🏢 Enterprise Integrations
- **🔐 Okta SSO Integration**: Full OIDC/OAuth 2.0 support with group-based role mapping
- **📱 Microsoft Teams Notifications**: Real-time webhook notifications for security events
- **🎫 ServiceNow Integration**: Ticket validation and incident tracking
- **🔌 REST API**: API-key access for SOAR platforms, SIEM playbooks, and scripts, with an OpenAPI 3.1 spec
- **🧩 Cortex XSOAR**: A content pack to submit, approve, track, and remove entries from playbooks and the War Room
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

### 🐳 Run with Docker

The container runs Apache as an unprivileged user on port 8080, on a read-only filesystem, and keeps its data in two volumes.

```bash
git clone https://github.com/darpanvedi0/EDL-Manager2.0.git
cd EDL-Manager2.0
docker compose up -d --build
docker compose logs edl-manager | grep "Initial admin password"
```

Open http://localhost:8080 and sign in as `admin` with the password from the logs. To choose it yourself, set `EDL_ADMIN_PASSWORD` (12+ characters) before the first start. Firewalls fetch the lists from `http://<host>:8080/edl-files/ip_blocklist.txt`, `domain_blocklist.txt`, and `url_blocklist.txt`.

**Accounts.** The image leaves out the web-based `user_setup.php`. Manage local accounts with `edl-users` (roles: `admin`, `approver`, `operator`, `viewer`):

```bash
docker compose exec edl-manager edl-users set-password approver        # prompts for the password
docker compose exec edl-manager edl-users set-password alice --role=operator
docker compose exec edl-manager edl-users list
```

**Settings**

| Variable | Default | Purpose |
|----------|---------|---------|
| `EDL_ADMIN_PASSWORD` | generated | Admin password, used only when no accounts exist |
| `EDL_ADMIN_PASSWORD_FILE` | – | Read the admin password from a file (Docker secrets) |
| `EDL_SECURE_COOKIES` | `0` | Set to `1` once the UI is served over HTTPS |
| `TZ` | `UTC` | Time zone for timestamps |

**HTTPS.** The container serves plain HTTP. Put the UI behind a TLS-terminating reverse proxy (nginx, Caddy, or a load balancer) and set `EDL_SECURE_COOKIES=1`. The in-app SSL Configuration page generates config for a web server installed on the host; it doesn't apply to the container.

**Data.** Accounts, requests, and the audit log live in the `edl-data` volume, and the published lists in `edl-lists`; back up both. Bind-mounted host directories must be writable by uid 33 (`www-data`). Sessions are kept in memory, so restarting the container signs everyone out.

**Testing an image.** `docker build -t edl-manager:dev . && docker/smoke-test.sh edl-manager:dev` starts the image with the same hardening and checks the blocklists, blocked paths, login, and the submit → approve → publish flow. CI runs it on every pull request.

### 📋 Prerequisites
- **PHP 7.4+** with extensions: `json`, `session`, `filter`, `curl`
- **Web Server**: Apache/Nginx with `mod_rewrite` enabled
- **SSL Certificate** (recommended for production)
- **Okta Developer Account** (optional, for SSO)

### ⚡ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/darpanvedi0/EDL-Manager2.0.git /var/www/edl-manager
   cd /var/www/edl-manager
   ```

2. **Choose a data directory (outside the web root)**

   The data directory holds user accounts and password hashes, requests, audit logs and SSL private keys. It must never be reachable over HTTP. The default is `data/` inside the app, which is only safe if your web server denies it (step 5). Moving it out of the web root is the safer option:
   ```bash
   sudo install -d -o www-data -g www-data -m 750 /var/lib/edl-manager
   cp config/config.local.php.example config/config.local.php
   # edit config/config.local.php: define('EDL_DATA_DIR', '/var/lib/edl-manager');
   ```
   `config/config.local.php` is not tracked by git. You can set `EDL_DATA_DIR` as an environment variable instead (`fastcgi_param` / `SetEnv`), but then also export it when you run `user_setup.php` from the shell.

3. **Set permissions**
   ```bash
   # Code: owned by root, readable (not writable) by the web server
   sudo chown -R root:root .
   sudo find . -type d -exec chmod 755 {} + && sudo find . -type f -exec chmod 644 {} +
   # PHP writes the EDL files; they must stay readable by the web server
   sudo chown www-data:www-data edl-files && sudo chmod 755 edl-files
   # Only if you keep the default data/ directory inside the web root:
   sudo chown www-data:www-data data && sudo chmod 750 data
   ```
   Replace `www-data` with your PHP user. Data and EDL files are written with a temp file plus `rename()`, so PHP needs write access to the **directories**, not only the files. Never use `chmod 777`.

4. **Create user accounts** (from a shell on the server, as the PHP user)
   ```bash
   sudo -u www-data php user_setup.php
   ```
   You will be prompted for a password (minimum 12 characters) for each role:
   - **Admin**: System Administrator (full access)
   - **Approver**: Security Approver (approve/deny requests)
   - **Operator**: Security Operator (submit requests)
   - **Viewer**: Security Viewer (read-only access)

   No accounts or default passwords ship with the application. After the first login, an admin can also reset the local passwords at `/user_setup.php` in the browser (requires the `manage` permission).

5. **Configure the web server**

   Point the document root at the EDL Manager directory and deny `data/`, `config/`, `includes/` and dotfiles (`.git`, `.htaccess`). Do this even if you moved the data directory, so a misconfiguration can't expose anything later.

   **Nginx + PHP-FPM**
   ```nginx
   server {
       listen 443 ssl;
       server_name edl.example.com;
       root /var/www/edl-manager;
       index index.php;

       # Never serve application data, configuration, includes, or dotfiles
       # (.git, .htaccess, ...). ^~ stops nginx from trying the .php regex below.
       location ^~ /data/     { deny all; }
       location ^~ /config/   { deny all; }
       location ^~ /includes/ { deny all; }
       location ~ /\.(?!well-known/) { deny all; }

       # EDL files fetched by firewalls
       location ^~ /edl-files/ {
           default_type text/plain;
           add_header Cache-Control "no-cache, must-revalidate";
       }

       location ~ \.php$ {
           include snippets/fastcgi-php.conf;
           fastcgi_pass unix:/run/php/php8.3-fpm.sock;
           # Optional if not set in config/config.local.php:
           # fastcgi_param EDL_DATA_DIR /var/lib/edl-manager;
       }
   }
   ```

   **Apache**

   `data/.htaccess` (`Require all denied`) ships with the app, but Apache only reads it when `AllowOverride` allows it. Debian/Ubuntu default to `AllowOverride None`, which silently ignores it. Put the rules in the virtual host so they apply regardless:
   ```apache
   <VirtualHost *:443>
       ServerName edl.example.com
       DocumentRoot /var/www/edl-manager

       <Directory /var/www/edl-manager>
           AllowOverride None
           Require all granted
       </Directory>

       # Never serve application data, configuration or includes
       <Directory /var/www/edl-manager/data>
           Require all denied
       </Directory>
       <Directory /var/www/edl-manager/config>
           Require all denied
       </Directory>
       <Directory /var/www/edl-manager/includes>
           Require all denied
       </Directory>
       # Dotfiles and directories (.git, .htaccess, ...)
       RedirectMatch 404 "/\.(?!well-known/)"

       # Optional if not set in config/config.local.php:
       # SetEnv EDL_DATA_DIR /var/lib/edl-manager
   </VirtualHost>
   ```
   Configure SSL certificates as described in the SSL Configuration section.

   **Check it:** `curl -I https://edl.example.com/data/users.example.json` and `curl -I https://edl.example.com/.git/config` must return 403 or 404.

6. **Access the application**
   - Navigate to your domain/IP in a web browser
   - Login with the credentials you created in step 4

### 🔁 Upgrading an Existing Installation

Earlier versions committed the runtime files in `data/` (`users.json`, `audit_logs.json`, request and config files) to git. They are no longer tracked, and a plain `git pull` will either refuse to run (if your copies have changed) or delete them (if they haven't). Back up first:

```bash
cd /var/www/edl-manager
sudo cp -a data /root/edl-data-backup          # your live data
sudo git checkout -- data/ && sudo git pull     # data/*.json are removed from git
```

Then either move the data out of the web root (recommended):
```bash
sudo install -d -o www-data -g www-data -m 750 /var/lib/edl-manager
sudo cp -a /root/edl-data-backup/. /var/lib/edl-manager/
sudo rm -f /var/lib/edl-manager/.htaccess /var/lib/edl-manager/*.example.json
sudo chown -R www-data:www-data /var/lib/edl-manager
sudo cp config/config.local.php.example config/config.local.php   # set EDL_DATA_DIR
# once the app works, remove the old copies from the web root:
sudo find data -mindepth 1 ! -path data/.htaccess ! -name '*.example.json' -delete
```
or put it back in place: `sudo cp -a /root/edl-data-backup/. data/` (git now ignores these files).

Finally, apply the web server rules from step 5, and **rotate every local password** with `sudo -u www-data php user_setup.php`. The password hashes previously committed to this repository remain in the git history and must be treated as public.

## 📁 Project Structure

```
edl-manager/
├── 📁 config/
│   ├── config.php              # Main application configuration
│   └── config.local.php.example # Site settings template (EDL_DATA_DIR, EDL_DEBUG)
├── 📁 includes/
│   ├── auth.php               # Core authentication system
│   ├── functions.php          # Utility functions
│   ├── validation.php         # Input validation
│   ├── edl_lists.php          # Writes the blocklist files
│   ├── requests.php           # Submit/approve/deny/remove, used by the REST API
│   ├── api_keys.php           # REST API keys
│   ├── fetch_stats.php        # Records which clients fetch the lists
│   ├── metrics.php            # Impact metrics
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
│   ├── api_keys.php          # REST API key management
│   ├── metrics.php           # Impact metrics and report
│   └── audit_log.php         # Security audit interface
├── 📁 data/                  # Default EDL_DATA_DIR (runtime files are not in git)
│   ├── .htaccess             # Denies all HTTP access (Apache)
│   ├── *.example.json        # Templates for the runtime files below
│   ├── users.json            # User accounts & password hashes (created by user_setup.php)
│   ├── pending_requests.json # Pending approval queue
│   ├── approved_entries.json # Active blocklist entries
│   ├── denied_entries.json   # Rejected requests
│   ├── api_keys.json         # API keys (hashed secrets)
│   ├── fetch_stats.json      # List fetches by client, for the Impact page
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
├── 📁 api/                   # JSON endpoints for the web UI (stats, export, EDL regeneration)
│   └── 📁 v1/
│       ├── index.php         # REST API router
│       └── openapi.yaml      # REST API reference
├── 📁 integrations/
│   └── 📁 xsoar/             # Cortex XSOAR content pack (demisto/content layout) and its tests
├── 📁 tests/
│   └── run.php               # Unit tests (php tests/run.php)
├── 📁 bench/                 # Performance and accuracy benchmarks (bench/run.sh) and results
├── feed.php                 # Serves the lists to firewalls and records fetches
├── user_setup.php           # User account creation (CLI, or admin-only in browser)
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

### 🔌 REST API (v1)

The REST API lets SOAR platforms (Cortex XSOAR, Splunk SOAR, Tines), SIEM playbooks, and scripts use the same approval workflow as the web UI. The full reference is [`api/v1/openapi.yaml`](api/v1/openapi.yaml); OpenAPI-aware tools can import it to generate a client.

**Keys.** An admin creates keys under **Admin → API Keys**, choosing any of `view`, `submit`, `approve`, and `remove`. The token is shown once; only a hash is stored. Send it as `Authorization: Bearer <token>` (or `X-API-Key: <token>`). Anything a key does shows up as `api:<key name>` in the UI and the audit log.

| Method | Path | Permission | Purpose |
|--------|------|------------|---------|
| `GET` | `/api/v1/health` | none | Liveness check |
| `GET` | `/api/v1/requests` | `view` | Pending requests |
| `POST` | `/api/v1/requests` | `submit` | Submit one `entry` or up to 500 `entries` |
| `GET` | `/api/v1/requests/{id}` | `view` | Where a request is now: pending, approved, denied, or deleted |
| `POST` | `/api/v1/requests/{id}/approve` | `approve` | Approve and publish |
| `POST` | `/api/v1/requests/{id}/deny` | `approve` | Deny (a `reason` is required) |
| `GET` | `/api/v1/entries` | `view` | Blocklist entries (`?status=active\|deleted\|all&type=&q=`) |
| `DELETE` | `/api/v1/entries/{id}` | `remove` | Remove an entry from the blocklist |
| `GET` | `/api/v1/metrics` | `view` | Impact metrics (`?days=30`) |

```bash
TOKEN=edl_...   # from Admin → API Keys
curl -X POST https://edl.example.com/api/v1/requests \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"entries": ["198.51.100.7", "evil.example.com"],
       "justification": "C2 infrastructure from IR-2291",
       "servicenow_ticket": "SIR0012345", "priority": "high"}'
```

Entries that are invalid, already blocked, already pending, or previously denied are skipped with a reason in the response; the rest wait for approval like any other request. URLs containing `&`, quotes, or angle brackets are rejected for now, because the web UI stores entries HTML-escaped.

**Routing.** The Docker image routes `/api/v1/*` to the API. On other installs, either use `/api/v1/index.php/requests` style URLs, or add `FallbackResource /api/v1/index.php` inside a `<Directory .../api/v1>` block (Apache) or `location /api/v1/ { try_files $uri /api/v1/index.php$is_args$args; }` (nginx).

### 🧩 Cortex XSOAR

[`integrations/xsoar`](integrations/xsoar) holds a Cortex XSOAR content pack built on the REST API. Its commands submit indicators from an incident with the justification and ticket, poll until the request is approved or denied, approve, deny, or remove entries, and get impact metrics. It's laid out for contribution to the XSOAR Marketplace; see its README for setup, tests, and the contribution steps.

## 📈 Impact Metrics

**Impact** in the navigation bar shows, for the last 7, 30, 90, or 365 days:

- **Request → approval**: median and 90th percentile, overall and by priority
- **Approval → first firewall fetch**: how long until a firewall first downloaded the updated list
- **Firewall clients**: every address and user agent that fetches the lists, how often each polls, and which ones have stopped polling
- Request volume, approval rate, pending backlog, and published list sizes

The page opens with a plain-language summary and can be printed or saved as PDF, or downloaded as JSON. The same numbers are at `GET /api/v1/metrics`. The page ends with how each number is measured.

### 📏 Measuring Firewall Fetches

Fetch data comes from `feed.php`, which serves each list and records who fetched which version. The Docker image routes `/edl-files/*.txt` through it, so firewall URLs don't change. On other installs, either point firewalls at `feed.php?list=ip` (or `domain`, `url`), or add a rewrite to the server configuration (adjust the paths if EDL Manager isn't at the web root):

```apache
# Apache virtual host (mod_rewrite)
RewriteEngine On
RewriteRule ^/edl-files/(ip|domain|url)_blocklist\.txt$ /feed.php?list=$1 [PT,L]
```

```nginx
# nginx server block
rewrite ^/edl-files/(ip|domain|url)_blocklist\.txt$ /feed.php?list=$1 last;
```

Fetches are stored in `fetch_stats.json` in the data directory: client address, user agent, and times, at most one write per client and list per minute. Behind a reverse proxy, every firewall shows the proxy's address, and firewalls sharing a NAT address and user agent count as one client.

## 🛠️ Development & Debugging

### 🔍 Debug Mode
PHP errors are logged, never shown in the browser. To display them while troubleshooting a non-production instance, set `EDL_DEBUG` in `config/config.local.php` (`define('EDL_DEBUG', true);`) or as an environment variable (`fastcgi_param EDL_DEBUG 1;` / `SetEnv EDL_DEBUG 1`). Turn it off again afterwards.

There are no debug or diagnostic pages in the web root; check the web server / PHP-FPM error log instead.

### 🧪 Tests
```bash
php tests/run.php                                     # unit tests: requests, API keys, fetch tracking, metrics
docker build -t edl-manager:dev . && docker/smoke-test.sh edl-manager:dev   # end to end, through Apache
```
CI runs both on every pull request. [`bench/`](bench) holds the performance and time-to-enforcement accuracy benchmarks, with their latest results.

### 📂 File Requirements
- The data directory (`EDL_DATA_DIR`, default `data/`) must be writable by the PHP user and must not be served over HTTP (750)
- `edl-files/` must be writable by the PHP user and readable by the web server (755)
- Missing JSON data files are created automatically; `data/*.example.json` shows their initial contents
- All JSON and EDL writes take an exclusive lock (`.data.lock` in the data directory) and replace files atomically, so concurrent approvals can't overwrite each other and firewalls never fetch a half-written list

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
- [ ] **Set strong passwords during initial user setup** (and rotate any account created before this release)
- [ ] **Keep the data directory outside the web root, or deny `/data/` in the web server** (verify with `curl -I`)
- [ ] **Deny `/config/`, `/includes/` and dotfiles such as `/.git/`**
- [ ] **Leave `EDL_DEBUG` off**
- [ ] **Enable HTTPS for all administrative interfaces**
- [ ] **Configure firewall rules to restrict admin access**
- [ ] **Implement automated backups of the data directory**
- [ ] **Keep PHP and web server updated to latest versions**
- [ ] **Review audit logs regularly for suspicious activity**
- [ ] **Configure proper file permissions (code 755/644 read-only, data 750)**
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
- **Application Health**: `/login.php` returns 200; PHP / web server error logs are clean
- **EDL File Availability**: `/edl-files/*.txt` - Blocklist accessibility
- **Authentication System**: Login functionality and SSO connectivity

### 📅 Maintenance Schedule
- **Daily**: Review audit logs and process pending requests
- **Weekly**: Verify system resources and backup integrity
- **Monthly**: Review user accounts, permissions, and access patterns
- **Quarterly**: Update SSL certificates and security configurations

### 📝 Log Files & Locations
```
📁 Application Logs (in EDL_DATA_DIR, default data/):
├── audit_logs.json             # User activity and security events
├── teams_logs.json             # Teams notification history
└── Web server / PHP-FPM logs   # PHP errors (display is off unless EDL_DEBUG is set)

📁 Monitoring Endpoints:
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
| **Permission denied errors**        | PHP needs write access to the data directory and `edl-files/` themselves (files are replaced atomically) |
| **Nobody can log in on a new install** | Create accounts with `sudo -u www-data php user_setup.php` |
| **Okta login failures**             | Verify redirect URI matches configuration exactly |
| **Teams notifications not working** | Test webhook URL independently in Teams |
| **Empty EDL files**                 | Ensure entries are approved and marked as active |
| **Session timeout issues**          | Adjust `SESSION_TIMEOUT` in configuration |

### 🐛 Debug Steps
1. Review web server / PHP-FPM error logs for detailed error information
2. On a non-production instance, temporarily enable `EDL_DEBUG` to display PHP errors
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
