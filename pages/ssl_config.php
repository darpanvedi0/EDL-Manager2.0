<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_permission('manage');

$page_title = 'SSL/TLS Configuration';
$error_message = '';
$success_message = '';

// SSL configuration file
$ssl_config_file = DATA_DIR . '/ssl_config.json';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = sanitize_input($_POST['action'] ?? '');
        
        if ($action === 'save_ssl_config') {
            $ssl_config = [
                'enabled' => ($_POST['ssl_enabled'] ?? 'off') === 'on',
                'force_https' => ($_POST['force_https'] ?? 'off') === 'on',
                'domain_name' => sanitize_input($_POST['domain_name'] ?? ''),
                'certificate_path' => sanitize_input($_POST['certificate_path'] ?? ''),
                'private_key_path' => sanitize_input($_POST['private_key_path'] ?? ''),
                'certificate_chain_path' => sanitize_input($_POST['certificate_chain_path'] ?? ''),
                'ssl_protocols' => array_map('sanitize_input', $_POST['ssl_protocols'] ?? ['TLSv1.2', 'TLSv1.3']),
                'cipher_suites' => sanitize_input($_POST['cipher_suites'] ?? 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'),
                'hsts_enabled' => ($_POST['hsts_enabled'] ?? 'off') === 'on',
                'hsts_max_age' => intval($_POST['hsts_max_age'] ?? 31536000),
                'edl_http_port' => intval($_POST['edl_http_port'] ?? 80),
                'edl_https_redirect' => ($_POST['edl_https_redirect'] ?? 'off') === 'on',
                'auto_redirect_http' => ($_POST['auto_redirect_http'] ?? 'off') === 'on',
                'updated_at' => date('c'),
                'updated_by' => $_SESSION['username']
            ];
            
            // Validation
            $errors = [];
            
            if ($ssl_config['enabled']) {
                if (empty($ssl_config['domain_name'])) {
                    $errors[] = 'Domain name is required when SSL is enabled';
                }
                if (empty($ssl_config['certificate_path'])) {
                    $errors[] = 'Certificate path is required when SSL is enabled';
                }
                if (empty($ssl_config['private_key_path'])) {
                    $errors[] = 'Private key path is required when SSL is enabled';
                }
                
                // Validate certificate files exist
                if (!empty($ssl_config['certificate_path']) && !file_exists($ssl_config['certificate_path'])) {
                    $errors[] = 'Certificate file does not exist: ' . $ssl_config['certificate_path'];
                }
                if (!empty($ssl_config['private_key_path']) && !file_exists($ssl_config['private_key_path'])) {
                    $errors[] = 'Private key file does not exist: ' . $ssl_config['private_key_path'];
                }
                if (!empty($ssl_config['certificate_chain_path']) && !file_exists($ssl_config['certificate_chain_path'])) {
                    $errors[] = 'Certificate chain file does not exist: ' . $ssl_config['certificate_chain_path'];
                }
            }
            
            if (empty($errors)) {
                if (write_json_file($ssl_config_file, $ssl_config)) {
                    show_flash('SSL/TLS configuration saved successfully! Please update your web server configuration.', 'success');
                    
                    // Generate web server configuration files
                    generateWebServerConfigs($ssl_config);
                    
                    // Add audit log
                    $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
                    $audit_logs[] = [
                        'id' => uniqid('audit_', true),
                        'timestamp' => date('c'),
                        'action' => 'ssl_config_update',
                        'entry' => 'SSL/TLS Configuration',
                        'user' => $_SESSION['username'],
                        'details' => 'Updated SSL/TLS configuration - Enabled: ' . ($ssl_config['enabled'] ? 'Yes' : 'No')
                    ];
                    write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
                    
                    header('Location: ssl_config.php');
                    exit;
                } else {
                    $error_message = 'Failed to save SSL/TLS configuration.';
                }
            } else {
                $error_message = implode('<br>', $errors);
            }
        }
        
        if ($action === 'test_ssl') {
            $domain = sanitize_input($_POST['domain_name'] ?? '');
            if (empty($domain)) {
                $error_message = 'Please enter domain name first.';
            } else {
                $test_result = testSSLConfiguration($domain);
                if ($test_result['success']) {
                    show_flash('SSL test successful: ' . $test_result['message'], 'success');
                } else {
                    $error_message = 'SSL test failed: ' . $test_result['message'];
                }
            }
        }
        
        if ($action === 'generate_csr') {
            $domain = sanitize_input($_POST['domain_name'] ?? '');
            $country = sanitize_input($_POST['csr_country'] ?? 'US');
            $state = sanitize_input($_POST['csr_state'] ?? '');
            $city = sanitize_input($_POST['csr_city'] ?? '');
            $organization = sanitize_input($_POST['csr_organization'] ?? '');
            $email = sanitize_input($_POST['csr_email'] ?? '');
            
            if (empty($domain)) {
                $error_message = 'Domain name is required to generate CSR.';
            } else {
                $csr_result = generateCSR($domain, $country, $state, $city, $organization, $email);
                if ($csr_result['success']) {
                    show_flash('CSR generated successfully. Check the generated files.', 'success');
                } else {
                    $error_message = 'CSR generation failed: ' . $csr_result['message'];
                }
            }
        }
    }
}

// Load current configuration
$ssl_config = read_json_file($ssl_config_file);
if (empty($ssl_config)) {
    $ssl_config = [
        'enabled' => false,
        'force_https' => true,
        'domain_name' => $_SERVER['HTTP_HOST'] ?? 'edl-manager.company.com',
        'certificate_path' => '/etc/ssl/certs/edl-manager.crt',
        'private_key_path' => '/etc/ssl/private/edl-manager.key',
        'certificate_chain_path' => '/etc/ssl/certs/edl-manager-chain.crt',
        'ssl_protocols' => ['TLSv1.2', 'TLSv1.3'],
        'cipher_suites' => 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS',
        'hsts_enabled' => true,
        'hsts_max_age' => 31536000,
        'edl_http_port' => 80,
        'edl_https_redirect' => false,
        'auto_redirect_http' => true
    ];
}

// Helper functions
function testSSLConfiguration($domain) {
    $url = "https://{$domain}";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $ssl_info = curl_getinfo($ch, CURLINFO_CERTINFO);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($response === false) {
        return ['success' => false, 'message' => 'Connection failed: ' . $error];
    }
    
    if ($http_code >= 200 && $http_code < 400) {
        return ['success' => true, 'message' => "SSL connection successful (HTTP {$http_code})"];
    } else {
        return ['success' => false, 'message' => "HTTP error: {$http_code}"];
    }
}

function generateCSR($domain, $country, $state, $city, $organization, $email) {
    if (!extension_loaded('openssl')) {
        return ['success' => false, 'message' => 'OpenSSL extension not available'];
    }
    
    $ssl_dir = DATA_DIR . '/ssl';
    if (!is_dir($ssl_dir)) {
        mkdir($ssl_dir, 0700, true);
    }
    
    $distinguished_name = [
        'countryName' => $country,
        'stateOrProvinceName' => $state,
        'localityName' => $city,
        'organizationName' => $organization,
        'organizationalUnitName' => 'IT Department',
        'commonName' => $domain,
        'emailAddress' => $email
    ];
    
    $config = [
        'digest_alg' => 'sha256',
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
    
    try {
        // Generate private key
        $private_key = openssl_pkey_new($config);
        if (!$private_key) {
            return ['success' => false, 'message' => 'Failed to generate private key'];
        }
        
        // Generate CSR
        $csr = openssl_csr_new($distinguished_name, $private_key, $config);
        if (!$csr) {
            return ['success' => false, 'message' => 'Failed to generate CSR'];
        }
        
        // Export CSR and private key
        openssl_csr_export($csr, $csr_string);
        openssl_pkey_export($private_key, $private_key_string);
        
        // Save files
        file_put_contents($ssl_dir . '/edl-manager.csr', $csr_string);
        file_put_contents($ssl_dir . '/edl-manager.key', $private_key_string);
        chmod($ssl_dir . '/edl-manager.key', 0600);
        
        return ['success' => true, 'message' => "CSR and private key generated in {$ssl_dir}/"];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function generateWebServerConfigs($ssl_config) {
    $configs_dir = DATA_DIR . '/webserver_configs';
    if (!is_dir($configs_dir)) {
        mkdir($configs_dir, 0755, true);
    }
    
    // Generate Apache configuration
    $apache_config = generateApacheConfig($ssl_config);
    file_put_contents($configs_dir . '/apache_ssl.conf', $apache_config);
    
    // Generate Nginx configuration
    $nginx_config = generateNginxConfig($ssl_config);
    file_put_contents($configs_dir . '/nginx_ssl.conf', $nginx_config);
    
    // Generate .htaccess for SSL redirect
    $htaccess_config = generateHtaccessConfig($ssl_config);
    file_put_contents($configs_dir . '/.htaccess', $htaccess_config);
}

function generateApacheConfig($ssl_config) {
    $config = "# EDL Manager SSL Configuration for Apache\n";
    $config .= "# Generated on " . date('Y-m-d H:i:s') . "\n\n";
    
    if ($ssl_config['enabled']) {
        $config .= "<VirtualHost *:443>\n";
        $config .= "    ServerName {$ssl_config['domain_name']}\n";
        $config .= "    DocumentRoot /var/www/html/edl-manager\n\n";
        
        $config .= "    # SSL Configuration\n";
        $config .= "    SSLEngine on\n";
        $config .= "    SSLCertificateFile {$ssl_config['certificate_path']}\n";
        $config .= "    SSLCertificateKeyFile {$ssl_config['private_key_path']}\n";
        
        if (!empty($ssl_config['certificate_chain_path'])) {
            $config .= "    SSLCertificateChainFile {$ssl_config['certificate_chain_path']}\n";
        }
        
        $config .= "    SSLProtocol " . implode(' ', $ssl_config['ssl_protocols']) . "\n";
        $config .= "    SSLCipherSuite {$ssl_config['cipher_suites']}\n";
        $config .= "    SSLHonorCipherOrder on\n\n";
        
        if ($ssl_config['hsts_enabled']) {
            $config .= "    # HSTS (HTTP Strict Transport Security)\n";
            $config .= "    Header always set Strict-Transport-Security \"max-age={$ssl_config['hsts_max_age']}; includeSubDomains; preload\"\n\n";
        }
        
        $config .= "    # Security Headers\n";
        $config .= "    Header always set X-Content-Type-Options nosniff\n";
        $config .= "    Header always set X-Frame-Options DENY\n";
        $config .= "    Header always set X-XSS-Protection \"1; mode=block\"\n\n";
        
        $config .= "</VirtualHost>\n\n";
    }
    
    // HTTP VirtualHost for EDL files
    $config .= "<VirtualHost *:{$ssl_config['edl_http_port']}>\n";
    $config .= "    ServerName {$ssl_config['domain_name']}\n";
    $config .= "    DocumentRoot /var/www/html/edl-manager\n\n";
    
    $config .= "    # Only allow access to EDL files\n";
    $config .= "    <Directory \"/var/www/html/edl-manager\">\n";
    $config .= "        Order deny,allow\n";
    $config .= "        Deny from all\n";
    $config .= "    </Directory>\n\n";
    
    $config .= "    <Directory \"/var/www/html/edl-manager/edl-files\">\n";
    $config .= "        Order allow,deny\n";
    $config .= "        Allow from all\n";
    $config .= "        <Files \"*.txt\">\n";
    $config .= "            Header set Content-Type \"text/plain\"\n";
    $config .= "            Header set Cache-Control \"no-cache, must-revalidate\"\n";
    $config .= "        </Files>\n";
    $config .= "    </Directory>\n\n";
    
    if ($ssl_config['auto_redirect_http'] && $ssl_config['enabled']) {
        $config .= "    # Redirect all non-EDL requests to HTTPS\n";
        $config .= "    RewriteEngine On\n";
        $config .= "    RewriteCond %{REQUEST_URI} !^/edl-files/\n";
        $config .= "    RewriteRule ^(.*)$ https://{$ssl_config['domain_name']}/$1 [R=301,L]\n";
    }
    
    $config .= "</VirtualHost>\n";
    
    return $config;
}

function generateNginxConfig($ssl_config) {
    $config = "# EDL Manager SSL Configuration for Nginx\n";
    $config .= "# Generated on " . date('Y-m-d H:i:s') . "\n\n";
    
    if ($ssl_config['enabled']) {
        $config .= "server {\n";
        $config .= "    listen 443 ssl http2;\n";
        $config .= "    server_name {$ssl_config['domain_name']};\n";
        $config .= "    root /var/www/html/edl-manager;\n";
        $config .= "    index index.php index.html;\n\n";
        
        $config .= "    # SSL Configuration\n";
        $config .= "    ssl_certificate {$ssl_config['certificate_path']};\n";
        $config .= "    ssl_certificate_key {$ssl_config['private_key_path']};\n";
        $config .= "    ssl_protocols " . implode(' ', $ssl_config['ssl_protocols']) . ";\n";
        $config .= "    ssl_ciphers {$ssl_config['cipher_suites']};\n";
        $config .= "    ssl_prefer_server_ciphers on;\n\n";
        
        if ($ssl_config['hsts_enabled']) {
            $config .= "    # HSTS\n";
            $config .= "    add_header Strict-Transport-Security \"max-age={$ssl_config['hsts_max_age']}; includeSubDomains; preload\" always;\n\n";
        }
        
        $config .= "    # Security Headers\n";
        $config .= "    add_header X-Content-Type-Options nosniff always;\n";
        $config .= "    add_header X-Frame-Options DENY always;\n";
        $config .= "    add_header X-XSS-Protection \"1; mode=block\" always;\n\n";
        
        $config .= "    # PHP Configuration\n";
        $config .= "    location ~ \\.php$ {\n";
        $config .= "        fastcgi_pass unix:/var/run/php/php-fpm.sock;\n";
        $config .= "        fastcgi_index index.php;\n";
        $config .= "        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;\n";
        $config .= "        include fastcgi_params;\n";
        $config .= "    }\n";
        $config .= "}\n\n";
    }
    
    // HTTP server for EDL files
    $config .= "server {\n";
    $config .= "    listen {$ssl_config['edl_http_port']};\n";
    $config .= "    server_name {$ssl_config['domain_name']};\n";
    $config .= "    root /var/www/html/edl-manager;\n\n";
    
    $config .= "    # Only allow EDL files\n";
    $config .= "    location / {\n";
    $config .= "        deny all;\n";
    $config .= "    }\n\n";
    
    $config .= "    location /edl-files/ {\n";
    $config .= "        location ~ \\.txt$ {\n";
    $config .= "            add_header Content-Type \"text/plain\";\n";
    $config .= "            add_header Cache-Control \"no-cache, must-revalidate\";\n";
    $config .= "            allow all;\n";
    $config .= "        }\n";
    $config .= "    }\n\n";
    
    if ($ssl_config['auto_redirect_http'] && $ssl_config['enabled']) {
        $config .= "    # Redirect non-EDL requests to HTTPS\n";
        $config .= "    location ~ ^(?!/edl-files/) {\n";
        $config .= "        return 301 https://\$server_name\$request_uri;\n";
        $config .= "    }\n";
    }
    
    $config .= "}\n";
    
    return $config;
}

function generateHtaccessConfig($ssl_config) {
    $config = "# EDL Manager .htaccess Configuration\n";
    $config .= "# Generated on " . date('Y-m-d H:i:s') . "\n\n";
    
    if ($ssl_config['auto_redirect_http'] && $ssl_config['enabled']) {
        $config .= "# Force HTTPS except for EDL files\n";
        $config .= "RewriteEngine On\n";
        $config .= "RewriteCond %{HTTPS} off\n";
        $config .= "RewriteCond %{REQUEST_URI} !^/edl-files/\n";
        $config .= "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n";
    }
    
    if ($ssl_config['hsts_enabled']) {
        $config .= "# HSTS Header\n";
        $config .= "<IfModule mod_headers.c>\n";
        $config .= "    Header always set Strict-Transport-Security \"max-age={$ssl_config['hsts_max_age']}; includeSubDomains; preload\"\n";
        $config .= "</IfModule>\n\n";
    }
    
    $config .= "# Security Headers\n";
    $config .= "<IfModule mod_headers.c>\n";
    $config .= "    Header always set X-Content-Type-Options nosniff\n";
    $config .= "    Header always set X-Frame-Options DENY\n";
    $config .= "    Header always set X-XSS-Protection \"1; mode=block\"\n";
    $config .= "</IfModule>\n\n";
    
    $config .= "# EDL Files Configuration\n";
    $config .= "<Files \"*.txt\">\n";
    $config .= "    <IfModule mod_headers.c>\n";
    $config .= "        Header set Content-Type \"text/plain\"\n";
    $config .= "        Header set Cache-Control \"no-cache, must-revalidate\"\n";
    $config .= "    </IfModule>\n";
    $config .= "</Files>\n";
    
    return $config;
}

// Include the centralized header
require_once '../includes/header.php';
?>

<div class="container mt-4">

<?php if ($error_message): ?>
<div class="alert alert-danger alert-dismissible fade show">
    <i class="fas fa-exclamation-triangle"></i>
    <?php echo $error_message; ?>
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>
<?php endif; ?>

<!-- Page Header -->
<div class="page-header">
    <h1 class="mb-2">
        <i class="fas fa-lock me-2"></i>
        SSL/TLS Configuration
    </h1>
    <p class="mb-0 opacity-75">Configure HTTPS encryption and security settings for EDL Manager</p>
</div>

<!-- Status Overview -->
<div class="row mb-4">
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="status-indicator <?php echo $ssl_config['enabled'] ? 'status-enabled' : 'status-disabled'; ?> mb-2">
                    <i class="fas fa-<?php echo $ssl_config['enabled'] ? 'lock' : 'unlock'; ?> me-1"></i>
                    <?php echo $ssl_config['enabled'] ? 'Enabled' : 'Disabled'; ?>
                </div>
                <h6 class="card-title">SSL Status</h6>
            </div>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="status-indicator <?php echo $ssl_config['force_https'] ? 'status-enabled' : 'status-disabled'; ?> mb-2">
                    <i class="fas fa-<?php echo $ssl_config['force_https'] ? 'shield-alt' : 'exclamation-triangle'; ?> me-1"></i>
                    <?php echo $ssl_config['force_https'] ? 'Enforced' : 'Optional'; ?>
                </div>
                <h6 class="card-title">HTTPS Redirect</h6>
            </div>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="status-indicator <?php echo $ssl_config['hsts_enabled'] ? 'status-enabled' : 'status-disabled'; ?> mb-2">
                    <i class="fas fa-<?php echo $ssl_config['hsts_enabled'] ? 'check-circle' : 'times-circle'; ?> me-1"></i>
                    <?php echo $ssl_config['hsts_enabled'] ? 'Active' : 'Inactive'; ?>
                </div>
                <h6 class="card-title">HSTS Security</h6>
            </div>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 mb-3">
        <div class="card">
            <div class="card-body text-center">
                <div class="mb-2">
                    <i class="fas fa-server fa-2x text-info"></i>
                </div>
                <h6 class="card-title">EDL Port <?php echo $ssl_config['edl_http_port']; ?></h6>
                <small class="text-muted">HTTP access for .txt files</small>
            </div>
        </div>
    </div>
</div>

<!-- SSL/TLS Information Card -->
<div class="ssl-card">
    <div class="d-flex align-items-center mb-3">
        <i class="fas fa-lock fa-3x me-3"></i>
        <div>
            <h4 class="mb-1">SSL/TLS Security</h4>
            <p class="mb-0">Secure your EDL Manager with industry-standard encryption while keeping EDL files accessible via HTTP</p>
        </div>
    </div>
</div>

<!-- Configuration Form -->
<div class="card">
    <div class="card-header">
        <h5 class="mb-0">
            <i class="fas fa-cog text-primary me-2"></i> SSL/TLS Settings
        </h5>
    </div>
    <div class="card-body">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
            <input type="hidden" name="action" value="save_ssl_config">
            
            <!-- Basic SSL Settings -->
            <div class="ssl-section">
                <h6><i class="fas fa-toggle-on text-success me-2"></i>Basic SSL Configuration</h6>
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label fw-bold">Enable SSL/TLS</label>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="ssl_enabled" name="ssl_enabled" 
                                       <?php echo $ssl_config['enabled'] ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="ssl_enabled">
                                    Enable HTTPS encryption for the application
                                </label>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label fw-bold">Force HTTPS Redirect</label>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="force_https" name="force_https" 
                                       <?php echo $ssl_config['force_https'] ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="force_https">
                                    Automatically redirect HTTP to HTTPS
                                </label>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="domain_name" class="form-label fw-bold">Domain Name <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="domain_name" name="domain_name" 
                                   value="<?php echo htmlspecialchars($ssl_config['domain_name']); ?>"
                                   placeholder="edl-manager.company.com" required>
                            <div class="form-text">Fully qualified domain name for your EDL Manager</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="edl_http_port" class="form-label fw-bold">EDL HTTP Port</label>
                            <input type="number" class="form-control" id="edl_http_port" name="edl_http_port" 
                                   value="<?php echo $ssl_config['edl_http_port']; ?>"
                                   min="1" max="65535">
                            <div class="form-text">Port for HTTP access to EDL .txt files (default: 80)</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Certificate Configuration -->
            <div class="ssl-section">
                <h6><i class="fas fa-certificate text-warning me-2"></i>Certificate Configuration</h6>
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="certificate_path" class="form-label fw-bold">SSL Certificate Path <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="certificate_path" name="certificate_path" 
                                   value="<?php echo htmlspecialchars($ssl_config['certificate_path']); ?>"
                                   placeholder="/etc/ssl/certs/edl-manager.crt">
                            <div class="form-text">Full path to your SSL certificate file</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="private_key_path" class="form-label fw-bold">Private Key Path <span class="text-danger">*</span></label>
                            <input type="text" class="form-control" id="private_key_path" name="private_key_path" 
                                   value="<?php echo htmlspecialchars($ssl_config['private_key_path']); ?>"
                                   placeholder="/etc/ssl/private/edl-manager.key">
                            <div class="form-text">Full path to your private key file</div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="certificate_chain_path" class="form-label fw-bold">Certificate Chain Path</label>
                            <input type="text" class="form-control" id="certificate_chain_path" name="certificate_chain_path" 
                                   value="<?php echo htmlspecialchars($ssl_config['certificate_chain_path']); ?>"
                                   placeholder="/etc/ssl/certs/edl-manager-chain.crt">
                            <div class="form-text">Optional: Path to certificate chain/intermediate certificates</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Security Settings -->
            <div class="ssl-section">
                <h6><i class="fas fa-shield-alt text-info me-2"></i>Security Settings</h6>
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="ssl_protocols" class="form-label fw-bold">SSL Protocols</label>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" name="ssl_protocols[]" value="TLSv1.2" id="tls12"
                                       <?php echo in_array('TLSv1.2', $ssl_config['ssl_protocols']) ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="tls12">TLS 1.2</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" name="ssl_protocols[]" value="TLSv1.3" id="tls13"
                                       <?php echo in_array('TLSv1.3', $ssl_config['ssl_protocols']) ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="tls13">TLS 1.3 (Recommended)</label>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label fw-bold">HSTS (HTTP Strict Transport Security)</label>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="hsts_enabled" name="hsts_enabled" 
                                       <?php echo $ssl_config['hsts_enabled'] ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="hsts_enabled">
                                    Enable HSTS for enhanced security
                                </label>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="cipher_suites" class="form-label fw-bold">Cipher Suites</label>
                            <textarea class="form-control" id="cipher_suites" name="cipher_suites" rows="3"
                                      placeholder="Enter cipher suites configuration"><?php echo htmlspecialchars($ssl_config['cipher_suites']); ?></textarea>
                            <div class="form-text">Advanced: SSL cipher suites configuration</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="hsts_max_age" class="form-label fw-bold">HSTS Max Age (seconds)</label>
                            <input type="number" class="form-control" id="hsts_max_age" name="hsts_max_age" 
                                   value="<?php echo $ssl_config['hsts_max_age']; ?>"
                                   min="3600" max="63072000">
                            <div class="form-text">Default: 31536000 (1 year)</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- EDL Specific Settings -->
            <div class="ssl-section">
                <h6><i class="fas fa-list-alt text-secondary me-2"></i>EDL Specific Settings</h6>
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label fw-bold">EDL HTTPS Redirect</label>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="edl_https_redirect" name="edl_https_redirect" 
                                       <?php echo $ssl_config['edl_https_redirect'] ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="edl_https_redirect">
                                    Also redirect EDL file requests to HTTPS
                                </label>
                            </div>
                            <div class="form-text">Warning: This may break firewall integrations expecting HTTP</div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label class="form-label fw-bold">Auto HTTP Redirect</label>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="auto_redirect_http" name="auto_redirect_http" 
                                       <?php echo $ssl_config['auto_redirect_http'] ? 'checked' : ''; ?>>
                                <label class="form-check-label" for="auto_redirect_http">
                                    Redirect all HTTP requests except EDL files to HTTPS
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Action Buttons -->
            <div class="d-flex justify-content-between">
                <div>
                    <a href="../index.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i> Back to Dashboard
                    </a>
                    <button type="button" class="btn btn-info ms-2" onclick="testSSL()">
                        <i class="fas fa-vial"></i> Test SSL
                    </button>
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save Configuration
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Certificate Generation -->
<div class="card mt-4">
    <div class="card-header">
        <h5 class="mb-0">
            <i class="fas fa-key text-warning me-2"></i> Certificate Management
        </h5>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-6">
                <h6>Generate Certificate Signing Request (CSR)</h6>
                <p class="text-muted">Generate a CSR and private key for obtaining an SSL certificate from a Certificate Authority.</p>
                
                <form method="POST" class="mb-3">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="action" value="generate_csr">
                    <input type="hidden" name="domain_name" value="<?php echo htmlspecialchars($ssl_config['domain_name']); ?>">
                    
                    <div class="row g-2">
                        <div class="col-md-6">
                            <input type="text" class="form-control form-control-sm" name="csr_country" placeholder="Country (US)" value="US">
                        </div>
                        <div class="col-md-6">
                            <input type="text" class="form-control form-control-sm" name="csr_state" placeholder="State/Province">
                        </div>
                        <div class="col-md-6">
                            <input type="text" class="form-control form-control-sm" name="csr_city" placeholder="City">
                        </div>
                        <div class="col-md-6">
                            <input type="text" class="form-control form-control-sm" name="csr_organization" placeholder="Organization">
                        </div>
                        <div class="col-md-12">
                            <input type="email" class="form-control form-control-sm" name="csr_email" placeholder="Email Address">
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-warning btn-sm mt-2">
                        <i class="fas fa-certificate"></i> Generate CSR
                    </button>
                </form>
            </div>
            
            <div class="col-md-6">
                <h6>Certificate Options</h6>
                <div class="list-group list-group-flush">
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1">Let's Encrypt (Free)</h6>
                            <small>Recommended</small>
                        </div>
                        <p class="mb-1">Free SSL certificates with automatic renewal.</p>
                        <small>Use Certbot: <code>certbot --apache -d <?php echo htmlspecialchars($ssl_config['domain_name']); ?></code></small>
                    </div>
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1">Commercial CA</h6>
                            <small>DigiCert, Comodo, etc.</small>
                        </div>
                        <p class="mb-1">Purchase from commercial Certificate Authority.</p>
                        <small>Use generated CSR to purchase certificate</small>
                    </div>
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1">Self-Signed</h6>
                            <small>Testing only</small>
                        </div>
                        <p class="mb-1">For development and testing environments.</p>
                        <small>Not recommended for production</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Web Server Configuration -->
<div class="card mt-4">
    <div class="card-header">
        <h5 class="mb-0">
            <i class="fas fa-server text-info me-2"></i> Web Server Configuration
        </h5>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-6">
                <h6>Apache Configuration</h6>
                <p class="text-muted">Generated Apache virtual host configuration for SSL.</p>
                <div class="config-preview">
<?php if ($ssl_config['enabled']): ?>
# Apache SSL Configuration
&lt;VirtualHost *:443&gt;
    ServerName <?php echo htmlspecialchars($ssl_config['domain_name']); ?>

    DocumentRoot /var/www/html/edl-manager
    
    SSLEngine on
    SSLCertificateFile <?php echo htmlspecialchars($ssl_config['certificate_path']); ?>

    SSLCertificateKeyFile <?php echo htmlspecialchars($ssl_config['private_key_path']); ?>

    SSLProtocol <?php echo implode(' ', $ssl_config['ssl_protocols']); ?>

    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=<?php echo $ssl_config['hsts_max_age']; ?>"
&lt;/VirtualHost&gt;

# HTTP for EDL files only
&lt;VirtualHost *:<?php echo $ssl_config['edl_http_port']; ?>&gt;
    ServerName <?php echo htmlspecialchars($ssl_config['domain_name']); ?>

    &lt;Directory "/var/www/html/edl-manager/edl-files"&gt;
        Allow from all
    &lt;/Directory&gt;
    
    # Redirect non-EDL to HTTPS
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/edl-files/
    RewriteRule ^(.*)$ https://<?php echo htmlspecialchars($ssl_config['domain_name']); ?>/$1 [R=301,L]
&lt;/VirtualHost&gt;
<?php else: ?>
# SSL is disabled. Configure SSL settings first.
<?php endif; ?>
                </div>
                <button type="button" class="btn btn-outline-primary btn-sm mt-2" onclick="downloadConfig('apache')">
                    <i class="fas fa-download"></i> Download Apache Config
                </button>
            </div>
            
            <div class="col-md-6">
                <h6>Nginx Configuration</h6>
                <p class="text-muted">Generated Nginx server block configuration for SSL.</p>
                <div class="config-preview">
<?php if ($ssl_config['enabled']): ?>
# Nginx SSL Configuration
server {
    listen 443 ssl http2;
    server_name <?php echo htmlspecialchars($ssl_config['domain_name']); ?>;

    root /var/www/html/edl-manager;
    index index.php;
    
    ssl_certificate <?php echo htmlspecialchars($ssl_config['certificate_path']); ?>;

    ssl_certificate_key <?php echo htmlspecialchars($ssl_config['private_key_path']); ?>;

    ssl_protocols <?php echo implode(' ', $ssl_config['ssl_protocols']); ?>;

    
    add_header Strict-Transport-Security "max-age=<?php echo $ssl_config['hsts_max_age']; ?>";
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
    }
}

# HTTP for EDL files
server {
    listen <?php echo $ssl_config['edl_http_port']; ?>;

    server_name <?php echo htmlspecialchars($ssl_config['domain_name']); ?>;

    
    location /edl-files/ {
        root /var/www/html/edl-manager;
        allow all;
    }
    
    location ~ ^(?!/edl-files/) {
        return 301 https://$server_name$request_uri;
    }
}
<?php else: ?>
# SSL is disabled. Configure SSL settings first.
<?php endif; ?>
                </div>
                <button type="button" class="btn btn-outline-primary btn-sm mt-2" onclick="downloadConfig('nginx')">
                    <i class="fas fa-download"></i> Download Nginx Config
                </button>
            </div>
        </div>
        
        <hr>
        
        <div class="row">
            <div class="col-md-12">
                <h6>.htaccess Configuration</h6>
                <p class="text-muted">Generated .htaccess file for Apache with SSL redirects and security headers.</p>
                <div class="config-preview">
<?php if ($ssl_config['enabled'] && $ssl_config['auto_redirect_http']): ?>
# Force HTTPS except for EDL files
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteCond %{REQUEST_URI} !^/edl-files/
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Security Headers
&lt;IfModule mod_headers.c&gt;
    Header always set Strict-Transport-Security "max-age=<?php echo $ssl_config['hsts_max_age']; ?>"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
&lt;/IfModule&gt;

# EDL Files
&lt;Files "*.txt"&gt;
    Header set Content-Type "text/plain"
    Header set Cache-Control "no-cache, must-revalidate"
&lt;/Files&gt;
<?php else: ?>
# SSL redirect is disabled. Enable auto redirect to generate .htaccess rules.
<?php endif; ?>
                </div>
                <button type="button" class="btn btn-outline-primary btn-sm mt-2" onclick="downloadConfig('htaccess')">
                    <i class="fas fa-download"></i> Download .htaccess
                </button>
            </div>
        </div>
    </div>
</div>

<!-- SSL Information -->
<div class="card mt-4">
    <div class="card-header">
        <h5 class="mb-0">
            <i class="fas fa-info-circle text-primary me-2"></i> SSL/TLS Implementation Guide
        </h5>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-6">
                <h6>Why SSL/TLS for EDL Manager?</h6>
                <ul class="list-unstyled">
                    <li><i class="fas fa-check text-success me-2"></i> Required for Okta SSO integration</li>
                    <li><i class="fas fa-check text-success me-2"></i> Protects authentication credentials</li>
                    <li><i class="fas fa-check text-success me-2"></i> Encrypts admin interface traffic</li>
                    <li><i class="fas fa-check text-success me-2"></i> Prevents session hijacking</li>
                    <li><i class="fas fa-check text-success me-2"></i> Industry security best practice</li>
                </ul>
            </div>
            
            <div class="col-md-6">
                <h6>EDL Files HTTP Access</h6>
                <ul class="list-unstyled">
                    <li><i class="fas fa-info text-info me-2"></i> Firewall devices expect HTTP access</li>
                    <li><i class="fas fa-info text-info me-2"></i> .txt files remain on port 80</li>
                    <li><i class="fas fa-info text-info me-2"></i> Admin interface uses HTTPS</li>
                    <li><i class="fas fa-info text-info me-2"></i> Separate virtual hosts handle both</li>
                    <li><i class="fas fa-info text-info me-2"></i> Best of both worlds approach</li>
                </ul>
            </div>
        </div>
        
        <hr>
        
        <div class="row">
            <div class="col-md-12">
                <h6>Implementation Steps</h6>
                <ol class="list-group list-group-numbered">
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Configure Domain and Paths</div>
                            Set your domain name and certificate file paths in the form above
                        </div>
                        <span class="badge bg-primary rounded-pill">1</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Obtain SSL Certificate</div>
                            Generate CSR or use Let's Encrypt to get your SSL certificate
                        </div>
                        <span class="badge bg-primary rounded-pill">2</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Update Web Server Configuration</div>
                            Download and apply the generated Apache/Nginx configuration
                        </div>
                        <span class="badge bg-primary rounded-pill">3</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Test SSL Configuration</div>
                            Use the "Test SSL" button to verify your setup
                        </div>
                        <span class="badge bg-primary rounded-pill">4</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Enable SSL in Application</div>
                            Save the configuration to enable SSL features
                        </div>
                        <span class="badge bg-success rounded-pill">5</span>
                    </li>
                </ol>
            </div>
        </div>
    </div>
</div>

</div>
<!-- End container -->

<script>
function testSSL() {
    const domain = document.getElementById('domain_name').value;
    if (!domain) {
        alert('Please enter domain name first');
        return;
    }
    
    const form = document.createElement('form');
    form.method = 'POST';
    form.style.display = 'none';
    
    const csrfToken = document.createElement('input');
    csrfToken.type = 'hidden';
    csrfToken.name = 'csrf_token';
    csrfToken.value = '<?php echo generate_csrf_token(); ?>';
    
    const action = document.createElement('input');
    action.type = 'hidden';
    action.name = 'action';
    action.value = 'test_ssl';
    
    const domainInput = document.createElement('input');
    domainInput.type = 'hidden';
    domainInput.name = 'domain_name';
    domainInput.value = domain;
    
    form.appendChild(csrfToken);
    form.appendChild(action);
    form.appendChild(domainInput);
    
    document.body.appendChild(form);
    form.submit();
}

function downloadConfig(type) {
    const domain = '<?php echo htmlspecialchars($ssl_config['domain_name']); ?>';
    const sslEnabled = <?php echo $ssl_config['enabled'] ? 'true' : 'false'; ?>;
    
    if (!sslEnabled) {
        alert('Please enable SSL and save configuration first');
        return;
    }
    
    // Create a link to download the configuration file
    const link = document.createElement('a');
    link.href = '../data/webserver_configs/' + type + (type === 'htaccess' ? '' : '_ssl') + (type === 'htaccess' ? '.htaccess' : '.conf');
    link.download = type + (type === 'htaccess' ? '.htaccess' : '_ssl.conf');
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    showNotification('Configuration file download started', 'success');
}

// Auto-enable related settings when SSL is enabled
document.getElementById('ssl_enabled').addEventListener('change', function() {
    const httpsRedirect = document.getElementById('force_https');
    const hstsEnabled = document.getElementById('hsts_enabled');
    const autoRedirect = document.getElementById('auto_redirect_http');
    
    if (this.checked) {
        httpsRedirect.checked = true;
        hstsEnabled.checked = true;
        autoRedirect.checked = true;
    }
});

// Validate certificate paths
function validatePaths() {
    const certPath = document.getElementById('certificate_path').value;
    const keyPath = document.getElementById('private_key_path').value;
    const sslEnabled = document.getElementById('ssl_enabled').checked;
    
    if (sslEnabled && (!certPath || !keyPath)) {
        showNotification('Certificate and private key paths are required when SSL is enabled', 'warning');
        return false;
    }
    
    return true;
}

// Form validation
document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form[method="POST"]');
    const sslEnabledCheckbox = document.getElementById('ssl_enabled');
    
    if (form) {
        form.addEventListener('submit', function(e) {
            if (!validatePaths()) {
                e.preventDefault();
                return false;
            }
        });
    }
    
    // Auto-update domain in configuration previews
    document.getElementById('domain_name').addEventListener('input', function() {
        const domain = this.value;
        // Update all domain references in the preview configs
        // This would be enhanced with real-time preview updates
    });
});
</script>

<?php require_once '../includes/footer.php'; ?>