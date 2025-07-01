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
            $key_size = intval($_POST['key_size'] ?? 2048);
            
            // Process SAN entries
            $san_entries = [];
            if (!empty($_POST['san_entries'])) {
                $san_lines = explode("\n", $_POST['san_entries']);
                foreach ($san_lines as $san_line) {
                    $san_entry = trim($san_line);
                    if (!empty($san_entry)) {
                        $san_entries[] = $san_entry;
                    }
                }
            }
            
            if (empty($domain)) {
                $error_message = 'Domain name is required to generate CSR.';
            } else {
                $csr_result = generateCSR($domain, $country, $state, $city, $organization, $email, $key_size, $san_entries);
                if ($csr_result['success']) {
                    show_flash('CSR and private key generated successfully. Files are ready for download.', 'success');
                } else {
                    $error_message = 'CSR generation failed: ' . $csr_result['message'];
                }
            }
        }
        
        if ($action === 'upload_certificates') {
            $upload_result = handleCertificateUpload();
            if ($upload_result['success']) {
                show_flash($upload_result['message'], 'success');
                header('Location: ssl_config.php');
                exit;
            } else {
                $error_message = $upload_result['message'];
            }
        }
    }
}

// Handle file downloads
if (isset($_GET['download'])) {
    $file_type = sanitize_input($_GET['download']);
    $ssl_dir = DATA_DIR . '/ssl';
    
    switch ($file_type) {
        case 'csr':
            $file_path = $ssl_dir . '/edl-manager.csr';
            $filename = 'edl-manager.csr';
            $content_type = 'application/pkcs10';
            break;
        case 'key':
            $file_path = $ssl_dir . '/edl-manager.key';
            $filename = 'edl-manager.key';
            $content_type = 'application/x-pem-file';
            break;
        default:
            $error_message = 'Invalid file type requested.';
            break;
    }
    
    if (isset($file_path) && file_exists($file_path)) {
        header('Content-Type: ' . $content_type);
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . filesize($file_path));
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        readfile($file_path);
        exit;
    } else {
        $error_message = 'File not found. Please generate CSR first.';
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

function generateCSR($domain, $country, $state, $city, $organization, $email, $key_size = 2048, $san_entries = []) {
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
        'private_key_bits' => $key_size,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
    
    // Add SAN extension if provided
    if (!empty($san_entries)) {
        $san_string = '';
        foreach ($san_entries as $index => $san_entry) {
            if ($index > 0) {
                $san_string .= ',';
            }
            // Determine if it's an IP or DNS name
            if (filter_var($san_entry, FILTER_VALIDATE_IP)) {
                $san_string .= 'IP:' . $san_entry;
            } else {
                $san_string .= 'DNS:' . $san_entry;
            }
        }
        
        $config['req_extensions'] = 'v3_req';
        $config['extensions'] = 'v3_req';
        $config['v3_req'] = [
            'subjectAltName' => $san_string
        ];
    }
    
    try {
        // Generate private key
        $private_key = openssl_pkey_new($config);
        if (!$private_key) {
            return ['success' => false, 'message' => 'Failed to generate private key: ' . openssl_error_string()];
        }
        
        // Generate CSR
        $csr = openssl_csr_new($distinguished_name, $private_key, $config);
        if (!$csr) {
            return ['success' => false, 'message' => 'Failed to generate CSR: ' . openssl_error_string()];
        }
        
        // Export CSR and private key
        openssl_csr_export($csr, $csr_string);
        openssl_pkey_export($private_key, $private_key_string);
        
        // Save files with timestamp
        $timestamp = date('Y-m-d_H-i-s');
        $csr_file = $ssl_dir . '/edl-manager.csr';
        $key_file = $ssl_dir . '/edl-manager.key';
        
        // Also save timestamped versions for backup
        $csr_backup = $ssl_dir . "/edl-manager_{$timestamp}.csr";
        $key_backup = $ssl_dir . "/edl-manager_{$timestamp}.key";
        
        file_put_contents($csr_file, $csr_string);
        file_put_contents($key_file, $private_key_string);
        file_put_contents($csr_backup, $csr_string);
        file_put_contents($key_backup, $private_key_string);
        
        chmod($key_file, 0600);
        chmod($key_backup, 0600);
        
        // Create info file with details
        $info = [
            'generated_at' => date('c'),
            'domain' => $domain,
            'key_size' => $key_size,
            'san_entries' => $san_entries,
            'distinguished_name' => $distinguished_name
        ];
        file_put_contents($ssl_dir . '/csr_info.json', json_encode($info, JSON_PRETTY_PRINT));
        
        return ['success' => true, 'message' => "CSR and private key generated successfully. Key size: {$key_size} bits."];
    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

function handleCertificateUpload() {
    $ssl_dir = DATA_DIR . '/ssl';
    if (!is_dir($ssl_dir)) {
        mkdir($ssl_dir, 0700, true);
    }
    
    $uploaded_files = [];
    $errors = [];
    
    // Handle certificate file upload
    if (isset($_FILES['cert_file']) && $_FILES['cert_file']['error'] === UPLOAD_ERR_OK) {
        $cert_content = file_get_contents($_FILES['cert_file']['tmp_name']);
        if (validateCertificateContent($cert_content, 'certificate')) {
            $cert_path = $ssl_dir . '/uploaded_certificate.crt';
            file_put_contents($cert_path, $cert_content);
            $uploaded_files[] = 'Certificate';
        } else {
            $errors[] = 'Invalid certificate file format';
        }
    }
    
    // Handle private key file upload
    if (isset($_FILES['key_file']) && $_FILES['key_file']['error'] === UPLOAD_ERR_OK) {
        $key_content = file_get_contents($_FILES['key_file']['tmp_name']);
        if (validateCertificateContent($key_content, 'private_key')) {
            $key_path = $ssl_dir . '/uploaded_private.key';
            file_put_contents($key_path, $key_content);
            chmod($key_path, 0600);
            $uploaded_files[] = 'Private Key';
        } else {
            $errors[] = 'Invalid private key file format';
        }
    }
    
    // Handle certificate chain file upload (optional)
    if (isset($_FILES['chain_file']) && $_FILES['chain_file']['error'] === UPLOAD_ERR_OK) {
        $chain_content = file_get_contents($_FILES['chain_file']['tmp_name']);
        if (validateCertificateContent($chain_content, 'certificate')) {
            $chain_path = $ssl_dir . '/uploaded_chain.crt';
            file_put_contents($chain_path, $chain_content);
            $uploaded_files[] = 'Certificate Chain';
        } else {
            $errors[] = 'Invalid certificate chain file format';
        }
    }
    
    if (!empty($errors)) {
        return ['success' => false, 'message' => 'Upload failed: ' . implode(', ', $errors)];
    }
    
    if (empty($uploaded_files)) {
        return ['success' => false, 'message' => 'No valid files were uploaded'];
    }
    
    // Log the upload
    $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
    $audit_logs[] = [
        'id' => uniqid('audit_', true),
        'timestamp' => date('c'),
        'action' => 'certificate_upload',
        'entry' => 'SSL Certificate Upload',
        'user' => $_SESSION['username'],
        'details' => 'Uploaded: ' . implode(', ', $uploaded_files)
    ];
    write_json_file(DATA_DIR . '/audit_logs.json', $audit_logs);
    
    return ['success' => true, 'message' => 'Successfully uploaded: ' . implode(', ', $uploaded_files)];
}

function validateCertificateContent($content, $type) {
    switch ($type) {
        case 'certificate':
            return (strpos($content, '-----BEGIN CERTIFICATE-----') !== false && 
                    strpos($content, '-----END CERTIFICATE-----') !== false);
        case 'private_key':
            return (strpos($content, '-----BEGIN PRIVATE KEY-----') !== false || 
                    strpos($content, '-----BEGIN RSA PRIVATE KEY-----') !== false);
        default:
            return false;
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

// Check if generated files exist for download
$ssl_dir = DATA_DIR . '/ssl';
$csr_exists = file_exists($ssl_dir . '/edl-manager.csr');
$key_exists = file_exists($ssl_dir . '/edl-manager.key');
$csr_info = [];
if (file_exists($ssl_dir . '/csr_info.json')) {
    $csr_info = json_decode(file_get_contents($ssl_dir . '/csr_info.json'), true);
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

<!-- Enhanced Certificate Management -->
<div class="card mt-4">
    <div class="card-header">
        <h5 class="mb-0">
            <i class="fas fa-key text-warning me-2"></i> Certificate Management
        </h5>
    </div>
    <div class="card-body">
        <div class="row">
            <!-- CSR Generation -->
            <div class="col-md-6">
                <h6><i class="fas fa-certificate me-2"></i>Generate Certificate Signing Request (CSR)</h6>
                <p class="text-muted">Generate a CSR and private key with support for Subject Alternative Names (SAN).</p>
                
                <form method="POST" class="mb-3">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="action" value="generate_csr">
                    <input type="hidden" name="domain_name" value="<?php echo htmlspecialchars($ssl_config['domain_name']); ?>">
                    
                    <div class="row g-2 mb-3">
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
                    
                    <div class="mb-3">
                        <label for="key_size" class="form-label fw-bold">Key Size</label>
                        <select class="form-select form-select-sm" name="key_size" id="key_size">
                            <option value="2048">2048 bits (Standard)</option>
                            <option value="3072">3072 bits (Enhanced)</option>
                            <option value="4096">4096 bits (Maximum)</option>
                        </select>
                    </div>
                    
                    <div class="mb-3">
                        <label for="san_entries" class="form-label fw-bold">Subject Alternative Names (SAN)</label>
                        <textarea class="form-control form-control-sm" name="san_entries" id="san_entries" rows="4" 
                                  placeholder="Enter additional domains/IPs (one per line)&#10;www.edl-manager.company.com&#10;edl.company.com&#10;192.168.1.100"></textarea>
                        <div class="form-text">One domain or IP per line. Mix of domains and IPs is supported.</div>
                    </div>
                    
                    <button type="submit" class="btn btn-warning btn-sm">
                        <i class="fas fa-certificate"></i> Generate CSR & Private Key
                    </button>
                </form>
                
                <!-- Download Generated Files -->
                <?php if ($csr_exists || $key_exists): ?>
                <div class="alert alert-success">
                    <h6 class="alert-heading"><i class="fas fa-check-circle"></i> Generated Files Available</h6>
                    <?php if (!empty($csr_info)): ?>
                        <p class="mb-2"><strong>Generated:</strong> <?php echo date('M j, Y H:i', strtotime($csr_info['generated_at'])); ?></p>
                        <p class="mb-2"><strong>Domain:</strong> <?php echo htmlspecialchars($csr_info['domain']); ?></p>
                        <p class="mb-2"><strong>Key Size:</strong> <?php echo $csr_info['key_size']; ?> bits</p>
                        <?php if (!empty($csr_info['san_entries'])): ?>
                            <p class="mb-2"><strong>SAN Entries:</strong> <?php echo implode(', ', $csr_info['san_entries']); ?></p>
                        <?php endif; ?>
                    <?php endif; ?>
                    <div class="d-flex gap-2 mt-3">
                        <?php if ($csr_exists): ?>
                            <a href="?download=csr" class="btn btn-outline-primary btn-sm">
                                <i class="fas fa-download"></i> Download CSR
                            </a>
                        <?php endif; ?>
                        <?php if ($key_exists): ?>
                            <a href="?download=key" class="btn btn-outline-danger btn-sm">
                                <i class="fas fa-download"></i> Download Private Key
                            </a>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>
            
            <!-- Certificate Upload -->
            <div class="col-md-6">
                <h6><i class="fas fa-upload me-2"></i>Upload SSL Certificates</h6>
                <p class="text-muted">Upload your SSL certificate files received from your Certificate Authority.</p>
                
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="action" value="upload_certificates">
                    
                    <div class="mb-3">
                        <label for="cert_file" class="form-label fw-bold">SSL Certificate (.crt, .pem)</label>
                        <input type="file" class="form-control form-control-sm" id="cert_file" name="cert_file" 
                               accept=".crt,.pem,.cer,.cert">
                        <div class="form-text">Main SSL certificate file</div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="key_file" class="form-label fw-bold">Private Key (.key, .pem)</label>
                        <input type="file" class="form-control form-control-sm" id="key_file" name="key_file" 
                               accept=".key,.pem">
                        <div class="form-text">Private key file (generated with CSR)</div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="chain_file" class="form-label fw-bold">Certificate Chain (Optional)</label>
                        <input type="file" class="form-control form-control-sm" id="chain_file" name="chain_file" 
                               accept=".crt,.pem,.cer,.cert">
                        <div class="form-text">Intermediate/Chain certificates</div>
                    </div>
                    
                    <button type="submit" class="btn btn-success btn-sm">
                        <i class="fas fa-upload"></i> Upload Certificates
                    </button>
                </form>
                
                <!-- Upload Guidelines -->
                <div class="alert alert-info mt-3">
                    <h6 class="alert-heading"><i class="fas fa-info-circle"></i> Upload Guidelines</h6>
                    <ul class="mb-0 small">
                        <li>Files will be uploaded to: <code><?php echo $ssl_dir; ?>/</code></li>
                        <li>Supported formats: .crt, .pem, .cer, .cert, .key</li>
                        <li>Files must contain valid PEM-encoded data</li>
                        <li>Private keys will be secured with 600 permissions</li>
                        <li>Update the paths above after successful upload</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Certificate Options -->
<div class="card mt-4">
    <div class="card-header">
        <h5 class="mb-0">
            <i class="fas fa-certificate text-info me-2"></i> Certificate Authority Options
        </h5>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-4">
                <div class="list-group">
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1"><i class="fas fa-robot text-success"></i> Let's Encrypt (Free)</h6>
                            <small class="text-success">Recommended</small>
                        </div>
                        <p class="mb-1">Free SSL certificates with automatic renewal. Supports SAN.</p>
                        <small>Use Certbot: <code>certbot --apache -d <?php echo htmlspecialchars($ssl_config['domain_name']); ?></code></small>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="list-group">
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1"><i class="fas fa-building text-primary"></i> Commercial CA</h6>
                            <small class="text-primary">Enterprise</small>
                        </div>
                        <p class="mb-1">DigiCert, Comodo, GlobalSign, etc. Enterprise features.</p>
                        <small>Use generated CSR to purchase certificate with SAN support</small>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="list-group">
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1"><i class="fas fa-tools text-warning"></i> Internal CA</h6>
                            <small class="text-warning">Testing</small>
                        </div>
                        <p class="mb-1">Self-signed or internal CA for testing environments.</p>
                        <small>Use generated CSR with your internal Certificate Authority</small>
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
                <h6>SAN Certificate Benefits</h6>
                <ul class="list-unstyled">
                    <li><i class="fas fa-star text-warning me-2"></i> One certificate for multiple domains</li>
                    <li><i class="fas fa-star text-warning me-2"></i> Covers www and non-www versions</li>
                    <li><i class="fas fa-star text-warning me-2"></i> Supports internal and external access</li>
                    <li><i class="fas fa-star text-warning me-2"></i> Cost-effective for multiple endpoints</li>
                    <li><i class="fas fa-star text-warning me-2"></i> Simplified certificate management</li>
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
                            <div class="fw-bold">Configure Domain and SAN</div>
                            Set your primary domain and additional Subject Alternative Names
                        </div>
                        <span class="badge bg-primary rounded-pill">1</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Generate CSR & Private Key</div>
                            Use the enhanced CSR generator with SAN support
                        </div>
                        <span class="badge bg-primary rounded-pill">2</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Obtain SSL Certificate</div>
                            Submit CSR to CA or use Let's Encrypt
                        </div>
                        <span class="badge bg-primary rounded-pill">3</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Upload Certificates</div>
                            Use the upload feature to install your certificates
                        </div>
                        <span class="badge bg-primary rounded-pill">4</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-start">
                        <div class="ms-2 me-auto">
                            <div class="fw-bold">Test & Enable SSL</div>
                            Test the configuration and enable SSL features
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
    
    // Auto-update domain in SAN textarea
    document.getElementById('domain_name').addEventListener('input', function() {
        const domain = this.value;
        const sanTextarea = document.getElementById('san_entries');
        if (domain && !sanTextarea.value.includes('www.' + domain)) {
            if (sanTextarea.value) {
                sanTextarea.value += '\n';
            }
            sanTextarea.value += 'www.' + domain;
        }
    });
    
    // File upload validation
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const maxSize = 5 * 1024 * 1024; // 5MB
                if (file.size > maxSize) {
                    showNotification('File size must be less than 5MB', 'warning');
                    this.value = '';
                }
            }
        });
    });
});

// Show notification function
function showNotification(message, type = 'info') {
    const alertClass = 'alert-' + type;
    const notification = document.createElement('div');
    notification.className = `alert ${alertClass} alert-dismissible position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    
    const icons = {
        'success': 'fas fa-check-circle',
        'danger': 'fas fa-exclamation-triangle',
        'warning': 'fas fa-exclamation-circle',
        'info': 'fas fa-info-circle'
    };
    const icon = icons[type] || icons['info'];
    
    notification.innerHTML = `
        <i class="${icon} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}
</script>

<?php require_once '../includes/footer.php'; ?>