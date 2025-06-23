<?php
// EDL Manager Validation Functions

/**
 * Comprehensive entry validation with detailed error messages
 */
function validate_entry_comprehensive($entry, $type) {
    $entry = trim($entry);
    
    if (empty($entry)) {
        return ['valid' => false, 'error' => 'Entry cannot be empty'];
    }
    
    switch ($type) {
        case 'ip':
            return validate_ip_comprehensive($entry);
        case 'domain':
            return validate_domain_comprehensive($entry);
        case 'url':
            return validate_url_comprehensive($entry);
        default:
            return ['valid' => false, 'error' => 'Invalid entry type'];
    }
}

/**
 * Comprehensive IP validation
 */
function validate_ip_comprehensive($ip) {
    // Check for CIDR notation
    if (strpos($ip, '/') !== false) {
        list($ip_part, $cidr) = explode('/', $ip, 2);
        $cidr = (int)$cidr;
        
        if (filter_var($ip_part, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if ($cidr < 0 || $cidr > 32) {
                return ['valid' => false, 'error' => 'IPv4 CIDR must be between 0 and 32'];
            }
            return ['valid' => true, 'type' => 'IPv4 with CIDR'];
        } elseif (filter_var($ip_part, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            if ($cidr < 0 || $cidr > 128) {
                return ['valid' => false, 'error' => 'IPv6 CIDR must be between 0 and 128'];
            }
            return ['valid' => true, 'type' => 'IPv6 with CIDR'];
        } else {
            return ['valid' => false, 'error' => 'Invalid IP address format'];
        }
    }
    
    // Single IP address
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return ['valid' => true, 'type' => 'IPv4'];
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return ['valid' => true, 'type' => 'IPv6'];
    } else {
        return ['valid' => false, 'error' => 'Invalid IP address format. Use formats like: 192.168.1.1, 10.0.0.0/24, or 2001:db8::1'];
    }
}

/**
 * Comprehensive domain validation
 */
function validate_domain_comprehensive($domain) {
    if (strlen($domain) > 253) {
        return ['valid' => false, 'error' => 'Domain name too long (max 253 characters)'];
    }
    
    if (strlen($domain) < 4) {
        return ['valid' => false, 'error' => 'Domain name too short (min 4 characters)'];
    }
    
    $pattern = '/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/';
    
    if (!preg_match($pattern, $domain)) {
        return ['valid' => false, 'error' => 'Invalid domain format. Domain can only contain letters, numbers, dots, and hyphens'];
    }
    
    $parts = explode('.', $domain);
    if (count($parts) < 2) {
        return ['valid' => false, 'error' => 'Domain must contain at least one dot (e.g., example.com)'];
    }
    
    $tld = end($parts);
    if (strlen($tld) < 2 || !ctype_alpha($tld)) {
        return ['valid' => false, 'error' => 'Invalid top-level domain (TLD)'];
    }
    
    return ['valid' => true, 'type' => 'Domain'];
}

/**
 * Comprehensive URL validation
 */
function validate_url_comprehensive($url) {
    if (strlen($url) > 2048) {
        return ['valid' => false, 'error' => 'URL too long (max 2048 characters)'];
    }
    
    if (!preg_match('/^https?:\/\//', $url)) {
        return ['valid' => false, 'error' => 'URL must start with http:// or https://'];
    }
    
    if (filter_var($url, FILTER_VALIDATE_URL) === false) {
        return ['valid' => false, 'error' => 'Invalid URL format'];
    }
    
    $parsed = parse_url($url);
    if (!isset($parsed['host']) || empty($parsed['host'])) {
        return ['valid' => false, 'error' => 'URL must contain a valid hostname'];
    }
    
    return ['valid' => true, 'type' => 'URL'];
}

/**
 * Validate ServiceNow ticket format
 */
function validate_snow_ticket($ticket) {
    if (empty($ticket)) {
        return ['valid' => false, 'error' => 'ServiceNow ticket is required'];
    }
    
    $pattern = '/^(INC|REQ|CHG|RITM|TASK|SCTASK)[0-9]{7}$/';
    if (!preg_match($pattern, $ticket)) {
        return ['valid' => false, 'error' => 'Invalid ServiceNow ticket format. Use: INC1234567, REQ1234567, etc.'];
    }
    
    return ['valid' => true, 'type' => 'ServiceNow Ticket'];
}

/**
 * Check if entry already exists
 */
function check_entry_exists($entry, $type) {
    // Check in approved entries
    $approved = read_json_file(DATA_DIR . '/approved_entries.json');
    foreach ($approved as $item) {
        if ($item['entry'] === $entry && $item['type'] === $type) {
            return ['exists' => true, 'location' => 'approved', 'status' => $item['status']];
        }
    }
    
    // Check in pending requests
    $pending = read_json_file(DATA_DIR . '/pending_requests.json');
    foreach ($pending as $item) {
        if ($item['entry'] === $entry && $item['type'] === $type && $item['status'] === 'pending') {
            return ['exists' => true, 'location' => 'pending', 'status' => 'pending'];
        }
    }
    
    // Check in denied entries
    $denied = read_json_file(DATA_DIR . '/denied_entries.json');
    foreach ($denied as $item) {
        if ($item['entry'] === $entry && $item['type'] === $type) {
            return ['exists' => true, 'location' => 'denied', 'denied_reason' => $item['reason']];
        }
    }
    
    return ['exists' => false];
}
?>