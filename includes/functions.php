<?php
// includes/functions.php - Complete EDL Manager Functions

function sanitize_input($data) {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validate_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function csrf_token_field() {
    return '<input type="hidden" name="csrf_token" value="' . generate_csrf_token() . '">';
}

/**
 * Call right before marking a session as logged in. Issues a new session ID
 * and deletes the old one, so an ID planted before login (session fixation)
 * is useless afterwards, and rotates the CSRF token.
 */
function regenerate_session_on_login() {
    if (session_status() !== PHP_SESSION_ACTIVE || !session_regenerate_id(true)) {
        throw new RuntimeException('Could not regenerate the session ID at login');
    }
    unset($_SESSION['csrf_token']);
}

function read_json_file($file) {
    if (!file_exists($file)) {
        return [];
    }
    $content = file_get_contents($file);
    return $content ? json_decode($content, true) : [];
}

/**
 * Exclusive lock shared by every JSON data file.
 *
 * Hold it across any read-modify-write so two requests (e.g. two approvers)
 * can't both read the same file and overwrite each other's changes. One lock
 * for all files keeps multi-file updates (pending -> approved -> audit log)
 * consistent without lock-ordering deadlocks.
 *
 * The lock is re-entrant: nested acquire/release pairs only release the lock
 * when the outermost pair finishes. PHP also releases it when the request
 * ends, so a code path that calls exit() while holding it is safe.
 */
function acquire_data_lock() {
    data_lock_handle(true);
}

function release_data_lock() {
    data_lock_handle(false);
}

function data_lock_handle($acquire) {
    static $handle = null;
    static $depth = 0;

    if ($acquire) {
        if ($depth === 0) {
            if (!is_dir(DATA_DIR)) {
                mkdir(DATA_DIR, 0750, true);
            }
            $handle = fopen(DATA_DIR . '/.data.lock', 'c');
            if ($handle === false || !flock($handle, LOCK_EX)) {
                if ($handle !== false) {
                    fclose($handle);
                }
                $handle = null;
                throw new RuntimeException('Unable to lock data directory ' . DATA_DIR);
            }
        }
        $depth++;
    } elseif ($depth > 0 && --$depth === 0) {
        flock($handle, LOCK_UN);
        fclose($handle);
        $handle = null;
    }
}

function with_data_lock(callable $callback) {
    acquire_data_lock();
    try {
        return $callback();
    } finally {
        release_data_lock();
    }
}

/**
 * Write a file atomically: write a temp file in the same directory, then
 * rename() it over the target. Readers (including firewalls fetching EDL
 * files) always see either the old or the new contents, never a partial file.
 *
 * $mode defaults to the existing file's permissions, or 0640 for a new file.
 */
function write_file_atomic($file, $contents, $mode = null) {
    $dir = dirname($file);
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }
    if ($mode === null) {
        $mode = file_exists($file) ? (fileperms($file) & 0777) : 0640;
    }

    $tmp = $dir . '/.' . basename($file) . '.' . bin2hex(random_bytes(6)) . '.tmp';
    $handle = @fopen($tmp, 'x');
    if ($handle === false) {
        error_log("write_file_atomic: cannot create temp file in {$dir}");
        return false;
    }

    $written = fwrite($handle, $contents);
    $flushed = fflush($handle) && (!function_exists('fsync') || fsync($handle));
    fclose($handle);

    if ($written !== strlen($contents) || !$flushed) {
        @unlink($tmp);
        error_log("write_file_atomic: short write to {$tmp}");
        return false;
    }

    @chmod($tmp, $mode);
    if (!rename($tmp, $file)) {
        @unlink($tmp);
        error_log("write_file_atomic: cannot replace {$file}");
        return false;
    }
    return true;
}

function write_json_file($file, $data) {
    $json = json_encode($data, JSON_PRETTY_PRINT);
    if ($json === false) {
        error_log("write_json_file: cannot encode data for {$file}: " . json_last_error_msg());
        return false;
    }
    return with_data_lock(function () use ($file, $json) {
        return write_file_atomic($file, $json);
    });
}

/**
 * Read a JSON file, pass its contents to $callback, and write back whatever
 * the callback returns, all under the data lock.
 */
function update_json_file($file, callable $callback) {
    return with_data_lock(function () use ($file, $callback) {
        return write_json_file($file, $callback(read_json_file($file)));
    });
}

function append_audit_log(array $log_entry) {
    return update_json_file(DATA_DIR . '/audit_logs.json', function ($logs) use ($log_entry) {
        $logs[] = $log_entry;
        return $logs;
    });
}

function show_flash($message, $type = 'info') {
    $_SESSION['flash_message'] = $message;
    $_SESSION['flash_type'] = $type;
}

function get_flash() {
    if (isset($_SESSION['flash_message'])) {
        $message = $_SESSION['flash_message'];
        $type = $_SESSION['flash_type'] ?? 'info';
        unset($_SESSION['flash_message'], $_SESSION['flash_type']);
        return ['message' => $message, 'type' => $type];
    }
    return null;
}

// Additional utility functions for EDL Manager

function validate_ip($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function validate_domain($domain) {
    return filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false ||
           preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/', $domain);
}

function validate_url($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

function get_entry_type($entry) {
    if (validate_url($entry)) {
        return 'url';
    } elseif (validate_ip($entry)) {
        return 'ip';
    } elseif (validate_domain($entry)) {
        return 'domain';
    }
    return 'unknown';
}

function format_datetime($datetime, $format = 'M j, Y H:i') {
    if (empty($datetime)) {
        return 'Unknown';
    }
    $timestamp = is_numeric($datetime) ? $datetime : strtotime($datetime);
    return $timestamp ? date($format, $timestamp) : 'Invalid Date';
}

function get_priority_badge($priority) {
    $badges = [
        'low' => '<span class="badge bg-secondary">🔵 Low</span>',
        'medium' => '<span class="badge bg-warning text-dark">🟡 Medium</span>',
        'high' => '<span class="badge bg-danger">🟠 High</span>',
        'critical' => '<span class="badge bg-dark">🔴 Critical</span>'
    ];
    return $badges[$priority] ?? '<span class="badge bg-secondary">Unknown</span>';
}

function get_status_badge($status) {
    $badges = [
        'pending' => '<span class="badge bg-warning text-dark">⏳ Pending</span>',
        'approved' => '<span class="badge bg-success">✅ Approved</span>',
        'denied' => '<span class="badge bg-danger">❌ Denied</span>'
    ];
    return $badges[$status] ?? '<span class="badge bg-secondary">Unknown</span>';
}

function get_type_icon($type) {
    $icons = [
        'ip' => '<i class="fas fa-network-wired text-primary"></i>',
        'domain' => '<i class="fas fa-globe text-success"></i>',
        'url' => '<i class="fas fa-link text-info"></i>'
    ];
    return $icons[$type] ?? '<i class="fas fa-question-circle text-muted"></i>';
}

function generate_unique_id($prefix = 'id') {
    return $prefix . '_' . uniqid() . '_' . bin2hex(random_bytes(4));
}

function is_valid_servicenow_ticket($ticket) {
    $patterns = [
        '/^INC\d{7}$/',     // Incident
        '/^REQ\d{7}$/',     // Request
        '/^CHG\d{7}$/',     // Change
        '/^RITM\d{7}$/',    // Request Item
        '/^TASK\d{7}$/',    // Task
        '/^SCTASK\d{7}$/'   // Service Catalog Task
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, strtoupper($ticket))) {
            return true;
        }
    }
    return false;
}

function log_activity($action, $details = '', $entry = '', $user = null) {
    $user = $user ?? ($_SESSION['username'] ?? 'system');
    
    $log_entry = [
        'id' => generate_unique_id('audit'),
        'timestamp' => date('c'),
        'action' => $action,
        'entry' => $entry,
        'user' => $user,
        'details' => $details,
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ];
    
    return update_json_file(DATA_DIR . '/audit_logs.json', function ($logs) use ($log_entry) {
        $logs[] = $log_entry;
        
        // Keep only last 10,000 logs to prevent file from growing too large
        if (count($logs) > 10000) {
            $logs = array_slice($logs, -10000);
        }
        
        return $logs;
    });
}

function clean_old_logs($days = 90) {
    $cutoff_date = strtotime("-{$days} days");
    
    return update_json_file(DATA_DIR . '/audit_logs.json', function ($logs) use ($cutoff_date) {
        $cleaned_logs = array_filter($logs, function($log) use ($cutoff_date) {
            $log_time = strtotime($log['timestamp'] ?? '');
            return $log_time && $log_time > $cutoff_date;
        });
        
        return array_values($cleaned_logs);
    });
}

function backup_data($backup_dir = 'backups') {
    if (!is_dir($backup_dir)) {
        mkdir($backup_dir, 0755, true);
    }
    
    $timestamp = date('Y-m-d_H-i-s');
    $backup_file = "{$backup_dir}/edl_backup_{$timestamp}.zip";
    
    if (class_exists('ZipArchive')) {
        $zip = new ZipArchive();
        if ($zip->open($backup_file, ZipArchive::CREATE) === TRUE) {
            $files = glob(DATA_DIR . '/*.json');
            foreach ($files as $file) {
                $zip->addFile($file, basename($file));
            }
            $zip->close();
            return $backup_file;
        }
    }
    return false;
}

function get_system_stats() {
    $pending_requests = read_json_file(DATA_DIR . '/pending_requests.json');
    $approved_entries = read_json_file(DATA_DIR . '/approved_entries.json');
    $denied_entries = read_json_file(DATA_DIR . '/denied_entries.json');
    $audit_logs = read_json_file(DATA_DIR . '/audit_logs.json');
    
    return [
        'pending_requests' => count($pending_requests),
        'approved_entries' => count($approved_entries),
        'denied_entries' => count($denied_entries),
        'total_logs' => count($audit_logs),
        'recent_activity' => array_slice(array_reverse($audit_logs), 0, 5)
    ];
}

?>