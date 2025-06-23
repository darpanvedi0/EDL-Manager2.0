<?php
// includes/teams_notifications.php - Teams webhook notification functions

/**
 * Send a Teams notification for EDL requests
 */
function send_teams_notification($event_type, $request_data, $additional_data = []) {
    // Check if we have the required functions
    if (!function_exists('read_json_file')) {
        return false;
    }
    
    $teams_config_file = DATA_DIR . '/teams_config.json';
    if (!file_exists($teams_config_file)) {
        return false;
    }
    
    $teams_config = read_json_file($teams_config_file);
    
    // Check if Teams notifications are enabled
    if (!$teams_config || !($teams_config['enabled'] ?? false)) {
        return false;
    }
    
    // Check if this event type should be notified
    $notify_events = $teams_config['notifications'] ?? [];
    $should_notify = false;
    
    switch ($event_type) {
        case 'new_request':
            $should_notify = $notify_events['new_requests'] ?? false;
            // Always notify for critical priority
            if (!$should_notify && ($request_data['priority'] ?? '') === 'critical' && ($notify_events['critical_priority'] ?? false)) {
                $should_notify = true;
            }
            break;
        case 'approved':
            $should_notify = $notify_events['approved_requests'] ?? false;
            break;
        case 'denied':
            $should_notify = $notify_events['denied_requests'] ?? false;
            break;
    }
    
    if (!$should_notify) {
        return false;
    }
    
    $webhook_url = $teams_config['webhook_url'] ?? '';
    if (empty($webhook_url)) {
        return false;
    }
    
    // Build the message
    $message = build_teams_message($event_type, $request_data, $teams_config, $additional_data);
    
    // Send the notification
    return send_teams_webhook($webhook_url, $message);
}

/**
 * Build Teams message card based on event type
 */
function build_teams_message($event_type, $request_data, $teams_config, $additional_data = []) {
    $custom_prefix = $teams_config['custom_message'] ?? '';
    $channel_name = $teams_config['channel_name'] ?? '';
    $mention_users = $teams_config['mention_users'] ?? [];
    
    // Build mentions string
    $mentions_text = '';
    if (!empty($mention_users)) {
        $mentions_text = ' ' . implode(' ', array_map(function($email) {
            return "<at>{$email}</at>";
        }, $mention_users));
    }
    
    // Event-specific configurations
    $event_configs = [
        'new_request' => [
            'title' => '🛡️ **New EDL Request Submitted**',
            'color' => '0078D4', // Microsoft Blue
        ],
        'approved' => [
            'title' => '✅ **EDL Request Approved**',
            'color' => '107C10', // Microsoft Green
        ],
        'denied' => [
            'title' => '❌ **EDL Request Denied**',
            'color' => 'D13438', // Microsoft Red
        ]
    ];
    
    $config = $event_configs[$event_type] ?? $event_configs['new_request'];
    
    // Priority styling
    $priority = $request_data['priority'] ?? 'medium';
    $priority_badges = [
        'critical' => '🔴 **CRITICAL**',
        'high' => '🟠 **HIGH**',
        'medium' => '🟡 **MEDIUM**',
        'low' => '🟢 **LOW**'
    ];
    $priority_text = $priority_badges[$priority] ?? $priority_badges['medium'];
    
    // Type icon
    $type_icons = [
        'ip' => '🌐',
        'domain' => '🏢',
        'url' => '🔗'
    ];
    $type_icon = $type_icons[$request_data['type'] ?? 'ip'] ?? '🌐';
    
    // Build facts array
    $facts = [
        [
            'name' => 'Entry:',
            'value' => "`{$request_data['entry']}`"
        ],
        [
            'name' => 'Type:',
            'value' => $type_icon . ' ' . strtoupper($request_data['type'] ?? 'unknown')
        ],
        [
            'name' => 'Priority:',
            'value' => $priority_text
        ],
        [
            'name' => 'Submitted by:',
            'value' => $request_data['submitted_by'] ?? 'Unknown'
        ]
    ];
    
    // Add event-specific facts
    if ($event_type === 'approved' || $event_type === 'denied') {
        $action_by = $additional_data['action_by'] ?? 'Unknown';
        $action_text = $event_type === 'approved' ? 'Approved by:' : 'Denied by:';
        $facts[] = [
            'name' => $action_text,
            'value' => $action_by
        ];
        
        if (!empty($additional_data['admin_comment'])) {
            $facts[] = [
                'name' => $event_type === 'approved' ? 'Approval Note:' : 'Denial Reason:',
                'value' => $additional_data['admin_comment']
            ];
        }
    }
    
    // Add justification
    if (!empty($request_data['justification'])) {
        $justification = strlen($request_data['justification']) > 200 
            ? substr($request_data['justification'], 0, 200) . '...' 
            : $request_data['justification'];
        $facts[] = [
            'name' => 'Justification:',
            'value' => $justification
        ];
    }
    
    $title_with_prefix = $custom_prefix ? $custom_prefix . ' ' . $config['title'] : $config['title'];
    $subtitle = $channel_name ? "EDL Manager → {$channel_name}" : 'EDL Manager';
    
    $message = [
        '@type' => 'MessageCard',
        '@context' => 'http://schema.org/extensions',
        'themeColor' => $config['color'],
        'summary' => strip_tags($config['title']),
        'sections' => [
            [
                'activityTitle' => $title_with_prefix . $mentions_text,
                'activitySubtitle' => $subtitle,
                'facts' => $facts,
                'markdown' => true
            ]
        ]
    ];
    
    return $message;
}

/**
 * Send webhook to Teams
 */
function send_teams_webhook($webhook_url, $message) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $webhook_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($message));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    // Log the attempt
    try {
        $log_entry = [
            'timestamp' => date('c'),
            'success' => $http_code === 200,
            'http_code' => $http_code,
            'error' => $error,
            'message_type' => $message['sections'][0]['activityTitle'] ?? 'Unknown'
        ];
        
        $teams_logs = read_json_file(DATA_DIR . '/teams_logs.json');
        $teams_logs[] = $log_entry;
        
        // Keep only last 100 logs
        if (count($teams_logs) > 100) {
            $teams_logs = array_slice($teams_logs, -100);
        }
        
        write_json_file(DATA_DIR . '/teams_logs.json', $teams_logs);
    } catch (Exception $e) {
        // Silent fail on logging
    }
    
    return $http_code === 200;
}

/**
 * Quick notification functions for common events
 */
function notify_teams_new_request($request_data) {
    return send_teams_notification('new_request', $request_data);
}

function notify_teams_approved($request_data, $approved_by, $admin_comment = '') {
    return send_teams_notification('approved', $request_data, [
        'action_by' => $approved_by,
        'admin_comment' => $admin_comment
    ]);
}

function notify_teams_denied($request_data, $denied_by, $denial_reason = '') {
    return send_teams_notification('denied', $request_data, [
        'action_by' => $denied_by,
        'admin_comment' => $denial_reason
    ]);
}

/**
 * Get Teams notification logs for admin dashboard
 */
function get_teams_notification_logs($limit = 20) {
    if (!function_exists('read_json_file')) {
        return [];
    }
    
    $logs = read_json_file(DATA_DIR . '/teams_logs.json');
    return array_slice(array_reverse($logs), 0, $limit);
}
?>