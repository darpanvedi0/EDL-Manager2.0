<?php
// includes/teams_notifications.php - Enhanced Teams webhook notification functions

/**
 * Send a Teams notification for EDL requests (supports individual and bulk operations)
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
        case 'bulk_new_request':
            $should_notify = $notify_events['new_requests'] ?? false;
            break;
        case 'approved':
            $should_notify = $notify_events['approved_requests'] ?? false;
            break;
        case 'denied':
            $should_notify = $notify_events['denied_requests'] ?? false;
            break;
        case 'bulk_approved':
            $should_notify = $notify_events['approved_requests'] ?? false;
            break;
        case 'bulk_denied':
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
    $result = send_teams_webhook($webhook_url, $message);
    
    // Log the notification attempt
    log_teams_notification($event_type, $request_data, $result, $additional_data);
    
    return $result;
}

/**
 * Build Teams message card based on event type (enhanced for bulk operations)
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
    
    // Check if this is a bulk operation
    $is_bulk = isset($request_data['bulk_operation']) || str_contains($event_type, 'bulk_');
    
    // Event-specific configurations
    $event_configs = [
        'new_request' => [
            'title' => '🛡️ **New EDL Request Submitted**',
            'color' => '0078D4', // Microsoft Blue
            'icon' => '🔔'
        ],
        'bulk_new_request' => [
            'title' => '📋 **Bulk EDL Requests Submitted**',
            'color' => '0078D4',
            'icon' => '📤'
        ],
        'approved' => [
            'title' => '✅ **EDL Request Approved**',
            'color' => '107C10', // Microsoft Green
            'icon' => '✅'
        ],
        'bulk_approved' => [
            'title' => '✅ **Bulk EDL Requests Approved**',
            'color' => '107C10',
            'icon' => '📝'
        ],
        'denied' => [
            'title' => '❌ **EDL Request Denied**',
            'color' => 'D13438', // Microsoft Red
            'icon' => '❌'
        ],
        'bulk_denied' => [
            'title' => '❌ **Bulk EDL Requests Denied**',
            'color' => 'D13438',
            'icon' => '🚫'
        ]
    ];
    
    $config = $event_configs[$event_type] ?? $event_configs['new_request'];
    
    // Build the main message content
    $facts = [];
    
    if ($is_bulk) {
        // Bulk operation message
        $bulk_count = $request_data['bulk_count'] ?? $additional_data['count'] ?? 'Multiple';
        $type_summary = $request_data['bulk_summary'] ?? $additional_data['type_summary'] ?? 'entries';
        
        $facts[] = [
            'name' => '📊 **Count**',
            'value' => $bulk_count . ' entries'
        ];
        
        $facts[] = [
            'name' => '📋 **Types**',
            'value' => $type_summary
        ];
        
        if (in_array($event_type, ['bulk_approved', 'bulk_denied'])) {
            $facts[] = [
                'name' => '👤 **Processed By**',
                'value' => $additional_data['processed_by'] ?? 'System'
            ];
        } else {
            $facts[] = [
                'name' => '👤 **Submitted By**',
                'value' => $request_data['submitted_by'] ?? 'Unknown'
            ];
        }
        
        if (!empty($additional_data['comment'])) {
            $facts[] = [
                'name' => '💬 **Admin Comment**',
                'value' => htmlspecialchars($additional_data['comment'])
            ];
        }
        
    } else {
        // Individual operation message
        $facts[] = [
            'name' => '🎯 **Entry**',
            'value' => '`' . htmlspecialchars($request_data['entry']) . '`'
        ];
        
        $facts[] = [
            'name' => '🏷️ **Type**',
            'value' => ucfirst($request_data['type'] ?? 'Unknown')
        ];
        
        $facts[] = [
            'name' => '⚡ **Priority**',
            'value' => get_priority_emoji($request_data['priority'] ?? 'medium') . ' ' . ucfirst($request_data['priority'] ?? 'Medium')
        ];
        
        if (in_array($event_type, ['approved', 'denied'])) {
            $facts[] = [
                'name' => '👤 **Processed By**',
                'value' => $additional_data['processed_by'] ?? 'System'
            ];
        } else {
            $facts[] = [
                'name' => '👤 **Submitted By**',
                'value' => $request_data['submitted_by'] ?? $additional_data['submitted_by'] ?? 'Unknown'
            ];
        }
        
        if (!empty($request_data['justification'])) {
            $justification = htmlspecialchars($request_data['justification']);
            if (strlen($justification) > 100) {
                $justification = substr($justification, 0, 97) . '...';
            }
            $facts[] = [
                'name' => '📝 **Justification**',
                'value' => $justification
            ];
        }
        
        if (!empty($additional_data['comment'])) {
            $facts[] = [
                'name' => '💬 **Admin Comment**',
                'value' => htmlspecialchars($additional_data['comment'])
            ];
        }
        
        if (!empty($request_data['servicenow_ticket'])) {
            $facts[] = [
                'name' => '🎫 **ServiceNow Ticket**',
                'value' => '`' . htmlspecialchars($request_data['servicenow_ticket']) . '`'
            ];
        }
    }
    
    $facts[] = [
        'name' => '⏰ **Timestamp**',
        'value' => date('Y-m-d H:i:s T')
    ];
    
    // Build the title with custom prefix
    $title = $config['title'];
    if (!empty($custom_prefix)) {
        $title = $custom_prefix . ' ' . $title;
    }
    
    // Build summary text
    if ($is_bulk) {
        $summary_parts = [];
        if (in_array($event_type, ['bulk_approved', 'bulk_denied'])) {
            $action = str_contains($event_type, 'approved') ? 'approved' : 'denied';
            $summary_parts[] = $bulk_count . ' EDL entries have been ' . $action;
        } else {
            $summary_parts[] = $bulk_count . ' new EDL entries submitted for review';
        }
        if (!empty($type_summary)) {
            $summary_parts[] = '(' . $type_summary . ')';
        }
        $summary = implode(' ', $summary_parts);
    } else {
        if (in_array($event_type, ['approved', 'denied'])) {
            $action = $event_type === 'approved' ? 'approved' : 'denied';
            $summary = "EDL entry **{$request_data['entry']}** has been {$action}";
        } else {
            $summary = "New EDL entry **{$request_data['entry']}** submitted for review";
        }
    }
    
    // Build the Teams card
    $card = [
        '@type' => 'MessageCard',
        '@context' => 'http://schema.org/extensions',
        'themeColor' => $config['color'],
        'summary' => strip_tags($summary),
        'sections' => [
            [
                'activityTitle' => $title . $mentions_text,
                'activitySubtitle' => $summary,
                'activityImage' => 'https://img.icons8.com/color/48/000000/security-shield-green.png',
                'facts' => $facts,
                'markdown' => true
            ]
        ]
    ];
    
    // Add potential actions for pending requests
    if ($event_type === 'new_request' || $event_type === 'bulk_new_request') {
        $base_url = 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
        $card['potentialAction'] = [
            [
                '@type' => 'OpenUri',
                'name' => 'Review Requests',
                'targets' => [
                    [
                        'os' => 'default',
                        'uri' => $base_url . '/pages/approvals.php'
                    ]
                ]
            ]
        ];
    }
    
    return $card;
}

/**
 * Get priority emoji for display
 */
function get_priority_emoji($priority) {
    $emojis = [
        'critical' => '🔴',
        'high' => '🟠',
        'medium' => '🟡',
        'low' => '🔵'
    ];
    return $emojis[$priority] ?? '🟡';
}

/**
 * Send webhook to Teams
 */
function send_teams_webhook($webhook_url, $message) {
    $json_message = json_encode($message, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $webhook_url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $json_message,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Content-Length: ' . strlen($json_message)
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    return [
        'success' => $http_code === 200,
        'http_code' => $http_code,
        'response' => $response,
        'error' => $error
    ];
}

/**
 * Log Teams notification attempts
 */
function log_teams_notification($event_type, $request_data, $result, $additional_data = []) {
    if (!function_exists('read_json_file') || !function_exists('write_json_file')) {
        return false;
    }
    
    $log_entry = [
        'id' => uniqid('teams_', true),
        'timestamp' => date('c'),
        'event_type' => $event_type,
        'success' => $result['success'] ?? false,
        'http_code' => $result['http_code'] ?? 0,
        'error' => $result['error'] ?? null,
        'entry' => $request_data['entry'] ?? 'bulk',
        'user' => $request_data['submitted_by'] ?? $additional_data['processed_by'] ?? 'system'
    ];
    
    // Add bulk-specific information
    if (isset($request_data['bulk_operation']) || str_contains($event_type, 'bulk_')) {
        $log_entry['bulk_count'] = $request_data['bulk_count'] ?? $additional_data['count'] ?? 0;
        $log_entry['bulk_summary'] = $request_data['bulk_summary'] ?? $additional_data['type_summary'] ?? '';
    }
    
    $teams_logs = read_json_file(DATA_DIR . '/teams_logs.json');
    $teams_logs[] = $log_entry;
    
    // Keep only last 100 logs
    if (count($teams_logs) > 100) {
        $teams_logs = array_slice($teams_logs, -100);
    }
    
    return write_json_file(DATA_DIR . '/teams_logs.json', $teams_logs);
}

/**
 * Send test notification
 */
function send_test_teams_notification() {
    $test_request = [
        'entry' => 'test.example.com',
        'type' => 'domain',
        'priority' => 'medium',
        'submitted_by' => 'Test User',
        'justification' => 'This is a test notification from EDL Manager',
        'servicenow_ticket' => 'TEST1234567',
        'submitted_at' => date('c')
    ];
    
    return send_teams_notification('new_request', $test_request, [
        'test_mode' => true
    ]);
}

/**
 * Send bulk test notification
 */
function send_bulk_test_teams_notification() {
    $test_request = [
        'bulk_operation' => true,
        'bulk_count' => 5,
        'bulk_summary' => '3 IPs, 1 domain, 1 URL',
        'submitted_by' => 'Test User'
    ];
    
    return send_teams_notification('bulk_new_request', $test_request, [
        'count' => 5,
        'type_summary' => '3 IPs, 1 domain, 1 URL',
        'test_mode' => true
    ]);
}

/**
 * Legacy compatibility functions
 */
function notify_teams_approved($request, $approved_by, $comment = '') {
    return send_teams_notification('approved', $request, [
        'processed_by' => $approved_by,
        'comment' => $comment
    ]);
}

function notify_teams_denied($request, $denied_by, $comment = '') {
    return send_teams_notification('denied', $request, [
        'processed_by' => $denied_by,
        'comment' => $comment
    ]);
}

/**
 * Enhanced bulk notification functions
 */
function notify_teams_bulk_approved($requests, $approved_by, $comment = '') {
    if (empty($requests)) return false;
    
    // Group by type for summary
    $by_type = [];
    foreach ($requests as $request) {
        $type = $request['type'];
        if (!isset($by_type[$type])) {
            $by_type[$type] = 0;
        }
        $by_type[$type]++;
    }
    
    $type_summary = [];
    foreach ($by_type as $type => $count) {
        $type_summary[] = "{$count} {$type}" . ($count > 1 ? 's' : '');
    }
    
    $template_request = $requests[0];
    $template_request['bulk_operation'] = true;
    $template_request['bulk_count'] = count($requests);
    $template_request['bulk_summary'] = implode(', ', $type_summary);
    
    return send_teams_notification('bulk_approved', $template_request, [
        'count' => count($requests),
        'type_summary' => implode(', ', $type_summary),
        'processed_by' => $approved_by,
        'comment' => $comment
    ]);
}

function notify_teams_bulk_denied($requests, $denied_by, $comment = '') {
    if (empty($requests)) return false;
    
    // Group by type for summary
    $by_type = [];
    foreach ($requests as $request) {
        $type = $request['type'];
        if (!isset($by_type[$type])) {
            $by_type[$type] = 0;
        }
        $by_type[$type]++;
    }
    
    $type_summary = [];
    foreach ($by_type as $type => $count) {
        $type_summary[] = "{$count} {$type}" . ($count > 1 ? 's' : '');
    }
    
    $template_request = $requests[0];
    $template_request['bulk_operation'] = true;
    $template_request['bulk_count'] = count($requests);
    $template_request['bulk_summary'] = implode(', ', $type_summary);
    
    return send_teams_notification('bulk_denied', $template_request, [
        'count' => count($requests),
        'type_summary' => implode(', ', $type_summary),
        'processed_by' => $denied_by,
        'comment' => $comment
    ]);
}

/**
 * Send notification for bulk submissions
 */
function notify_teams_bulk_submitted($requests, $submitted_by) {
    if (empty($requests)) return false;
    
    // Group by type for summary
    $by_type = [];
    foreach ($requests as $request) {
        $type = $request['type'];
        if (!isset($by_type[$type])) {
            $by_type[$type] = 0;
        }
        $by_type[$type]++;
    }
    
    $type_summary = [];
    foreach ($by_type as $type => $count) {
        $type_summary[] = "{$count} {$type}" . ($count > 1 ? 's' : '');
    }
    
    $template_request = $requests[0];
    $template_request['bulk_operation'] = true;
    $template_request['bulk_count'] = count($requests);
    $template_request['bulk_summary'] = implode(', ', $type_summary);
    $template_request['submitted_by'] = $submitted_by;
    
    return send_teams_notification('bulk_new_request', $template_request, [
        'count' => count($requests),
        'type_summary' => implode(', ', $type_summary),
        'submitted_by' => $submitted_by
    ]);
}

?>
