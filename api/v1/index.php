<?php
// api/v1/index.php - EDL Manager REST API, version 1. Reference: openapi.yaml.
//
// Every route except /health needs an API key, sent as
// "Authorization: Bearer <token>" or "X-API-Key: <token>". Admins create keys
// under Admin > API Keys. URLs work as /api/v1/requests where the web server
// routes /api/v1/* here (the Docker image does), and as
// /api/v1/index.php/requests everywhere.

define('EDL_NO_SESSION', true);
require_once __DIR__ . '/../../config/config.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/requests.php';
require_once __DIR__ . '/../../includes/api_keys.php';
require_once __DIR__ . '/../../includes/metrics.php';
if (file_exists(__DIR__ . '/../../includes/teams_notifications.php')) {
    require_once __DIR__ . '/../../includes/teams_notifications.php';
}

const API_MAX_BODY_BYTES = 1048576;
const API_MAX_PAGE_SIZE = 1000;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function api_send($status, array $body) {
    http_response_code($status);
    echo json_encode($body, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    exit;
}

function api_error($status, $code, $message, array $extra = []) {
    api_send($status, ['error' => ['code' => $code, 'message' => $message] + $extra]);
}

function api_token() {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    // mod_php doesn't always copy Authorization into $_SERVER.
    if ($header === '' && function_exists('getallheaders')) {
        foreach (getallheaders() as $name => $value) {
            if (strcasecmp($name, 'Authorization') === 0) {
                $header = $value;
            }
        }
    }
    if (preg_match('/^Bearer\s+(\S+)$/i', $header, $m)) {
        return $m[1];
    }
    return $_SERVER['HTTP_X_API_KEY'] ?? null;
}

function api_body() {
    $raw = (string) file_get_contents('php://input', false, null, 0, API_MAX_BODY_BYTES + 1);
    if (strlen($raw) > API_MAX_BODY_BYTES) {
        api_error(413, 'payload_too_large', 'The request body is larger than 1 MB');
    }
    if (trim($raw) === '') {
        return [];
    }
    $body = json_decode($raw, true);
    if (!is_array($body) || ($body && array_keys($body) === range(0, count($body) - 1))) {
        api_error(400, 'invalid_json', 'The request body must be a JSON object');
    }
    return $body;
}

function api_time($value) {
    $time = edl_timestamp($value);
    return $time === null ? null : date('c', $time);
}

function api_page(array $records, callable $format) {
    $limit = filter_var($_GET['limit'] ?? 100, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => API_MAX_PAGE_SIZE]]);
    $offset = filter_var($_GET['offset'] ?? 0, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
    if ($limit === false || $offset === false) {
        api_error(400, 'invalid_parameter', 'limit must be 1-' . API_MAX_PAGE_SIZE . ' and offset 0 or more');
    }
    return [
        'data' => array_map($format, array_slice($records, $offset, $limit)),
        'total' => count($records),
        'limit' => $limit,
        'offset' => $offset,
    ];
}

// Newest first, filtered by ?type= and ?q= (substring of the entry).
function api_filter(array $records) {
    $type = $_GET['type'] ?? null;
    $query = $_GET['q'] ?? null;
    if ($type !== null && !in_array($type, EDL_ENTRY_TYPES, true)) {
        api_error(400, 'invalid_parameter', 'type must be ip, domain, or url');
    }
    if ($query !== null && !is_string($query)) {
        api_error(400, 'invalid_parameter', 'q must be a string');
    }
    $records = array_filter($records, fn($r) => ($type === null || ($r['type'] ?? null) === $type)
        && ($query === null || stripos($r['entry'] ?? '', $query) !== false));
    return array_reverse(array_values($records));
}

function api_format_request(array $r) {
    return [
        'id' => $r['id'],
        'entry' => $r['entry'],
        'type' => $r['type'],
        'status' => $r['status'] ?? 'pending',
        'priority' => $r['priority'] ?? null,
        'justification' => $r['justification'] ?? null,
        'comment' => $r['comment'] ?? null,
        'servicenow_ticket' => $r['servicenow_ticket'] ?? null,
        'submitted_by' => $r['submitted_by'] ?? null,
        'submitted_at' => api_time($r['submitted_at'] ?? null),
    ];
}

function api_format_entry(array $e) {
    return [
        'id' => $e['id'],
        'entry' => $e['entry'],
        'type' => $e['type'],
        'status' => $e['status'] ?? null,
        'priority' => $e['priority'] ?? null,
        'justification' => $e['justification'] ?? null,
        'comment' => $e['comment'] ?? null,
        'servicenow_ticket' => $e['servicenow_ticket'] ?? null,
        'request_id' => $e['request_id'] ?? null,
        'submitted_by' => $e['submitted_by'] ?? null,
        'submitted_at' => api_time($e['submitted_at'] ?? null),
        'approved_by' => $e['approved_by'] ?? null,
        'approved_at' => api_time($e['approved_at'] ?? null),
        'approval_comment' => $e['admin_comment'] ?? null,
        'deleted_by' => $e['deleted_by'] ?? null,
        'deleted_at' => api_time($e['deleted_at'] ?? null),
        'deletion_reason' => $e['deletion_reason'] ?? null,
    ];
}

function api_format_denied(array $d) {
    return [
        'id' => $d['id'],
        'entry' => $d['entry'],
        'type' => $d['type'],
        'status' => 'denied',
        'priority' => $d['priority'] ?? null,
        'justification' => $d['justification'] ?? null,
        'comment' => $d['comment'] ?? null,
        'servicenow_ticket' => $d['servicenow_ticket'] ?? null,
        'request_id' => $d['request_id'] ?? null,
        'submitted_by' => $d['submitted_by'] ?? null,
        'submitted_at' => api_time($d['submitted_at'] ?? null),
        'denied_by' => $d['denied_by'] ?? null,
        'denied_at' => api_time($d['denied_at'] ?? null),
        'reason' => $d['reason'] ?? null,
    ];
}

function api_decision_error(array $result) {
    $status = ['not_found' => 404, 'conflict' => 409, 'invalid' => 422][$result['error']];
    api_error($status, $result['error'], $result['message']);
}

// Teams notifications are best-effort; a webhook problem mustn't fail the call.
function api_notify(callable $send) {
    if (!function_exists('send_teams_notification')) {
        return;
    }
    try {
        $send();
    } catch (Throwable $e) {
        error_log('API Teams notification failed: ' . $e->getMessage());
    }
}

function api_find_entry($id) {
    foreach (read_json_file(DATA_DIR . '/approved_entries.json') as $entry) {
        if (($entry['id'] ?? null) === $id) {
            return $entry;
        }
    }
    api_error(404, 'not_found', 'Entry not found');
}

// ---------------------------------------------------------------- handlers

function api_health() {
    api_send(200, ['status' => 'ok', 'version' => APP_VERSION]);
}

function api_list_entries() {
    $status = $_GET['status'] ?? 'active';
    if (!in_array($status, ['active', 'deleted', 'all'], true)) {
        api_error(400, 'invalid_parameter', 'status must be active, deleted, or all');
    }
    $entries = array_filter(read_json_file(DATA_DIR . '/approved_entries.json'),
        fn($e) => $status === 'all' || ($e['status'] ?? '') === $status);
    api_send(200, api_page(api_filter($entries), 'api_format_entry'));
}

function api_get_entry($key, $id) {
    api_send(200, ['data' => api_format_entry(api_find_entry($id))]);
}

function api_delete_entry($key, $id, $actor) {
    $body = api_body();
    $result = edl_remove_entry($id, $actor, (string) ($body['reason'] ?? ''));
    if (isset($result['error'])) {
        api_decision_error($result);
    }
    api_send(200, ['data' => api_format_entry($result['record'])]);
}

function api_list_requests() {
    $pending = array_filter(read_json_file(DATA_DIR . '/pending_requests.json'),
        fn($r) => ($r['status'] ?? 'pending') === 'pending');
    api_send(200, api_page(api_filter($pending), 'api_format_request'));
}

function api_create_requests($key, $id, $actor) {
    $body = api_body();
    if (isset($body['entries'])) {
        if (!is_array($body['entries'])) {
            api_error(422, 'validation_failed', '"entries" must be a list');
        }
        $items = [];
        foreach ($body['entries'] as $item) {
            if (is_string($item)) {
                $items[] = ['entry' => $item, 'type' => $body['type'] ?? null];
            } elseif (is_array($item) && is_string($item['entry'] ?? null)) {
                $items[] = ['entry' => $item['entry'], 'type' => $item['type'] ?? $body['type'] ?? null];
            } else {
                api_error(422, 'validation_failed', 'Each item in "entries" must be a string or an object with an "entry" string');
            }
        }
    } elseif (is_string($body['entry'] ?? null)) {
        $items = [['entry' => $body['entry'], 'type' => $body['type'] ?? null]];
    } else {
        $items = [];
    }
    foreach (['justification', 'servicenow_ticket', 'priority', 'comment'] as $field) {
        if (isset($body[$field]) && !is_string($body[$field])) {
            api_error(422, 'validation_failed', "\"$field\" must be a string");
        }
    }

    $result = edl_submit_requests($items, $body, $actor);
    if (isset($result['errors'])) {
        api_error(422, 'validation_failed', implode('; ', $result['errors']), ['details' => $result['errors']]);
    }
    if (!$result['created']) {
        api_error(422, 'nothing_submitted', 'No entries were submitted', ['skipped' => $result['skipped']]);
    }

    $created = $result['created'];
    api_notify(function () use ($created, $actor) {
        if (count($created) === 1) {
            send_teams_notification('new_request', $created[0]);
        } elseif (function_exists('notify_teams_bulk_submitted')) {
            notify_teams_bulk_submitted($created, $actor);
        }
    });
    api_send(201, ['data' => [
        'created' => array_map('api_format_request', $created),
        'skipped' => $result['skipped'],
    ]]);
}

function api_get_request($key, $id) {
    $found = edl_find_request($id);
    if (!$found) {
        api_error(404, 'not_found', 'Request not found');
    }
    $format = ['pending' => 'api_format_request', 'denied' => 'api_format_denied'][$found['status']] ?? 'api_format_entry';
    api_send(200, ['data' => ['request_id' => $id, 'status' => $found['status'], 'record' => $format($found['record'])]]);
}

function api_decide($id, $approve, $actor) {
    $body = api_body();
    $comment = $approve ? ($body['comment'] ?? '') : ($body['reason'] ?? $body['comment'] ?? '');
    if (!is_string($comment)) {
        api_error(422, 'validation_failed', $approve ? '"comment" must be a string' : '"reason" must be a string');
    }
    $result = edl_decide_request($id, $approve, $actor, $comment);
    if (isset($result['error'])) {
        api_decision_error($result);
    }

    $request = $result['request'];
    api_notify(function () use ($request, $approve, $actor, $comment) {
        send_teams_notification($approve ? 'approved' : 'denied', $request, ['processed_by' => $actor, 'comment' => $comment]);
    });
    api_send(200, ['data' => $approve ? api_format_entry($result['record']) : api_format_denied($result['record'])]);
}

function api_approve($key, $id, $actor) {
    api_decide($id, true, $actor);
}

function api_deny($key, $id, $actor) {
    api_decide($id, false, $actor);
}

function api_metrics() {
    $days = filter_var($_GET['days'] ?? 30, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 3650]]);
    if ($days === false) {
        api_error(400, 'invalid_parameter', 'days must be between 1 and 3650');
    }
    api_send(200, ['data' => edl_collect_metrics($days)]);
}

// ----------------------------------------------------------------- routing

// [method, path, handler, permission]; null permission means no key needed.
$routes = [
    ['GET', 'health', 'api_health', null],
    ['GET', 'entries', 'api_list_entries', 'view'],
    ['GET', 'entries/{id}', 'api_get_entry', 'view'],
    ['DELETE', 'entries/{id}', 'api_delete_entry', 'remove'],
    ['GET', 'requests', 'api_list_requests', 'view'],
    ['POST', 'requests', 'api_create_requests', 'submit'],
    ['GET', 'requests/{id}', 'api_get_request', 'view'],
    ['POST', 'requests/{id}/approve', 'api_approve', 'approve'],
    ['POST', 'requests/{id}/deny', 'api_deny', 'approve'],
    ['GET', 'metrics', 'api_metrics', 'view'],
];

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$prefix = strpos($path, '/api/v1');
$route = $prefix === false ? '' : substr($path, $prefix + strlen('/api/v1'));
$route = trim(preg_replace('#^/index\.php#', '', $route), '/');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$allowed = [];
foreach ($routes as [$route_method, $pattern, $handler, $permission]) {
    $regex = '#^' . str_replace('\{id\}', '([A-Za-z0-9._-]{1,80})', preg_quote($pattern, '#')) . '$#';
    if (!preg_match($regex, $route, $match)) {
        continue;
    }
    if ($route_method !== $method) {
        $allowed[] = $route_method;
        continue;
    }

    try {
        if ($permission === null) {
            $handler();
        }
        $key = api_key_authenticate(api_token());
        if (!$key) {
            header('WWW-Authenticate: Bearer');
            api_error(401, 'unauthorized', 'Send a valid API key as "Authorization: Bearer <token>"');
        }
        if (!in_array($permission, $key['permissions'], true)) {
            api_error(403, 'forbidden', "This API key lacks the \"$permission\" permission");
        }
        $handler($key, $match[1] ?? null, 'api:' . $key['name']);
    } catch (Throwable $e) {
        error_log('API error on ' . $method . ' /' . $route . ': ' . $e->getMessage());
        api_error(500, 'internal_error', 'The server could not complete the request');
    }
}

if ($allowed) {
    header('Allow: ' . implode(', ', array_unique($allowed)));
    api_error(405, 'method_not_allowed', "$method is not supported on /$route");
}
api_error(404, 'not_found', 'No such endpoint. See api/v1/openapi.yaml');
