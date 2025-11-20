<?php
// includes/virustotal.php - VirusTotal integration helpers
if (!defined('DATA_DIR')) {
    require_once __DIR__ . '/../config/config.php';
}

if (!function_exists('read_json_file')) {
    require_once __DIR__ . '/functions.php';
}

if (!defined('VIRUSTOTAL_API_KEY')) {
    define('VIRUSTOTAL_API_KEY', getenv('VIRUSTOTAL_API_KEY') ?: '');
}

if (!defined('VIRUSTOTAL_CACHE_TTL')) {
    define('VIRUSTOTAL_CACHE_TTL', 3600); // 1 hour
}

if (!defined('VIRUSTOTAL_CACHE_FILE')) {
    define('VIRUSTOTAL_CACHE_FILE', DATA_DIR . '/virustotal_cache.json');
}

/**
 * Determine VirusTotal risk level from detection counts.
 */
function vt_risk_level_from_detections(int $detections): string
{
    if ($detections >= 25) {
        return 'critical';
    }
    if ($detections >= 10) {
        return 'high';
    }
    if ($detections >= 3) {
        return 'medium';
    }
    if ($detections >= 1) {
        return 'low';
    }
    return 'clean';
}

function vt_badge_class(string $level): string
{
    $classes = [
        'critical' => 'bg-dark',
        'high' => 'bg-danger',
        'medium' => 'bg-warning text-dark',
        'low' => 'bg-secondary',
        'clean' => 'bg-success',
        'unknown' => 'bg-secondary'
    ];

    return $classes[$level] ?? $classes['unknown'];
}

function vt_cache_load(): array
{
    $cache = read_json_file(VIRUSTOTAL_CACHE_FILE);
    return is_array($cache) ? $cache : [];
}

function vt_cache_save(array $cache): void
{
    write_json_file(VIRUSTOTAL_CACHE_FILE, $cache);
}

function vt_cache_key(string $entry, string $type): string
{
    return hash('sha256', strtolower(trim($type)) . '|' . trim($entry));
}

function vt_get_cached_summary(string $entry, string $type): ?array
{
    $cache = vt_cache_load();
    $key = vt_cache_key($entry, $type);

    if (isset($cache[$key]) && isset($cache[$key]['timestamp'])) {
        if ((time() - (int)$cache[$key]['timestamp']) < VIRUSTOTAL_CACHE_TTL) {
            $cached = $cache[$key];
            $cached['source'] = 'cache';
            return $cached;
        }
    }

    return null;
}

function vt_store_summary(string $entry, string $type, array $summary): void
{
    $cache = vt_cache_load();
    $key = vt_cache_key($entry, $type);
    $summary['timestamp'] = time();
    $cache[$key] = $summary;
    vt_cache_save($cache);
}

function vt_api_endpoint(string $entry, string $type): ?string
{
    switch ($type) {
        case 'ip':
            return 'https://www.virustotal.com/api/v3/ip_addresses/' . rawurlencode($entry);
        case 'domain':
            return 'https://www.virustotal.com/api/v3/domains/' . rawurlencode($entry);
        case 'url':
            $url_id = rtrim(strtr(base64_encode($entry), '+/', '-_'), '=');
            return 'https://www.virustotal.com/api/v3/urls/' . $url_id;
        default:
            return null;
    }
}

function vt_api_request(string $endpoint): array
{
    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . VIRUSTOTAL_API_KEY,
            'accept: application/json'
        ]
    ]);

    $response = curl_exec($ch);
    $error = curl_error($ch);
    $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response === false) {
        return [
            'status' => 'error',
            'message' => 'cURL error: ' . $error
        ];
    }

    if ($status_code >= 400) {
        return [
            'status' => 'error',
            'message' => 'VirusTotal API returned HTTP ' . $status_code
        ];
    }

    $decoded = json_decode($response, true);
    if ($decoded === null) {
        return [
            'status' => 'error',
            'message' => 'Unable to decode VirusTotal response'
        ];
    }

    return [
        'status' => 'ok',
        'data' => $decoded
    ];
}

/**
 * Fetch and summarize VirusTotal detections for an entry.
 */
function get_virustotal_summary(string $entry, string $type): array
{
    if (empty(VIRUSTOTAL_API_KEY)) {
        return [
            'status' => 'unavailable',
            'label' => 'VT Unavailable',
            'badge_class' => vt_badge_class('unknown'),
            'message' => 'VirusTotal API key not configured.',
            'detections' => null,
            'level' => 'unknown',
            'source' => 'none'
        ];
    }

    $cached = vt_get_cached_summary($entry, $type);
    if ($cached) {
        return $cached;
    }

    $endpoint = vt_api_endpoint($entry, $type);
    if (!$endpoint) {
        return [
            'status' => 'error',
            'label' => 'Unsupported',
            'badge_class' => vt_badge_class('unknown'),
            'message' => 'Unsupported entry type for VirusTotal lookup.',
            'detections' => null,
            'level' => 'unknown',
            'source' => 'none'
        ];
    }

    $api_response = vt_api_request($endpoint);
    if ($api_response['status'] !== 'ok') {
        $summary = [
            'status' => 'error',
            'label' => 'VT Error',
            'badge_class' => vt_badge_class('unknown'),
            'message' => $api_response['message'],
            'detections' => null,
            'level' => 'unknown',
            'source' => 'live'
        ];
        vt_store_summary($entry, $type, $summary);
        return $summary;
    }

    $stats = $api_response['data']['data']['attributes']['last_analysis_stats'] ?? [];
    $malicious = (int)($stats['malicious'] ?? 0);
    $suspicious = (int)($stats['suspicious'] ?? 0);
    $detections = $malicious + $suspicious;

    $level = vt_risk_level_from_detections($detections);
    $labels = [
        'critical' => 'Critical Risk',
        'high' => 'High Risk',
        'medium' => 'Medium Risk',
        'low' => 'Low Risk',
        'clean' => 'Clean',
        'unknown' => 'Unknown'
    ];

    $summary = [
        'status' => 'ok',
        'label' => $labels[$level] ?? 'Unknown',
        'badge_class' => vt_badge_class($level),
        'message' => 'Detections: ' . $detections,
        'detections' => $detections,
        'level' => $level,
        'source' => 'live'
    ];

    vt_store_summary($entry, $type, $summary);
    return $summary;
}
?>
