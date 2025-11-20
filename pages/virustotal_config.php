<?php
// pages/virustotal_config.php - VirusTotal configuration management (Admin only)
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

$auth = new EDLAuth();
$auth->require_permission('manage');

// Enforce admin role explicitly
if (($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403);
    die('Access denied. Admin role required.');
}

$page_title = 'VirusTotal Configuration';
$vt_config_file = DATA_DIR . '/virustotal_config.json';

$vt_config = read_json_file($vt_config_file);
if (!is_array($vt_config)) {
    $vt_config = [
        'api_key' => VIRUSTOTAL_API_KEY,
        'cache_ttl' => VIRUSTOTAL_CACHE_TTL
    ];
}

$error_message = '';
$success_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $api_key = trim($_POST['api_key'] ?? '');
        $cache_ttl = (int)($_POST['cache_ttl'] ?? VIRUSTOTAL_CACHE_TTL);

        if ($cache_ttl < 60) {
            $error_message = 'Cache TTL must be at least 60 seconds.';
        } else {
            $vt_config = [
                'api_key' => $api_key,
                'cache_ttl' => $cache_ttl
            ];
            write_json_file($vt_config_file, $vt_config);
            $success_message = 'VirusTotal configuration updated successfully.';
        }
    }
}

include '../includes/header.php';
?>

<div class="main-container">
    <div class="row mb-4">
        <div class="col-md-8">
            <h1 class="display-6">
                <i class="fas fa-shield-virus text-primary"></i>
                VirusTotal Configuration
            </h1>
            <p class="text-muted">Manage VirusTotal API credentials and caching settings. This page is restricted to administrators.</p>
        </div>
    </div>

    <?php if ($error_message): ?>
    <div class="alert alert-danger">
        <i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error_message); ?>
    </div>
    <?php endif; ?>

    <?php if ($success_message): ?>
    <div class="alert alert-success">
        <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success_message); ?>
    </div>
    <?php endif; ?>

    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">

                <div class="mb-3">
                    <label for="api_key" class="form-label fw-bold">VirusTotal API Key</label>
                    <input type="password" class="form-control" id="api_key" name="api_key" value="<?php echo htmlspecialchars($vt_config['api_key'] ?? ''); ?>" autocomplete="new-password" placeholder="Paste your VirusTotal v3 API key" required>
                    <div class="form-text">Stored securely in server data directory. Ensure your web server permissions protect this file.</div>
                </div>

                <div class="mb-3">
                    <label for="cache_ttl" class="form-label fw-bold">Cache Duration (seconds)</label>
                    <input type="number" min="60" class="form-control" id="cache_ttl" name="cache_ttl" value="<?php echo htmlspecialchars((string)($vt_config['cache_ttl'] ?? VIRUSTOTAL_CACHE_TTL)); ?>">
                    <div class="form-text">Controls how long VirusTotal lookups are cached locally to reduce API usage.</div>
                </div>

                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save Configuration
                </button>
            </form>
        </div>
    </div>

    <div class="alert alert-info">
        <div class="d-flex align-items-start">
            <div class="me-2 mt-1"><i class="fas fa-info-circle"></i></div>
            <div>
                <strong>Notes:</strong>
                <ul class="mb-0">
                    <li>Risk levels are derived from VirusTotal detections (malicious + suspicious).</li>
                    <li>Cache entries are stored in <code><?php echo htmlspecialchars(VIRUSTOTAL_CACHE_FILE); ?></code> and expire after the configured TTL.</li>
                    <li>Approvals pages will display VirusTotal badges when an API key is configured.</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<?php include '../includes/footer.php'; ?>
