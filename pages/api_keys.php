<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/api_keys.php';

$auth = new EDLAuth();
$auth->require_permission('manage');

$page_title = 'API Keys';
$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } elseif (($_POST['action'] ?? '') === 'create') {
        try {
            $name = is_string($_POST['name'] ?? null) ? $_POST['name'] : '';
            $permissions = array_filter((array) ($_POST['permissions'] ?? []), 'is_string');
            $created = api_key_create($name, $permissions, $_SESSION['username']);
            // Shown once on the next page load, then dropped from the session.
            $_SESSION['new_api_token'] = ['name' => $created['key']['name'], 'token' => $created['token']];
            header('Location: api_keys.php');
            exit;
        } catch (InvalidArgumentException $e) {
            $error_message = $e->getMessage();
        }
    } elseif (($_POST['action'] ?? '') === 'revoke') {
        if (is_string($_POST['key_id'] ?? null) && api_key_revoke($_POST['key_id'], $_SESSION['username'])) {
            show_flash('API key revoked. Requests using it are now rejected.', 'success');
        } else {
            show_flash('That key was not found or is already revoked.', 'warning');
        }
        header('Location: api_keys.php');
        exit;
    }
}

$new_token = $_SESSION['new_api_token'] ?? null;
unset($_SESSION['new_api_token']);

$keys = api_key_list();
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$api_base = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . get_app_base_path() . 'api/v1';

$permission_help = [
    'view' => 'Read entries, requests, and metrics',
    'submit' => 'Submit entries for approval',
    'approve' => 'Approve or deny pending requests',
    'remove' => 'Remove entries from the blocklist',
];

require_once '../includes/header.php';
?>

<div class="container mt-4">

<?php if ($error_message): ?>
<div class="alert alert-danger">
    <i class="fas fa-exclamation-triangle"></i>
    <?php echo htmlspecialchars($error_message); ?>
</div>
<?php endif; ?>

<div class="page-header">
    <h1 class="mb-2"><i class="fas fa-key me-2"></i>API Keys</h1>
    <p class="mb-0 opacity-75">Let SOAR platforms, SIEM playbooks, and scripts use the REST API</p>
</div>

<?php if ($new_token): ?>
<div class="alert alert-success">
    <h5 class="alert-heading"><i class="fas fa-check-circle"></i> Key "<?php echo $new_token['name']; ?>" created</h5>
    <p class="mb-2">Copy the token now. It won't be shown again.</p>
    <code class="d-block p-2 bg-white border rounded user-select-all" id="new-token"><?php echo htmlspecialchars($new_token['token']); ?></code>
    <p class="mt-3 mb-1 small">Example:</p>
    <code class="d-block p-2 bg-white border rounded small user-select-all">curl -H "Authorization: Bearer <?php echo htmlspecialchars($new_token['token']); ?>" <?php echo htmlspecialchars($api_base); ?>/requests</code>
</div>
<?php endif; ?>

<div class="row">
    <div class="col-lg-4 mb-4">
        <div class="card">
            <div class="card-header"><i class="fas fa-plus"></i> New key</div>
            <div class="card-body">
                <form method="POST">
                    <?php echo csrf_token_field(); ?>
                    <input type="hidden" name="action" value="create">
                    <div class="mb-3">
                        <label for="name" class="form-label fw-bold">Name</label>
                        <input type="text" class="form-control" id="name" name="name" maxlength="64" required
                               placeholder="e.g. xsoar-prod">
                        <div class="form-text">Shows as the submitter or approver of anything the key does.</div>
                    </div>
                    <div class="mb-3">
                        <span class="form-label fw-bold d-block">Permissions</span>
                        <?php foreach ($permission_help as $permission => $help): ?>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="permissions[]"
                                   value="<?php echo $permission; ?>" id="perm-<?php echo $permission; ?>"
                                   <?php echo $permission === 'view' ? 'checked' : ''; ?>>
                            <label class="form-check-label" for="perm-<?php echo $permission; ?>">
                                <strong><?php echo $permission; ?></strong>
                                <small class="text-muted d-block"><?php echo $help; ?></small>
                            </label>
                        </div>
                        <?php endforeach; ?>
                    </div>
                    <button type="submit" class="btn btn-primary"><i class="fas fa-key"></i> Create key</button>
                </form>
            </div>
        </div>
        <p class="small text-muted mt-3">
            API reference: <a href="../api/v1/openapi.yaml">openapi.yaml</a><br>
            Base URL: <code><?php echo htmlspecialchars($api_base); ?></code>
        </p>
    </div>

    <div class="col-lg-8 mb-4">
        <div class="card">
            <div class="card-header"><i class="fas fa-list"></i> Keys</div>
            <div class="card-body p-0">
                <?php if (!$keys): ?>
                <p class="text-muted p-3 mb-0">No API keys yet.</p>
                <?php else: ?>
                <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Permissions</th>
                            <th>Created</th>
                            <th>Last used</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($keys as $key): ?>
                        <tr class="<?php echo $key['revoked_at'] ? 'text-muted' : ''; ?>">
                            <td>
                                <strong><?php echo $key['name']; ?></strong>
                                <small class="d-block text-muted">edl_<?php echo htmlspecialchars($key['id']); ?>_…</small>
                            </td>
                            <td>
                                <?php foreach ($key['permissions'] as $permission): ?>
                                <span class="badge bg-secondary"><?php echo htmlspecialchars($permission); ?></span>
                                <?php endforeach; ?>
                            </td>
                            <td>
                                <?php echo format_datetime($key['created_at']); ?>
                                <small class="d-block text-muted">by <?php echo htmlspecialchars($key['created_by']); ?></small>
                            </td>
                            <td>
                                <?php if ($key['last_used_at']): ?>
                                <?php echo format_datetime($key['last_used_at']); ?>
                                <small class="d-block text-muted"><?php echo htmlspecialchars($key['last_used_ip'] ?? ''); ?></small>
                                <?php else: ?>
                                <span class="text-muted">Never</span>
                                <?php endif; ?>
                            </td>
                            <td class="text-end">
                                <?php if ($key['revoked_at']): ?>
                                <span class="badge bg-light text-muted border">Revoked <?php echo format_datetime($key['revoked_at'], 'M j, Y'); ?></span>
                                <?php else: ?>
                                <form method="POST" class="d-inline"
                                      onsubmit="return confirm('Revoke this key? Anything using it stops working immediately.');">
                                    <?php echo csrf_token_field(); ?>
                                    <input type="hidden" name="action" value="revoke">
                                    <input type="hidden" name="key_id" value="<?php echo htmlspecialchars($key['id']); ?>">
                                    <button type="submit" class="btn btn-sm btn-outline-danger">Revoke</button>
                                </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

</div>

<?php require_once '../includes/footer.php'; ?>
