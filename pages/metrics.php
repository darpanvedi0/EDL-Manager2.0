<?php
require_once '../config/config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';
require_once '../includes/metrics.php';

$auth = new EDLAuth();
$auth->require_permission('view');

$page_title = 'Impact';
$windows = [7, 30, 90, 365];
$days = in_array((int) ($_GET['days'] ?? 30), $windows, true) ? (int) $_GET['days'] : 30;
$metrics = edl_collect_metrics($days);

if (($_GET['format'] ?? '') === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="edl-impact-' . date('Y-m-d') . "-{$days}d.json\"");
    echo json_encode($metrics, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// Escape for HTML. Client user agents come from whoever fetched the lists.
function h($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function duration_cell(array $stats) {
    if (!$stats['count']) {
        return '<span class="text-muted">No data</span>';
    }
    return h(edl_format_duration($stats['median_seconds']))
        . '<small class="text-muted d-block">90% within ' . h(edl_format_duration($stats['p90_seconds']))
        . ' · ' . $stats['count'] . ' measured</small>';
}

$active = $metrics['indicators']['active'];
$requests = $metrics['requests'];
$block = $metrics['time_to_block'];
$enforce = $metrics['time_to_enforcement'];
$firewalls = $metrics['firewalls'];
$list_names = ['ip' => 'IP addresses', 'domain' => 'Domains', 'url' => 'URLs'];

require_once '../includes/header.php';
?>

<style>
    .kpi-value { font-size: 1.9rem; font-weight: 700; line-height: 1.1; }
    .summary-list li { margin-bottom: .35rem; }
    /* assets/css/style.css restyles every .btn, so set these explicitly. */
    .page-header .header-btn {
        background: rgba(255, 255, 255, .12) !important;
        border: 1px solid rgba(255, 255, 255, .55) !important;
        color: #fff !important;
    }
    .page-header .header-btn.active {
        background: #fff !important;
        color: #3d3d8f !important;
        font-weight: 600;
    }
    @media print {
        nav, footer, .no-print { display: none !important; }
        .card { break-inside: avoid; }
        .page-header { color: #000 !important; background: none !important; }
    }
</style>

<div class="container mt-4">

<div class="page-header d-flex flex-wrap justify-content-between align-items-end gap-3">
    <div>
        <h1 class="mb-2"><i class="fas fa-chart-line me-2"></i>Impact</h1>
        <p class="mb-0 opacity-75">How fast blocks are approved and reach your firewalls</p>
    </div>
    <div class="no-print d-flex flex-wrap gap-2">
        <div class="btn-group" role="group" aria-label="Time window">
            <?php foreach ($windows as $window): ?>
            <a href="?days=<?php echo $window; ?>" class="btn btn-sm header-btn<?php echo $window === $days ? ' active" aria-current="page' : ''; ?>"><?php echo $window; ?> days</a>
            <?php endforeach; ?>
        </div>
        <a href="?days=<?php echo $days; ?>&amp;format=json" class="btn btn-sm header-btn"><i class="fas fa-download"></i> JSON</a>
        <button type="button" class="btn btn-sm header-btn" onclick="window.print()"><i class="fas fa-print"></i> Print / PDF</button>
    </div>
</div>

<div class="card mb-4">
    <div class="card-header"><i class="fas fa-file-alt"></i> Summary, last <?php echo $days; ?> days</div>
    <div class="card-body">
        <ul class="summary-list mb-2">
            <?php foreach ($metrics['summary'] as $line): ?>
            <li><?php echo h($line); ?></li>
            <?php endforeach; ?>
        </ul>
        <small class="text-muted">
            <?php echo h(APP_NAME . ' ' . APP_VERSION); ?> ·
            <?php echo h(format_datetime($metrics['window']['from'], 'M j, Y')); ?> to
            <?php echo h(format_datetime($metrics['window']['to'], 'M j, Y H:i T')); ?>
        </small>
    </div>
</div>

<div class="row">
    <div class="col-md-6 col-xl-3 mb-4">
        <div class="card h-100"><div class="card-body">
            <div class="text-muted small">Blocked now</div>
            <div class="kpi-value"><?php echo $active['total']; ?></div>
            <small class="text-muted"><?php echo "{$active['ip']} IP · {$active['domain']} domain · {$active['url']} URL"; ?></small>
        </div></div>
    </div>
    <div class="col-md-6 col-xl-3 mb-4">
        <div class="card h-100"><div class="card-body">
            <div class="text-muted small">Request → approval (median)</div>
            <div class="kpi-value"><?php echo h(edl_format_duration($block['median_seconds'])); ?></div>
            <small class="text-muted"><?php echo $block['count'] ? '90% within ' . h(edl_format_duration($block['p90_seconds'])) : 'No approvals in this window'; ?></small>
        </div></div>
    </div>
    <div class="col-md-6 col-xl-3 mb-4">
        <div class="card h-100"><div class="card-body">
            <div class="text-muted small">Approval → firewall (median)</div>
            <div class="kpi-value"><?php echo h(edl_format_duration($enforce['median_seconds'])); ?></div>
            <small class="text-muted">
                <?php if ($enforce['count']): ?>
                90% within <?php echo h(edl_format_duration($enforce['p90_seconds'])); ?> · <?php echo round($enforce['coverage'] * 100); ?>% of approvals measured
                <?php else: ?>
                No measured approvals yet
                <?php endif; ?>
            </small>
        </div></div>
    </div>
    <div class="col-md-6 col-xl-3 mb-4">
        <div class="card h-100"><div class="card-body">
            <div class="text-muted small">Firewall clients polling</div>
            <div class="kpi-value"><?php echo $firewalls['polling']; ?></div>
            <small class="<?php echo $firewalls['stale'] ? 'text-danger' : 'text-muted'; ?>">
                <?php echo $firewalls['stale'] ? $firewalls['stale'] . ' stopped polling' : ($firewalls['total'] ? 'All polling on schedule' : 'None recorded yet'); ?>
            </small>
        </div></div>
    </div>
</div>

<?php if (!$firewalls['tracking']): ?>
<div class="alert alert-info no-print">
    <i class="fas fa-info-circle"></i>
    No firewall has fetched a list through <code>feed.php</code> yet, so time-to-enforcement and firewall clients are empty.
    The Docker image routes <code>/edl-files/*.txt</code> through it automatically. On other installs, see
    "Measuring firewall fetches" in the README.
</div>
<?php endif; ?>

<div class="row">
    <div class="col-lg-5 mb-4">
        <div class="card h-100">
            <div class="card-header"><i class="fas fa-inbox"></i> Requests</div>
            <div class="card-body p-0">
                <table class="table mb-0">
                    <tr><th>Submitted</th><td class="text-end"><?php echo $requests['submitted']; ?></td></tr>
                    <tr><th>Approved</th><td class="text-end"><?php echo $requests['approved']; ?></td></tr>
                    <tr><th>Denied</th><td class="text-end"><?php echo $requests['denied']; ?></td></tr>
                    <tr><th>Approval rate</th><td class="text-end"><?php echo $requests['approval_rate'] === null ? '–' : round($requests['approval_rate'] * 100) . '%'; ?></td></tr>
                    <tr><th>Removed from blocklist</th><td class="text-end"><?php echo $metrics['indicators']['removed']; ?></td></tr>
                    <tr><th>Pending now</th><td class="text-end">
                        <?php echo $requests['pending']; ?>
                        <?php if ($requests['oldest_pending_age_seconds'] !== null): ?>
                        <small class="text-muted d-block">oldest waiting <?php echo h(edl_format_duration($requests['oldest_pending_age_seconds'])); ?></small>
                        <?php endif; ?>
                    </td></tr>
                </table>
            </div>
        </div>
    </div>
    <div class="col-lg-7 mb-4">
        <div class="card h-100">
            <div class="card-header"><i class="fas fa-stopwatch"></i> Response times</div>
            <div class="card-body p-0">
                <table class="table mb-0">
                    <thead><tr><th></th><th>Median</th></tr></thead>
                    <tr><th>Request → approval</th><td><?php echo duration_cell($block); ?></td></tr>
                    <?php foreach ($block['by_priority'] as $priority => $stats): ?>
                    <tr><td class="ps-4"><?php echo get_priority_badge($priority); ?></td><td><?php echo duration_cell($stats); ?></td></tr>
                    <?php endforeach; ?>
                    <tr><th>Approval → first firewall fetch</th><td><?php echo duration_cell($enforce); ?></td></tr>
                    <tr><th>Request → first firewall fetch</th><td><?php echo duration_cell($metrics['request_to_enforcement']); ?></td></tr>
                </table>
            </div>
        </div>
    </div>
</div>

<div class="card mb-4">
    <div class="card-header"><i class="fas fa-list"></i> Published lists</div>
    <div class="card-body p-0">
        <div class="table-responsive">
        <table class="table mb-0">
            <thead><tr><th>List</th><th>Entries</th><th>Published</th><th>Last fetched</th><th>Clients (24 h)</th><th>Current version fetched</th></tr></thead>
            <tbody>
            <?php foreach ($metrics['lists'] as $type => $list): ?>
                <tr>
                    <td><?php echo get_type_icon($type) . ' ' . h($list_names[$type] ?? $type); ?></td>
                    <td><?php echo $list['entries'] ?? '–'; ?></td>
                    <td><?php echo $list['published_at'] ? h(format_datetime($list['published_at'])) : '–'; ?></td>
                    <td><?php echo $list['last_fetch_at'] ? h(format_datetime($list['last_fetch_at'])) : '<span class="text-muted">Never</span>'; ?></td>
                    <td><?php echo $list['clients_last_24h']; ?></td>
                    <td><?php echo $list['current_version_fetched'] ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-warning text-dark">Not yet</span>'; ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>

<div class="card mb-4">
    <div class="card-header"><i class="fas fa-shield-alt"></i> Firewall clients</div>
    <div class="card-body p-0">
        <?php if (!$firewalls['clients']): ?>
        <p class="text-muted p-3 mb-0">No list fetches recorded yet.</p>
        <?php else: ?>
        <div class="table-responsive">
        <table class="table mb-0">
            <thead><tr><th>Address</th><th>User agent</th><th>Lists</th><th>Last seen</th><th>Polls every</th><th>Status</th></tr></thead>
            <tbody>
            <?php foreach ($firewalls['clients'] as $client): ?>
                <tr>
                    <td><code><?php echo h($client['ip']); ?></code></td>
                    <td><small><?php echo h($client['user_agent'] === '' ? '(none)' : $client['user_agent']); ?></small></td>
                    <td><?php echo h(implode(', ', $client['lists'])); ?></td>
                    <td><?php echo h(format_datetime($client['last_seen'])); ?></td>
                    <td><?php echo h(edl_format_duration($client['typical_interval_seconds'])); ?></td>
                    <td><?php echo $client['stale'] ? '<span class="badge bg-danger">Stopped polling</span>' : '<span class="badge bg-success">Polling</span>'; ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php endif; ?>
    </div>
</div>

<div class="card mb-4">
    <div class="card-header"><i class="fas fa-book"></i> How these are measured</div>
    <div class="card-body small text-muted">
        <ul class="mb-0">
            <li><strong>Request → approval</strong>: from submission to approval, for requests approved in the window.</li>
            <li><strong>Approval → first firewall fetch</strong>: from approval until any client first downloads a version of the list published at or after the approval. Only approvals made while fetch tracking was running are measured; the percentage shown is how many were.</li>
            <li><strong>Firewall clients</strong> are distinct pairs of source address and user agent that fetched a list through <code>feed.php</code>. Firewalls behind the same NAT address with the same user agent count as one, and a browser opening a list counts as a client too.</li>
            <li>A client has <strong>stopped polling</strong> when it hasn't fetched in three of its usual polling intervals (at least an hour), or in a day if it has only fetched once.</li>
        </ul>
    </div>
</div>

</div>

<?php require_once '../includes/footer.php'; ?>
