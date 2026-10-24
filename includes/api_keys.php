<?php
// includes/api_keys.php - API keys for the REST API.
//
// A token is "edl_<id>_<secret>". Only a SHA-256 hash of the secret is
// stored; the token is shown once, when the key is created. The secret is 32
// random bytes, so a fast hash is enough (there is nothing to brute-force).

// What a key may do. "remove" takes entries off the blocklist, which the web
// UI only allows for admins.
const API_KEY_PERMISSIONS = ['view', 'submit', 'approve', 'remove'];

function api_keys_file() {
    return DATA_DIR . '/api_keys.json';
}

// The key as shown in the UI and the audit log, without the secret hash.
function api_key_public(array $key) {
    unset($key['secret_hash']);
    return $key;
}

/**
 * Create a key. Returns ['token' => full token, 'key' => public record].
 */
function api_key_create($name, array $permissions, $created_by) {
    $name = trim((string) $name);
    $permissions = array_values(array_intersect(API_KEY_PERMISSIONS, $permissions));
    if ($name === '' || strlen($name) > 64) {
        throw new InvalidArgumentException('Name the key (up to 64 characters), e.g. after the system that will use it');
    }
    if (!$permissions) {
        throw new InvalidArgumentException('Choose at least one permission');
    }

    $id = bin2hex(random_bytes(6));
    $secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $key = [
        'id' => $id,
        'name' => sanitize_input($name),
        'permissions' => $permissions,
        'created_by' => $created_by,
        'created_at' => date('c'),
        'last_used_at' => null,
        'last_used_ip' => null,
        'revoked_at' => null,
        'revoked_by' => null,
        'secret_hash' => hash('sha256', $secret),
    ];

    update_json_file(api_keys_file(), function ($keys) use ($key) {
        $keys[$key['id']] = $key;
        return $keys;
    });
    log_activity('api_key_created', "Created API key \"{$key['name']}\" ({$id}) with permissions: " . implode(', ', $permissions), '', $created_by);

    return ['token' => "edl_{$id}_{$secret}", 'key' => api_key_public($key)];
}

/**
 * All keys, newest first, without secret hashes.
 */
function api_key_list() {
    $keys = array_map('api_key_public', array_values(read_json_file(api_keys_file())));
    usort($keys, fn($a, $b) => strcmp($b['created_at'] ?? '', $a['created_at'] ?? ''));
    return $keys;
}

function api_key_revoke($id, $revoked_by) {
    $revoked = null;
    update_json_file(api_keys_file(), function ($keys) use ($id, $revoked_by, &$revoked) {
        if (isset($keys[$id]) && empty($keys[$id]['revoked_at'])) {
            $keys[$id]['revoked_at'] = date('c');
            $keys[$id]['revoked_by'] = $revoked_by;
            $revoked = $keys[$id];
        }
        return $keys;
    });
    if ($revoked) {
        log_activity('api_key_revoked', "Revoked API key \"{$revoked['name']}\" ({$id})", '', $revoked_by);
    }
    return $revoked !== null;
}

/**
 * The active key for $token, or null.
 */
function api_key_authenticate($token) {
    if (!preg_match('/^edl_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$/', (string) $token, $m)) {
        return null;
    }
    $keys = read_json_file(api_keys_file());
    $key = $keys[$m[1]] ?? null;
    if (!$key || !empty($key['revoked_at']) || !hash_equals($key['secret_hash'], hash('sha256', $m[2]))) {
        return null;
    }

    // Record use at most once a minute, so busy integrations don't rewrite
    // the file on every call.
    $last_used = $key['last_used_at'] ? strtotime($key['last_used_at']) : 0;
    if (time() - $last_used >= 60) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;
        update_json_file(api_keys_file(), function ($keys) use ($key, $ip) {
            if (isset($keys[$key['id']])) {
                $keys[$key['id']]['last_used_at'] = date('c');
                $keys[$key['id']]['last_used_ip'] = $ip;
            }
            return $keys;
        });
    }
    return $key;
}
