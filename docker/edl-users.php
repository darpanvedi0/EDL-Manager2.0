#!/usr/bin/env php
<?php
// docker/edl-users.php - Manage local EDL Manager accounts from the command line.
// Installed in the image as /usr/local/bin/edl-users. It replaces the web-based
// user_setup.php, which is left out of the image because it has no authentication.

const ROLES = [
    'admin' => ['name' => 'System Administrator', 'permissions' => ['submit', 'approve', 'view', 'manage', 'audit']],
    'approver' => ['name' => 'Security Approver', 'permissions' => ['approve', 'view']],
    'operator' => ['name' => 'Security Operator', 'permissions' => ['submit', 'view']],
    'viewer' => ['name' => 'Security Viewer', 'permissions' => ['view']],
];
const MIN_PASSWORD_LENGTH = 12;

$users_file = rtrim(getenv('EDL_DATA_DIR') ?: '/var/lib/edl-manager', '/') . '/users.json';

function fail($message) {
    fwrite(STDERR, "edl-users: $message\n");
    exit(1);
}

function usage() {
    $roles = implode('|', array_keys(ROLES));
    fwrite(STDERR, <<<TXT
Usage:
  edl-users list
  edl-users set-password <username> [--role=$roles]
  edl-users delete <username>
  edl-users init-admin

set-password creates the account if it does not exist. The role defaults to the
username when the username is a role name. The password is read from the
terminal, or from the first line of stdin when piped.

init-admin creates the admin account when no accounts exist. It uses
EDL_ADMIN_PASSWORD or EDL_ADMIN_PASSWORD_FILE, or generates a password and
prints it once.

TXT);
    exit(2);
}

function load_users($file) {
    if (!file_exists($file)) {
        return [];
    }
    $users = json_decode((string) file_get_contents($file), true);
    if (!is_array($users)) {
        fail("$file is not valid JSON; refusing to overwrite it");
    }
    return $users;
}

// Write to a temp file and rename it over users.json, so the web app never
// reads a half-written file.
function save_users($file, $users) {
    $dir = dirname($file);
    $tmp = $dir . '/.users.json.' . bin2hex(random_bytes(6));
    $json = json_encode($users ?: new stdClass(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (@file_put_contents($tmp, $json . "\n") === false) {
        fail("cannot write to $dir");
    }
    chmod($tmp, 0600);
    if (!@rename($tmp, $file)) {
        @unlink($tmp);
        fail("cannot replace $file");
    }
}

function check_password($password) {
    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        fail('password must be at least ' . MIN_PASSWORD_LENGTH . ' characters');
    }
}

function read_password() {
    if (!stream_isatty(STDIN)) {
        return rtrim((string) fgets(STDIN), "\r\n");
    }
    $prompt = function ($label) {
        fwrite(STDERR, $label);
        shell_exec('stty -echo');
        $value = rtrim((string) fgets(STDIN), "\r\n");
        shell_exec('stty echo');
        fwrite(STDERR, "\n");
        return $value;
    };
    $password = $prompt('New password: ');
    if ($prompt('Repeat password: ') !== $password) {
        fail('passwords do not match');
    }
    return $password;
}

function make_user($role) {
    return [
        'password' => '',
        'name' => ROLES[$role]['name'],
        'email' => '',
        'role' => $role,
        'permissions' => ROLES[$role]['permissions'],
    ];
}

// users.json must stay owned by the web server user; a copy written by root
// would be unreadable to Apache.
if (posix_geteuid() === 0) {
    fail('run this as www-data, not root (drop "-u root" from docker exec)');
}

$args = array_slice($argv, 1);
$command = array_shift($args) ?? '';
$role = null;
$positional = [];
foreach ($args as $arg) {
    if (strpos($arg, '--role=') === 0) {
        $role = substr($arg, 7);
    } else {
        $positional[] = $arg;
    }
}

switch ($command) {
    case 'list':
        foreach (load_users($users_file) as $username => $user) {
            printf("%-20s %-10s %s\n", $username, $user['role'] ?? '?', $user['name'] ?? '');
        }
        break;

    case 'set-password':
        $username = $positional[0] ?? usage();
        if (!preg_match('/^[A-Za-z0-9._@-]{1,64}$/', $username)) {
            fail('username may only contain letters, digits, and . _ @ -');
        }
        $users = load_users($users_file);
        if ($role !== null && !isset(ROLES[$role])) {
            fail('unknown role "' . $role . '"; use one of: ' . implode(', ', array_keys(ROLES)));
        }
        if (!isset($users[$username])) {
            $role = $role ?? (isset(ROLES[$username]) ? $username : null);
            if ($role === null) {
                fail("$username does not exist; pass --role to create it");
            }
            $users[$username] = make_user($role);
        } elseif ($role !== null && $role !== ($users[$username]['role'] ?? null)) {
            fail("$username already exists with role " . ($users[$username]['role'] ?? '?') . '; delete it first to change the role');
        }
        $password = read_password();
        check_password($password);
        $users[$username]['password'] = password_hash($password, PASSWORD_DEFAULT);
        save_users($users_file, $users);
        echo "Password set for $username ({$users[$username]['role']}).\n";
        break;

    case 'delete':
        $username = $positional[0] ?? usage();
        $users = load_users($users_file);
        if (!isset($users[$username])) {
            fail("$username does not exist");
        }
        $admins = array_filter($users, fn($u) => ($u['role'] ?? '') === 'admin');
        if (($users[$username]['role'] ?? '') === 'admin' && count($admins) === 1) {
            fail("$username is the only admin account");
        }
        unset($users[$username]);
        save_users($users_file, $users);
        echo "Deleted $username.\n";
        break;

    case 'init-admin':
        if (load_users($users_file)) {
            break;
        }
        $password = getenv('EDL_ADMIN_PASSWORD') ?: '';
        $password_file = getenv('EDL_ADMIN_PASSWORD_FILE') ?: '';
        if ($password_file !== '') {
            $password = rtrim((string) @file_get_contents($password_file), "\r\n");
            if ($password === '') {
                fail("EDL_ADMIN_PASSWORD_FILE ($password_file) is empty or unreadable");
            }
        }
        $generated = $password === '';
        if ($generated) {
            $password = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
        }
        check_password($password);
        $users = ['admin' => make_user('admin')];
        $users['admin']['password'] = password_hash($password, PASSWORD_DEFAULT);
        save_users($users_file, $users);
        if ($generated) {
            echo "==============================================================\n";
            echo " EDL Manager: created the admin account.\n";
            echo " Initial admin password: $password\n";
            echo " Change it with: edl-users set-password admin\n";
            echo "==============================================================\n";
        } else {
            echo "EDL Manager: created the admin account from EDL_ADMIN_PASSWORD" . ($password_file !== '' ? '_FILE' : '') . ".\n";
        }
        break;

    default:
        usage();
}
