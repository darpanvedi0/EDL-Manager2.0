<?php
// includes/requests.php - Submit, approve, deny, and remove blocklist entries.
//
// Used by the REST API. Records have the same shape the web pages write, so
// entries from either path look the same in the UI, the blocklists, and the
// metrics.

require_once __DIR__ . '/validation.php';
require_once __DIR__ . '/edl_lists.php';

const EDL_ENTRY_TYPES = ['ip', 'domain', 'url'];
const EDL_PRIORITIES = ['low', 'medium', 'high', 'critical'];
const EDL_MAX_ENTRIES_PER_SUBMISSION = 500;

/**
 * Guess an entry's type the way the submit page does, plus CIDR ranges.
 * Returns null when the type can't be determined.
 */
function edl_detect_type($entry) {
    if (preg_match('/^https?:\/\//', $entry)) {
        return 'url';
    }
    if (filter_var($entry, FILTER_VALIDATE_IP)) {
        return 'ip';
    }
    if (strpos($entry, '/') !== false && filter_var(explode('/', $entry, 2)[0], FILTER_VALIDATE_IP)) {
        return 'ip';
    }
    if (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\.-]*\.[a-zA-Z]{2,}$/', $entry)) {
        return 'domain';
    }
    return null;
}

// Same ticket formats the submit page accepts.
function edl_valid_ticket($ticket) {
    return (bool) preg_match('/^(INC|REQ|CHG|RITM|TASK|SCTASK|SIR)[0-9]{7}$/', $ticket);
}

/**
 * Why $entry can't be queued, or null if it can.
 */
function edl_entry_problem($entry, $type) {
    if ($entry === '') {
        return 'Entry is empty';
    }
    if ($type === null) {
        return 'Could not determine the entry type; pass "type" (ip, domain, or url)';
    }
    if (!in_array($type, EDL_ENTRY_TYPES, true)) {
        return 'Unknown type "' . $type . '"; use ip, domain, or url';
    }
    // The web pages store entries HTML-escaped, so these characters would be
    // written to the blocklist as entities and never match on the firewall.
    if (preg_match('/[&<>"\']/', $entry)) {
        return 'Entries containing & < > " or \' are not supported yet';
    }
    $validation = validate_entry_comprehensive($entry, $type);
    return $validation['valid'] ? null : $validation['error'];
}

/**
 * Why $entry is already handled (in the blocklist, pending, or denied), or
 * null. Unlike check_entry_exists(), a removed entry can be submitted again.
 */
function edl_existing_entry_problem($entry, $type, $pending, $approved, $denied) {
    foreach ($approved as $item) {
        if (($item['entry'] ?? null) === $entry && ($item['status'] ?? '') === 'active') {
            return 'Already in the blocklist';
        }
    }
    foreach ($pending as $item) {
        if (($item['entry'] ?? null) === $entry && ($item['type'] ?? null) === $type && ($item['status'] ?? 'pending') === 'pending') {
            return 'Already pending approval';
        }
    }
    foreach ($denied as $item) {
        if (($item['entry'] ?? null) === $entry && ($item['type'] ?? null) === $type) {
            return 'Previously denied: ' . ($item['reason'] ?? 'no reason recorded');
        }
    }
    return null;
}

/**
 * Validate entries and queue them for approval.
 *
 * $items is a list of ['entry' => string, 'type' => string|null]. $fields
 * holds justification, servicenow_ticket, priority, and comment.
 *
 * Returns ['errors' => [...]] when the submission as a whole is invalid,
 * otherwise ['created' => [requests], 'skipped' => [['entry', 'reason']]].
 */
function edl_submit_requests(array $items, array $fields, $actor) {
    $justification = trim((string) ($fields['justification'] ?? ''));
    $ticket = trim((string) ($fields['servicenow_ticket'] ?? ''));
    $priority = (string) ($fields['priority'] ?? 'medium');
    $comment = trim((string) ($fields['comment'] ?? ''));

    $errors = [];
    if ($justification === '') {
        $errors[] = 'justification is required';
    }
    if (!edl_valid_ticket($ticket)) {
        $errors[] = 'servicenow_ticket is required, in a format like INC1234567, REQ1234567, CHG1234567, or SIR1234567';
    }
    if (!in_array($priority, EDL_PRIORITIES, true)) {
        $errors[] = 'priority must be one of: ' . implode(', ', EDL_PRIORITIES);
    }
    if (!$items) {
        $errors[] = 'Provide "entry" or a non-empty "entries" list';
    } elseif (count($items) > EDL_MAX_ENTRIES_PER_SUBMISSION) {
        $errors[] = 'At most ' . EDL_MAX_ENTRIES_PER_SUBMISSION . ' entries per submission';
    }
    if ($errors) {
        return ['errors' => $errors];
    }

    // Hold the lock from the duplicate checks through the write, like the
    // submit page, so concurrent submissions can't both pass the checks.
    return with_data_lock(function () use ($items, $justification, $ticket, $priority, $comment, $actor) {
        $pending = read_json_file(DATA_DIR . '/pending_requests.json');
        $approved = read_json_file(DATA_DIR . '/approved_entries.json');
        $denied = read_json_file(DATA_DIR . '/denied_entries.json');

        $created = [];
        $skipped = [];
        $seen = [];
        foreach ($items as $item) {
            $entry = trim((string) ($item['entry'] ?? ''));
            $type = isset($item['type']) && $item['type'] !== '' && $item['type'] !== 'auto'
                ? (string) $item['type']
                : edl_detect_type($entry);

            $problem = edl_entry_problem($entry, $type)
                ?? (isset($seen["$type|$entry"]) ? 'Duplicate in this submission' : null)
                ?? edl_existing_entry_problem($entry, $type, $pending, $approved, $denied);
            if ($problem !== null) {
                $skipped[] = ['entry' => $entry, 'reason' => $problem];
                continue;
            }
            $seen["$type|$entry"] = true;

            $created[] = [
                'id' => generate_unique_id('req'),
                'entry' => $entry,
                'type' => $type,
                'justification' => sanitize_input($justification),
                'comment' => sanitize_input($comment),
                'priority' => $priority,
                'servicenow_ticket' => $ticket,
                'submitted_by' => $actor,
                'submitted_at' => date('Y-m-d H:i:s'),
                'status' => 'pending',
                'submission_type' => count($items) > 1 ? 'bulk' : 'individual',
                'source' => 'api',
            ];
        }

        if ($created) {
            if (!write_json_file(DATA_DIR . '/pending_requests.json', array_merge($pending, $created))) {
                throw new RuntimeException('Failed to save the requests');
            }
            append_audit_log([
                'id' => generate_unique_id('audit'),
                'timestamp' => date('c'),
                'action' => count($created) > 1 ? 'bulk_request_submitted' : 'request_submitted',
                'entry' => count($created) === 1 ? $created[0]['entry'] : '',
                'user' => $actor,
                'details' => count($created) > 1
                    ? 'Submitted ' . count($created) . ' entries via the API'
                    : "Submitted entry via the API: {$created[0]['entry']}",
            ]);
        }

        return ['created' => $created, 'skipped' => $skipped];
    });
}

/**
 * Approve or deny a pending request.
 *
 * Returns ['request' => ..., 'record' => approved or denied record] on
 * success, or ['error' => not_found|conflict|invalid, 'message' => ...].
 */
function edl_decide_request($request_id, $approve, $actor, $comment) {
    $comment = trim((string) $comment);
    if (!$approve && $comment === '') {
        return ['error' => 'invalid', 'message' => 'A reason is required to deny a request'];
    }

    return with_data_lock(function () use ($request_id, $approve, $actor, $comment) {
        $pending = read_json_file(DATA_DIR . '/pending_requests.json');
        $key = null;
        foreach ($pending as $k => $request) {
            if (($request['id'] ?? null) === $request_id && ($request['status'] ?? 'pending') === 'pending') {
                $key = $k;
                break;
            }
        }
        if ($key === null) {
            $found = edl_find_request($request_id);
            return $found
                ? ['error' => 'conflict', 'message' => "Request was already {$found['status']}"]
                : ['error' => 'not_found', 'message' => 'Request not found'];
        }
        $request = $pending[$key];

        if ($approve) {
            $validation = validate_entry_comprehensive($request['entry'], $request['type']);
            if (!$validation['valid']) {
                return ['error' => 'invalid', 'message' => 'Cannot approve invalid entry: ' . $validation['error']];
            }
            $approved = read_json_file(DATA_DIR . '/approved_entries.json');
            foreach ($approved as $existing) {
                if ($existing['entry'] === $request['entry'] && $existing['status'] === 'active') {
                    return ['error' => 'conflict', 'message' => 'Entry already exists in the blocklist'];
                }
            }

            $record = [
                'id' => uniqid('app_', true),
                'entry' => $request['entry'],
                'type' => $request['type'],
                'comment' => $request['comment'] ?? '',
                'justification' => $request['justification'],
                'priority' => $request['priority'],
                'submitted_by' => $request['submitted_by'],
                'submitted_at' => $request['submitted_at'],
                'approved_by' => $actor,
                'approved_at' => date('c'),
                'status' => 'active',
                'admin_comment' => sanitize_input($comment),
                'request_id' => $request['id'],
                'source' => 'request',
            ];
            if (isset($request['servicenow_ticket'])) {
                $record['servicenow_ticket'] = $request['servicenow_ticket'];
            }
            $approved[] = $record;
            $saved = write_json_file(DATA_DIR . '/approved_entries.json', $approved);
        } else {
            $record = [
                'id' => uniqid('den_', true),
                'entry' => $request['entry'],
                'type' => $request['type'],
                'comment' => $request['comment'] ?? '',
                'justification' => $request['justification'],
                'priority' => $request['priority'],
                'submitted_by' => $request['submitted_by'],
                'submitted_at' => $request['submitted_at'],
                'denied_by' => $actor,
                'denied_at' => date('c'),
                'reason' => sanitize_input($comment),
                'request_id' => $request['id'],
            ];
            if (isset($request['servicenow_ticket'])) {
                $record['servicenow_ticket'] = $request['servicenow_ticket'];
            }
            $denied = read_json_file(DATA_DIR . '/denied_entries.json');
            $denied[] = $record;
            $saved = write_json_file(DATA_DIR . '/denied_entries.json', $denied);
        }
        if (!$saved) {
            throw new RuntimeException('Failed to save the decision');
        }

        unset($pending[$key]);
        write_json_file(DATA_DIR . '/pending_requests.json', array_values($pending));
        if ($approve) {
            write_edl_lists();
        }

        append_audit_log([
            'id' => generate_unique_id('audit'),
            'timestamp' => date('c'),
            'action' => $approve ? 'approve' : 'deny',
            'entry' => $request['entry'],
            'user' => $actor,
            'details' => ($approve ? 'Approved' : 'Denied') . " {$request['type']} request from {$request['submitted_by']} via the API",
            'request_id' => $request['id'],
            'admin_comment' => sanitize_input($comment),
        ]);

        return ['request' => $request, 'record' => $record];
    });
}

/**
 * Remove an active entry from the blocklist. The record is kept with status
 * "deleted", as the EDL viewer does.
 */
function edl_remove_entry($entry_id, $actor, $reason) {
    return with_data_lock(function () use ($entry_id, $actor, $reason) {
        $approved = read_json_file(DATA_DIR . '/approved_entries.json');
        foreach ($approved as $key => $entry) {
            if (($entry['id'] ?? null) !== $entry_id) {
                continue;
            }
            if (($entry['status'] ?? '') !== 'active') {
                return ['error' => 'conflict', 'message' => 'Entry was already removed'];
            }
            $approved[$key]['status'] = 'deleted';
            $approved[$key]['deleted_by'] = $actor;
            $approved[$key]['deleted_at'] = date('c');
            if (trim((string) $reason) !== '') {
                $approved[$key]['deletion_reason'] = sanitize_input(trim($reason));
            }
            if (!write_json_file(DATA_DIR . '/approved_entries.json', $approved)) {
                throw new RuntimeException('Failed to save the removal');
            }
            write_edl_lists();
            append_audit_log([
                'id' => generate_unique_id('audit'),
                'timestamp' => date('c'),
                'action' => 'delete_entry',
                'entry' => $entry['entry'],
                'user' => $actor,
                'details' => "Removed {$entry['type']} entry from the active EDL via the API",
                'admin_comment' => $approved[$key]['deletion_reason'] ?? '',
            ]);
            return ['record' => $approved[$key]];
        }
        return ['error' => 'not_found', 'message' => 'Entry not found'];
    });
}

/**
 * Find a request by id wherever it is now. Returns null, or
 * ['status' => pending|approved|denied|deleted, 'record' => ...].
 */
function edl_find_request($request_id) {
    foreach (read_json_file(DATA_DIR . '/pending_requests.json') as $request) {
        if (($request['id'] ?? null) === $request_id) {
            return ['status' => $request['status'] ?? 'pending', 'record' => $request];
        }
    }
    foreach (read_json_file(DATA_DIR . '/approved_entries.json') as $entry) {
        if (($entry['request_id'] ?? null) === $request_id) {
            return ['status' => ($entry['status'] ?? '') === 'active' ? 'approved' : 'deleted', 'record' => $entry];
        }
    }
    foreach (read_json_file(DATA_DIR . '/denied_entries.json') as $denied) {
        if (($denied['request_id'] ?? null) === $request_id) {
            return ['status' => 'denied', 'record' => $denied];
        }
    }
    return null;
}
