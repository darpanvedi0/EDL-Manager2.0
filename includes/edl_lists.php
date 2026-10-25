<?php
// includes/edl_lists.php - Publish the blocklist files that firewalls fetch.

// Entry type => file in edl-files/.
const EDL_LIST_FILES = [
    'ip' => 'ip_blocklist.txt',
    'domain' => 'domain_blocklist.txt',
    'url' => 'url_blocklist.txt',
];

/**
 * Rewrite the EDL files from the active approved entries.
 *
 * Holds the data lock while reading, so an approval can't land between the
 * read and the write, and writes each file atomically so firewalls never fetch
 * a partial list. 'written' is false if any file could not be written.
 */
function write_edl_lists() {
    return with_data_lock(function () {
        $lists = array_fill_keys(array_keys(EDL_LIST_FILES), []);
        $total_active = 0;

        foreach (read_json_file(DATA_DIR . '/approved_entries.json') as $entry) {
            if (($entry['status'] ?? '') !== 'active') {
                continue;
            }
            $total_active++;
            $type = $entry['type'] ?? '';
            if (isset($lists[$type])) {
                $lists[$type][] = $entry['entry'];
            }
        }

        if (!is_dir(EDL_FILES_DIR)) {
            mkdir(EDL_FILES_DIR, 0755, true);
        }

        $written = true;
        foreach (EDL_LIST_FILES as $type => $file) {
            $written = write_file_atomic(EDL_FILES_DIR . '/' . $file, implode("\n", $lists[$type]), 0644) && $written;
        }
        if (!$written) {
            error_log('write_edl_lists: failed to write EDL files in ' . EDL_FILES_DIR);
        }

        return [
            'written' => $written,
            'ip_count' => count($lists['ip']),
            'domain_count' => count($lists['domain']),
            'url_count' => count($lists['url']),
            'total_active' => $total_active,
        ];
    });
}
