<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<!DOCTYPE html>";
echo "<html><head><title>EDL Manager Test</title></head><body>";
echo "<h1>EDL Manager - Simple Test</h1>";
echo "<p>If you see this, PHP is working!</p>";
echo "<p>PHP Version: " . PHP_VERSION . "</p>";
echo "<p>Current Time: " . date('Y-m-d H:i:s') . "</p>";

// Test basic functionality
echo "<h2>Basic Tests:</h2>";

// Test session
session_start();
echo "✅ Session started<br>";

// Test file operations
$test_file = 'data/test.txt';
if (!is_dir('data')) {
    mkdir('data', 0755, true);
    echo "✅ Created data directory<br>";
}

if (file_put_contents($test_file, 'test')) {
    echo "✅ File write successful<br>";
    unlink($test_file); // Clean up
} else {
    echo "❌ File write failed<br>";
}

// Test JSON
$test_data = ['test' => 'value'];
$json = json_encode($test_data);
if ($json) {
    echo "✅ JSON encoding works<br>";
} else {
    echo "❌ JSON encoding failed<br>";
}

echo "<p><a href='debug.php'>← Back to Debug</a></p>";
echo "</body></html>";
?>