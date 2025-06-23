<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h1>EDL Manager Setup</h1>";

// Create directory structure
$dirs = [
    'config',
    'includes',
    'assets',
    'assets/css', 
    'assets/js',
    'data',
    'edl-files',
    'pages',
    'api'
];

echo "<h2>Creating directories...</h2>";
foreach ($dirs as $dir) {
    if (!is_dir($dir)) {
        if (mkdir($dir, 0755, true)) {
            echo "✅ Created: $dir<br>";
        } else {
            echo "❌ Failed to create: $dir<br>";
        }
    } else {
        echo "➡️ Already exists: $dir<br>";
    }
}

// Create basic CSS file
echo "<h2>Creating basic assets...</h2>";
$basic_css = "
body { 
    font-family: Arial, sans-serif; 
    margin: 20px;
    background: #f8f9fa;
}
.container { max-width: 1200px; margin: 0 auto; }
.card { 
    background: white; 
    border: 1px solid #dee2e6; 
    border-radius: 0.375rem; 
    margin-bottom: 1rem;
    box-shadow: 0 0.125rem 0.25rem rgba(0,0,0,0.075);
}
.card-header { 
    background: #f8f9fa; 
    border-bottom: 1px solid #dee2e6; 
    padding: 1rem;
    font-weight: 600;
}
.card-body { padding: 1rem; }
.btn { 
    display: inline-block; 
    padding: 0.375rem 0.75rem; 
    margin: 0.25rem; 
    background: #0d6efd; 
    color: white; 
    text-decoration: none; 
    border-radius: 0.375rem;
    border: none;
    cursor: pointer;
}
.btn:hover { background: #0b5ed7; color: white; }
.btn-success { background: #198754; }
.btn-info { background: #0dcaf0; color: #000; }
.alert { 
    padding: 0.75rem 1.25rem; 
    margin-bottom: 1rem; 
    border: 1px solid transparent; 
    border-radius: 0.375rem;
}
.alert-info { 
    color: #055160; 
    background-color: #d1ecf1; 
    border-color: #bee5eb;
}
";

if (file_put_contents('assets/css/style.css', $basic_css)) {
    echo "✅ Created: assets/css/style.css<br>";
} else {
    echo "❌ Failed to create: assets/css/style.css<br>";
}

// Create basic JS file
$basic_js = "
console.log('EDL Manager loaded');
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM ready');
});
";

if (file_put_contents('assets/js/main.js', $basic_js)) {
    echo "✅ Created: assets/js/main.js<br>";
} else {
    echo "❌ Failed to create: assets/js/main.js<br>";
}

echo "<h2>Setup complete!</h2>";
echo "<p><a href='index.php' class='btn'>Go to Index</a></p>";
echo "<p><a href='debug.php' class='btn btn-info'>Run Debug</a></p>";
?>