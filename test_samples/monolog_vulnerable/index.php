<?php
/**
 * Vulnerable Web Application Endpoint using Monolog
 * Demonstrating PHP Insecure Deserialization (CWE-502)
 */

spl_autoload_register(function ($class) {
    $prefix = 'Monolog\\';
    $base_dir = __DIR__ . '/monolog/src/Monolog/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});

// Untrusted user input via HTTP POST parameter
if (isset($_POST['data'])) {
    $raw_input = $_POST['data'];
    $decoded_data = base64_decode($raw_input);

    // Insecure Deserialization sink (CWE-502)
    $user_session = unserialize($decoded_data);

    echo "Session loaded successfully.";
}
