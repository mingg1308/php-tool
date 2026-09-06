<?php
// Vulnerable Sample: Direct unserialize from POST input
namespace App\Controller;

class ImportController {
    public function importData() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $payload = $_POST['import_payload'];
            $sanitized = stripslashes($payload);
            
            // Vulnerable sink
            $data = unserialize($sanitized);
            echo "Data imported successfully!";
        }
    }
}
