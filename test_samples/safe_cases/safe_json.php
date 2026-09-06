<?php
// Safe Implementation: Uses JSON instead of PHP serialization
namespace App\Safe;

class SafeDataProcessor {
    public function processPayload() {
        if (isset($_POST['json_data'])) {
            $input = $_POST['json_data'];
            // Safe: json_decode does not instantiate arbitrary PHP classes
            $data = json_decode($input, true);
            return $data;
        }
        return [];
    }
}
