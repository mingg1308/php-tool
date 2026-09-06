<?php
// Vulnerable Sample: Phar Deserialization via filesystem sink
namespace App\Services;

class FileViewer {
    public function viewUserAvatar() {
        $avatarPath = $_GET['avatar_url'];
        
        // Vulnerable sink: If attacker provides phar://path/to/uploaded/jpg,
        // file_exists() or exif_read_data() triggers automatic metadata deserialization
        if (file_exists($avatarPath)) {
            $meta = exif_read_data($avatarPath);
            return file_get_contents($avatarPath);
        }
        return false;
    }
}
