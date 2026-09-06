<?php
// Vulnerable Sample: Direct unserialize from Cookie session
namespace App\Http;

class SessionManager {
    public function loadUserSession() {
        if (isset($_COOKIE['auth_session'])) {
            $rawCookie = $_COOKIE['auth_session'];
            $decoded = base64_decode($rawCookie);
            
            // Vulnerable direct unserialize sink without allowed_classes
            $userObject = unserialize($decoded);
            return $userObject;
        }
        return null;
    }
}
