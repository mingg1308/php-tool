<?php
// Safe Implementation: unserialize with allowed_classes => false
namespace App\Safe;

class SafeDeserializer {
    public function parsePrimitives() {
        if (isset($_COOKIE['prefs'])) {
            $cookieData = $_COOKIE['prefs'];
            // Safe: allowed_classes => false prevents instantiating PHP objects
            $prefs = unserialize($cookieData, ['allowed_classes' => false]);
            return $prefs;
        }
        return null;
    }
}
