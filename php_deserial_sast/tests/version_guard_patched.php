<?php
if (version_compare(PHP_VERSION, '7.0.0', '>=')) {
    unserialize($_GET['value'], ['allowed_classes' => FALSE]);
} else {
    unserialize($_GET['value']);
}
