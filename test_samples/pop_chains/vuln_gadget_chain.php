<?php
// Multi-hop POP Gadget Chain Sample (PHPGGC inspired)
namespace App\POP;

class SessionCleanup {
    public $handler;
    public $sessionId = "admin_sess";

    public function __destruct() {
        if ($this->handler != null) {
            // Hop 1: Dynamic dispatch on $this->handler
            $this->handler->close($this->sessionId);
        }
    }
}

class FileLogger {
    public $logPath = "/var/log/app.log";

    public function close($content) {
        // Sink: Arbitrary File Write
        file_put_contents($this->logPath, $content);
    }
}

class DynamicCaller {
    public $callback = "system";
    public $payload = "id";

    public function __call($name, $arguments) {
        // Sink: Dynamic RCE Invocation
        call_user_func($this->callback, $this->payload);
    }
}

class CodeSnippet {
    public $code = "phpinfo();";

    public function __toString() {
        // Sink: Direct code evaluation
        eval($this->code);
        return "evaluated";
    }
}
