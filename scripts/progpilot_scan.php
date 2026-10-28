<?php
// Run the downloaded source with its own Composer dependencies.
require '/tools/progpilot/vendor/autoload.php';
$context = new \progpilot\Context();
$context->setMaxFileSize(50000000);
$context->setMaxDefinitions(10000);
$context->setMaxFileAnalysisDuration(60);
$context->setMaxMemory(2500000000);
$context->setAnalyzeIncludes(true);
$context->inputs->setExclusions([]);
$context->outputs->taintedFlow(true);
// PHP 8.5 deprecations in upstream dependencies are unrelated to scan coverage.
error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);
$error = null;
$parserVersion = (new \ReflectionMethod(\progpilot\Analyzer::class, '__construct'))->getNumberOfParameters() > 0 ? ($argv[3] ?? null) : null;
try {
    $files = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
    (new \progpilot\Analyzer($parserVersion))->run($context, $files);
} catch (\Throwable $e) {
    $error = get_class($e) . ': ' . $e->getMessage();
    fwrite(STDERR, $error . "\n" . $e->getTraceAsString() . "\n");
}
file_put_contents($argv[2], json_encode([
    'results' => $context->outputs->getResults(),
    'enumerated_files' => $context->outputs->getCountAnalyzedFiles(),
    'error' => $error,
    'parser_target_php_version' => $parserVersion,
    'analysis_warning_count' => $context->outputs->analysisWarningCount ?? null,
    'analysis_warnings' => $context->outputs->analysisWarnings ?? null,
    'coverage_complete' => $error === null && isset($context->outputs->analysisWarningCount) && $context->outputs->analysisWarningCount === 0,
], JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE));
exit($error === null ? 0 : 2);
