"""Classify where a finding occurs without changing its security rating."""

from pathlib import Path


def is_test_source_path(path):
    file = Path(path)
    return (file.name.lower() in {'test.php', 'tests.php'}
            or file.stem.endswith('Test')
            or any(part.lower() in {'test', 'tests', '__tests__', 'testing', 'fixtures'}
                   for part in file.parts[:-1]))


def source_scope(target_path, file_path):
    """Return a structural scope based only on the path inside the scan root."""
    target = Path(target_path).resolve()
    file = Path(file_path).resolve()
    try:
        parts = file.relative_to(target if target.is_dir() else target.parent).parts[:-1]
    except ValueError:
        return 'external'
    lowered = {part.lower() for part in parts}
    if is_test_source_path(file.relative_to(target if target.is_dir() else target.parent)):
        return 'tests'
    if lowered & {'example', 'examples', 'demo', 'demos'}:
        return 'examples'
    if lowered & {'vendor', 'vendors', 'node_modules'}:
        return 'vendor'
    return 'production'
