"""
JSON Reporter for machine-readable output.
"""

import json
import os
from pathlib import Path
import tempfile
from php_deserial_sast.models import ScanResult


class JSONReporter:
    """Exports ScanResult to formatted JSON."""

    def generate_json(self, result: ScanResult) -> str:
        return result.model_dump_json(indent=2)

    def save_to_file(self, result: ScanResult, output_path: str):
        # Serialize one record at a time and replace only a complete report.
        # A killed process must not truncate a previous valid destination.
        target = Path(output_path)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                             prefix=target.name + ".", suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write("{\n")
                for index, name in enumerate(type(result).model_fields):
                    if index:
                        stream.write(",\n")
                    json.dump(name, stream)
                    stream.write(": ")
                    value = getattr(result, name)
                    if isinstance(value, list):
                        stream.write("[")
                        for item_index, item in enumerate(value):
                            if item_index:
                                stream.write(",\n")
                            if hasattr(item, "model_dump_json"):
                                stream.write(item.model_dump_json())
                            else:
                                json.dump(item, stream, ensure_ascii=False)
                        stream.write("]")
                    elif hasattr(value, "model_dump_json"):
                        stream.write(value.model_dump_json())
                    else:
                        json.dump(value, stream, ensure_ascii=False)
                stream.write("\n}\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
