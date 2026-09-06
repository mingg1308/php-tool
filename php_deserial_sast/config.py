"""
Configuration settings for PHP Deserialization SAST Scanner.
"""

import os
from typing import List, Optional
from pydantic import BaseModel, Field
from php_deserial_sast.models import Severity


DEFAULT_BUILTIN_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules", "definitions")


class ScannerConfig(BaseModel):
    target_path: str = "."
    rules_dir: str = DEFAULT_BUILTIN_RULES_DIR
    enable_taint: bool = True
    enable_gadgets: bool = True
    enable_rules: bool = True
    enable_llm: bool = False
    llm_provider: str = "openai"  # openai, gemini, ollama
    llm_model: Optional[str] = None
    llm_api_key: Optional[str] = None
    min_severity: Severity = Severity.LOW
    max_chain_depth: int = 6
    exclude_dirs: List[str] = Field(default_factory=lambda: [".git", "node_modules", ".svn", "vendor_disabled"])
    output_format: str = "console"  # console, json, sarif, html
    output_file: Optional[str] = None
