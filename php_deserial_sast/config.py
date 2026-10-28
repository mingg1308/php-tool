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
    # None lets a top-level Composer package with type=library select the
    # external-caller assumption automatically. Explicit False disables it.
    library_mode: Optional[bool] = None
    framework_models: bool = True
    experimental_foreach_cfg: bool = False
    experimental_side_effects: bool = False
    experimental_demand_summaries: bool = True  # Legacy field name; demand mode is now the default.
    max_file_bytes: int = Field(default=0, ge=0)
    max_ast_nodes: int = Field(default=0, ge=0)
    max_gadget_paths: int = Field(default=10000, ge=1)
    max_gadget_expansions: int = Field(default=250000, ge=1)
    php_version: Optional[str] = Field(default=None, pattern=r"^\d+\.\d+(?:\.\d+)?$")
    llm_provider: str = "openai"  # openai, gemini, ollama
    llm_model: Optional[str] = None
    llm_api_key: Optional[str] = None
    min_severity: Severity = Severity.LOW
    max_chain_depth: int = 6
    exclude_dirs: List[str] = Field(default_factory=lambda: [".git", ".svn", ".hg", "vendor_disabled"])
    output_format: str = "console"  # console, json, sarif, html
    output_file: Optional[str] = None
