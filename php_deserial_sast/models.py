"""
Data models and definitions for PHP Insecure Deserialization SAST Scanner.
"""

from enum import Enum
from typing import List, Dict, Optional, Any, Literal
from pydantic import BaseModel, Field, StrictBool


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        levels = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1
        }
        return levels.get(self.value, 0)


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VulnerabilityType(str, Enum):
    LIBRARY_API_EXPOSURE = "LIBRARY_API_EXPOSURE"
    DIRECT_UNSERIALIZE = "DIRECT_UNSERIALIZE"
    PHAR_DESERIALIZATION = "PHAR_DESERIALIZATION"
    POP_GADGET_CHAIN = "POP_GADGET_CHAIN"
    DANGEROUS_MAGIC_METHOD = "DANGEROUS_MAGIC_METHOD"
    CUSTOM_RULE_MATCH = "CUSTOM_RULE_MATCH"


class CodeLocation(BaseModel):
    file_path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def __str__(self) -> str:
        return f"{self.file_path}:{self.start_line}:{self.start_col}"


class TaintStep(BaseModel):
    location: CodeLocation
    code_snippet: str
    description: str
    variable_name: Optional[str] = None


class GadgetStep(BaseModel):
    step_number: int
    class_name: str
    method_name: str
    step_type: str  # e.g., "ENTRY_MAGIC_METHOD", "METHOD_CALL_DISPATCH", "PROPERTY_ACCESS", "STRING_CONVERSION", "SINK_CALL"
    target_class: Optional[str] = None
    target_method: Optional[str] = None
    location: CodeLocation
    code_snippet: str
    description: str
    controllable_properties: List[str] = Field(default_factory=list)


class GadgetChain(BaseModel):
    chain_id: str
    entry_class: str
    entry_method: str  # e.g., "__destruct", "__wakeup", "__toString"
    sink_class: str
    sink_method: str
    sink_function: str  # e.g., "eval", "system", "call_user_func", "file_put_contents"
    sink_type: str  # "RCE", "FILE_WRITE", "FILE_READ", "FILE_DELETE", "CODE_EXEC"
    steps: List[GadgetStep]
    candidate_serialized_properties: List[str] = Field(default_factory=list)
    length: int
    confidence: Confidence = Confidence.MEDIUM
    severity: Severity = Severity.HIGH
    explanation: str = ""
    payload_blueprint: Optional[str] = None


class LLMVerificationResult(BaseModel):
    is_vulnerable: StrictBool
    confidence_score: float = Field(ge=0.0, le=1.0)
    verdict: Literal["CONFIRMED", "LIKELY", "NEEDS_CONTEXT", "FALSE_POSITIVE"] = "NEEDS_CONTEXT"
    reachability: str = "UNKNOWN"
    sanitization: str = "UNKNOWN"
    exploitability: str = "UNKNOWN"
    reasoning: str
    exploitability_assessment: str
    prerequisites: List[str] = Field(default_factory=list)
    suggested_poc: Optional[str] = None
    remediation: Optional[str] = None


class FlowEvidence(BaseModel):
    """One retained static route, not an assertion of exploitability."""
    source_kind: str
    source_origin: str
    source_parameter: int = -1
    source_fields: List[Any] = Field(default_factory=list)
    uncertain: bool = False
    guard_status: Literal["no_guard", "unrecognized_guard"] = "no_guard"
    review_conditions: List[str] = Field(default_factory=list)
    path_assumptions: List[str] = Field(default_factory=list)
    trace: List[TaintStep] = Field(default_factory=list)


class EvidenceAssessment(BaseModel):
    potential_impact: Severity
    evidence_level: Literal["syntactic_review", "candidate_call_chain", "assumed_api_flow", "assumed_persistent_flow", "modeled_source_flow", "observed_source_flow", "unresolved_flow"]
    detection_level: Literal["direct_untrusted_deserialization", "conditional_path", "review_candidate"] = "review_candidate"
    analysis_completeness: Literal["within_model", "limited"]
    limitations: List[str] = Field(default_factory=list)
    exploitability_verified: bool = False


class Finding(BaseModel):
    id: str
    rule_id: str
    vuln_type: VulnerabilityType
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    location: CodeLocation
    code_snippet: str
    dataflow_trace: Optional[List[TaintStep]] = None
    gadget_chain: Optional[GadgetChain] = None
    cwe: Optional[str] = "CWE-502: Deserialization of Untrusted Data"
    owasp: Optional[str] = "A08:2021-Software and Data Integrity Failures"
    remediation: Optional[str] = None
    llm_verification: Optional[LLMVerificationResult] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    flow_evidence: List[FlowEvidence] = Field(default_factory=list)
    assessment: Optional[EvidenceAssessment] = None


class SinkInventoryEntry(BaseModel):
    location: CodeLocation
    sink_name: str
    sink_argument: int
    disposition: str
    source_assumption: Optional[str] = None
    evidence: List[TaintStep] = Field(default_factory=list)
    note: str = ""


class ScanSummary(BaseModel):
    api_exposure_count: int = 0
    total_files_discovered: int = 0
    total_files_scanned: int = 0
    files_with_errors: int = 0
    total_lines_scanned: int = 0
    total_classes_found: int = 0
    total_methods_found: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    gadget_chains_found: int = 0
    scan_duration_seconds: float = 0.0


class ScanError(BaseModel):
    file_path: str
    phase: str
    message: str


class ScanResult(BaseModel):
    analysis: Dict[str, Any] = Field(default_factory=dict)
    target_path: str
    summary: ScanSummary
    findings: List[Finding]
    sink_inventory: List[SinkInventoryEntry] = Field(default_factory=list)
    gadget_chains: List[GadgetChain] = Field(default_factory=list)
    all_classes: List[str] = Field(default_factory=list)
    errors: List[ScanError] = Field(default_factory=list)
