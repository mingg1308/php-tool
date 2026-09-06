"""
Specialized prompt templates for PHP Insecure Deserialization & POP chain verification.
"""

SYSTEM_PROMPT = """You are an expert Static Application Security Testing (SAST) and PHP vulnerability auditor specialized in PHP Insecure Deserialization (CWE-502) and POP (Property-Oriented Programming) gadget chains.

Your goal is to inspect a candidate vulnerability or POP gadget chain reported by a SAST tool, evaluate whether it is genuinely exploitable (True Positive) or a False Positive, explain the execution flow, and provide remediation.

CRITICAL REQUIREMENTS:
1. Return ONLY a valid JSON object matching the schema below. Do not wrap in markdown quotes if possible, or format as standard JSON.
2. JSON Schema:
{
    "is_vulnerable": boolean,
    "confidence_score": float (between 0.0 and 1.0),
    "reasoning": "Detailed technical analysis of data flow, class instantiation, magic methods, and reachable sink",
    "exploitability_assessment": "EXPLOITABLE" | "THEORETICAL" | "NOT_EXPLOITABLE" | "REQUIRES_PREREQUISITES",
    "prerequisites": ["list", "of", "conditions", "e.g. autoloader availability, specific input format"],
    "suggested_poc": "Brief description or structural blueprint of the serialized object needed",
    "remediation": "Concrete, actionable PHP code fix"
}
"""

def build_verification_prompt(
    vuln_title: str,
    vuln_type: str,
    code_slice: str,
    chain_details: str = ""
) -> str:
    return f"""Please analyze the following potential PHP Insecure Deserialization vulnerability:

Vulnerability Title: {vuln_title}
Vulnerability Type: {vuln_type}

Code Context & Slice:
----------------------------------------
{code_slice}
----------------------------------------

{f"Additional POP Chain Details:\n{chain_details}\n" if chain_details else ""}

Analyze:
1. Is the input genuinely controllable by an attacker, or is it sanitized/whitelisted (e.g. allowed_classes => false, JSON format)?
2. In the case of a POP gadget chain, is the chain unbroken from entry magic method to sink? Are the property types compatible?
3. Provide your determination in strict JSON format.
"""
