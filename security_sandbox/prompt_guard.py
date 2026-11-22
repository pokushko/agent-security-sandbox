import re
from typing import List, Tuple

class PromptSanitizer:
    """
    Inbound & Outbound Prompt Guard for LLM-based autonomous workflows.
    Filters known jailbreaks, prompt leaks, canary tokens, and secret patterns.
    """

    SUSPICIOUS_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions",
        r"(?i)system\s+prompt\s+override",
        r"(?i)reveal\s+(your\s+)?(secret|password|api_key|token)",
        r"(?i)disregard\s+the\s+safety\s+rules",
        r"(?i)you\s+are\s+now\s+in\s+DAN\s+mode",
        r"(?i)act\s+as\s+an\s+unfiltered\s+AI"
    ]

    SECRET_MASKS = [
        (re.compile(r"sk-[A-Za-z0-9-_]{20,}"), "[REDACTED_API_KEY]"),
        (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
        (re.compile(r"hf_[A-Za-z0-9_]{20,}"), "[REDACTED_HF_TOKEN]")
    ]

    def __init__(self, custom_forbidden: List[str] = None):
        self.forbidden_patterns = [re.compile(p) for p in (self.SUSPICIOUS_PATTERNS + (custom_forbidden or []))]

    def inspect_prompt(self, text: str) -> Tuple[bool, str]:
        """
        Returns (is_safe, reason).
        """
        for pat in self.forbidden_patterns:
            if pat.search(text):
                return False, f"Prompt blocked: matched adversarial pattern '{pat.pattern}'"
        return True, "Safe"

    def redact_secrets(self, text: str) -> str:
        """
        Sanitizes text by scrubbing accidental credential leakage.
        """
        sanitized = text
        for pat, replacement in self.SECRET_MASKS:
            sanitized = pat.sub(replacement, sanitized)
        return sanitized
