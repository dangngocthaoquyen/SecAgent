"""Deterministic preview filtering, not an artifact store or a general DLP service."""
import hashlib
import re


class Redactor:
    _PRESERVED_MARKER_RE = re.compile(
        r"(\[(?:CANARY_SHA256|ID_SHA256):[a-f0-9]{64}\]|\[URL_REDACTED:[a-f0-9]{16}\]|\[(?:CREDENTIAL_REDACTED|TOKEN_REDACTED|OPAQUE_REDACTED|REDACTED)\])"
    )

    def __init__(self, values=()):
        if any(not isinstance(value, str) for value in values):
            raise ValueError("Redaction values must be strings.")
        self.values = sorted({v for v in values if v}, key=len, reverse=True)
        self._secret_pattern = (
            re.compile("|".join(re.escape(v) for v in self.values))
            if self.values
            else None
        )

    def redact_secrets_only(self, value: str) -> str:
        """Replace configured secrets in a single pass without corrupting redaction markers."""
        if not self._secret_pattern or not value:
            return value
        parts = self._PRESERVED_MARKER_RE.split(value)
        for index in range(0, len(parts), 2):
            if parts[index]:
                parts[index] = self._secret_pattern.sub("[REDACTED]", parts[index])
        return "".join(parts)

    def clean(self, value, *, limit=4096, opaque=True):
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Expected report text.")
        value = re.sub(r'https?://[^\s"<>]+', lambda m:
            "[URL_REDACTED:" + hashlib.sha256(m[0].encode()).hexdigest()[:16] + "]", value)
        # Labeled canaries are sensitive even in dotted evidence references.
        value = re.sub(r"(?i)canary[-_][A-Za-z0-9_-]+", lambda m:
            "[CANARY_SHA256:" + hashlib.sha256(m[0].encode()).hexdigest() + "]", value)
        if self._secret_pattern is not None:
            value = self.redact_secrets_only(value)
        parts = self._PRESERVED_MARKER_RE.split(value)
        for index in range(0, len(parts), 2):
            seg = parts[index]
            if not seg:
                continue
            seg = re.sub(r"\bsk-[A-Za-z0-9_-]+", "[CREDENTIAL_REDACTED]", seg)
            seg = re.sub(r"(?i)\bBearer\s+[^\s\"<>]+", "Bearer [REDACTED]", seg)
            seg = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[TOKEN_REDACTED]", seg)
            seg = re.sub(
                r'''(?ix)(\b(?:api[_-]?key|password|secret|access[_-]?token|canary|authorization)\b["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;<>"']+)''',
                lambda m: m[1] + "[REDACTED]",
                seg,
            )
            if opaque:
                seg = re.sub(r"\b[a-fA-F0-9]{24,}\b", "[OPAQUE_REDACTED]", seg)
            parts[index] = seg
        return "".join(parts)[:limit]

    def identifier(self, value, *, limit=4096):
        """Stable aliases retain correlation without copying opaque identifier tokens."""
        if value is None:
            return None
        value = self.clean(value, limit=1024 * 1024, opaque=False)
        # Do not rehash the digest inside an already sanitized marker.
        parts = re.split(r"(\[(?:CANARY_SHA256|ID_SHA256):[a-f0-9]{64}\]|\[URL_REDACTED:[a-f0-9]{16}\])", value)
        for index in range(0, len(parts), 2):
            parts[index] = re.sub(r"\b[a-fA-F0-9]{24,}\b", lambda m:
                "[ID_SHA256:" + hashlib.sha256(m[0].encode()).hexdigest() + "]", parts[index])
        return "".join(parts)[:limit]
