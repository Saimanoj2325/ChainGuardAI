"""Upload validation. The client filename is only ever used as display metadata, never for paths."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .errors import APIError

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str | None) -> str:
    """Display-safe basename: strips directories (/ and \\), control chars and unsafe chars; max 100 chars."""
    base = (name or "").replace("\\", "/").split("/")[-1]
    base = _SAFE.sub("_", base).strip("._") or "contract.sol"
    if not base.lower().endswith(".sol"):
        base = (base[:96] if base else "contract") + ".sol"
    if len(base) > 100:
        base = base[:96] + ".sol"
    return base


@dataclass
class ValidatedUpload:
    filename: str        # sanitized display name
    source: str          # decoded text
    raw: bytes
    sha256: str
    size_bytes: int


def validate_upload(filename: str | None, raw: bytes, max_bytes: int) -> ValidatedUpload:
    if not filename or not filename.strip():
        raise APIError(400, "invalid_filename", "A filename ending in .sol is required.")
    if "\x00" in filename:
        raise APIError(400, "invalid_filename", "Filename contains NUL bytes.")
    base = filename.replace("\\", "/").split("/")[-1]
    if not base.lower().endswith(".sol") or base.lower() == ".sol":
        raise APIError(400, "invalid_file_type", "Only Solidity source files (.sol) are accepted.")
    if len(raw) > max_bytes:
        raise APIError(413, "payload_too_large", f"File exceeds the {max_bytes}-byte limit.")
    if len(raw) == 0:
        raise APIError(400, "empty_file", "The uploaded file is empty.")
    if b"\x00" in raw:
        raise APIError(400, "invalid_content", "File contains NUL bytes; Solidity source must be text.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise APIError(400, "invalid_encoding", f"File is not valid UTF-8 (byte offset {e.start}).") from None
    if text.startswith("\ufeff"):
        text = text[1:]
    if not text.strip():
        raise APIError(400, "empty_file", "The uploaded file contains only whitespace.")
    return ValidatedUpload(sanitize_filename(filename), text, raw, hashlib.sha256(raw).hexdigest(), len(raw))
