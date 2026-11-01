"""Forensic integrity hashing utilities."""

import hashlib
from pathlib import Path


def compute_sha256(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 hash of a file using chunked streaming.
    
    Safe for multi-gigabyte forensic artifacts.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw byte data."""
    return hashlib.sha256(data).hexdigest()
