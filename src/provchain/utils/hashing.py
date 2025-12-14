"""Hash calculation utilities"""

import hashlib
from pathlib import Path


def calculate_sha256(file_path: str | Path) -> str:
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_md5(file_path: str | Path) -> str:
    """Calculate MD5 hash of a file"""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()


def calculate_blake2b(file_path: str | Path) -> str:
    """Calculate BLAKE2b hash of a file"""
    blake2b = hashlib.blake2b()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            blake2b.update(chunk)
    return blake2b.hexdigest()


def calculate_hash(file_path: str | Path, algorithm: str = "sha256") -> str:
    """Calculate hash of a file using specified algorithm"""
    if algorithm.lower() == "sha256":
        return calculate_sha256(file_path)
    elif algorithm.lower() == "md5":
        return calculate_md5(file_path)
    elif algorithm.lower() == "blake2b":
        return calculate_blake2b(file_path)
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

