#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic whitelist bundler and clean-room verifier for moonbit-agent-guard."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ARCHIVE_ROOT = "moonbit-agent-guard"
WHITELIST_FILES = [
    "moon.mod.json",
    "src/moon.pkg.json",
    "src/guard.mbt",
    "src/guard_test.mbt",
    "README.md",
    "LICENSE",
    "verify_semantics.py",
    "package_release.py",
]
FIXED_ZIP_DT = (2026, 11, 26, 0, 0, 0)
SECRET_PATTERNS = [
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"ghp_[A-Za-z0-9]{36}"),
    re.compile(rb"sk-[A-Za-z0-9]{32,}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


def scan_clean_bytes(rel_name: str, raw: bytes) -> None:
    for idx, b in enumerate(raw):
        if (b < 0x20 and b not in (0x09, 0x0A, 0x0D)) or b == 0x7F:
            raise AssertionError(f"{rel_name}: control byte 0x{b:02x} at offset {idx}")
    if (b"/" + b"Users/") in raw:
        raise AssertionError(f"{rel_name}: contains forbidden local path prefix host-user-dir")
    for pat in SECRET_PATTERNS:
        if pat.search(raw):
            raise AssertionError(f"{rel_name}: matched credential pattern")


def build_deterministic_zip(repo_dir: Path, out_zip: Path) -> str:
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in WHITELIST_FILES:
            src_path = repo_dir / rel
            if not src_path.is_file():
                raise FileNotFoundError(f"Missing whitelisted file: {rel}")
            raw = src_path.read_bytes()
            scan_clean_bytes(rel, raw)
            info = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{rel}", date_time=FIXED_ZIP_DT)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if rel.endswith(".py") else 0o644) << 16
            zf.writestr(info, raw)
    return hashlib.sha256(out_zip.read_bytes()).hexdigest()


def verify_extracted_archive(out_zip: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="moonbit_guard_extract_") as tmp_str:
        tmp_path = Path(tmp_str)
        with zipfile.ZipFile(out_zip, "r") as zf:
            names = zf.namelist()
            expected = [f"{ARCHIVE_ROOT}/{r}" for r in WHITELIST_FILES]
            if names != expected:
                raise AssertionError(f"Archive entries mismatch: {names} != {expected}")
            zf.extractall(tmp_path)

        extracted_repo = tmp_path / ARCHIVE_ROOT
        proc = subprocess.run(
            [sys.executable, str(extracted_repo / "verify_semantics.py"), "--self-test"],
            cwd=extracted_repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"Extracted verify_semantics.py failed:\n{proc.stdout}\n{proc.stderr}"
            )


def run_self_test(output_path: Path) -> int:
    repo_dir = Path(__file__).resolve().parent
    sha_first = build_deterministic_zip(repo_dir, output_path)
    sha_second = build_deterministic_zip(repo_dir, output_path)
    if sha_first != sha_second:
        raise AssertionError(f"Non-idempotent zip build: {sha_first} != {sha_second}")
    verify_extracted_archive(output_path)
    print(
        f"[PASS] {output_path.name} built idempotently (sha256={sha_first[:16]}...) "
        "and passed extracted clean-room self-test."
    )
    return 0


def main() -> int:
    repo_dir = Path(__file__).resolve().parent
    default_out = repo_dir.parent / "moonbit-agent-guard-v0.1.0.zip"
    parser = argparse.ArgumentParser(description="Package moonbit-agent-guard release.")
    parser.add_argument("--output", type=Path, default=default_out, help="Target zip path.")
    parser.add_argument("--self-test", action="store_true", help="Build and run clean-room test.")
    args = parser.parse_args()
    return run_self_test(args.output.resolve())


if __name__ == "__main__":
    sys.exit(main())
