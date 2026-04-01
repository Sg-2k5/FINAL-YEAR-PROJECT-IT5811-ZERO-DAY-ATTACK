"""
Open-source AV integration helpers (ClamAV).

This module is designed to fail gracefully when ClamAV is not installed.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


@dataclass
class AVScanVerdict:
    status: str
    signature: str = ""
    engine: str = "ClamAV"
    raw_output: str = ""


class ClamAVScanner:
    """Wrapper around clamscan/clamdscan command line tools."""

    def __init__(self, executable: Optional[str] = None, timeout_seconds: int = 15):
        self.timeout_seconds = timeout_seconds
        self.executable = executable or self._find_executable()

    @staticmethod
    def _find_executable() -> Optional[str]:
        for candidate in ("clamscan", "clamdscan", "clamscan.exe", "clamdscan.exe"):
            found = shutil.which(candidate)
            if found:
                return found
        return None

    @property
    def available(self) -> bool:
        return self.executable is not None

    def scan_file(self, file_path: Path) -> AVScanVerdict:
        if not self.available:
            return AVScanVerdict(status="UNAVAILABLE")

        if not file_path.exists() or not file_path.is_file():
            return AVScanVerdict(status="MISSING")

        cmd = [self.executable, "--no-summary", str(file_path)]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return AVScanVerdict(status="ERROR", raw_output="timeout")
        except OSError as exc:
            return AVScanVerdict(status="ERROR", raw_output=str(exc))

        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        combined = "\n".join([s for s in (out, err) if s])

        # Typical output: "C:\path\file: OK" or "...: Signature.Name FOUND"
        for line in combined.splitlines():
            if ":" not in line:
                continue
            _, remainder = line.split(":", 1)
            remainder = remainder.strip()
            if remainder.endswith(" FOUND"):
                signature = remainder[: -len(" FOUND")].strip()
                return AVScanVerdict(status="INFECTED", signature=signature, raw_output=combined)
            if remainder == "OK":
                return AVScanVerdict(status="CLEAN", raw_output=combined)

        if proc.returncode == 0:
            return AVScanVerdict(status="CLEAN", raw_output=combined)
        if proc.returncode == 1:
            return AVScanVerdict(status="INFECTED", raw_output=combined)
        return AVScanVerdict(status="ERROR", raw_output=combined)


def annotate_attack_reports_with_av(reports: Iterable, sandbox_path: Path, scanner: Optional[ClamAVScanner] = None):
    """Mutates FileImpact records in each report with AV scan verdict fields."""
    scanner = scanner or ClamAVScanner()

    cache: Dict[str, AVScanVerdict] = {}

    for report in reports:
        for impact in report.files_impacted:
            if not impact.existed_after:
                impact.av_engine = "ClamAV"
                impact.av_status = "MISSING"
                impact.av_signature = ""
                continue

            rel = impact.path
            if rel not in cache:
                cache[rel] = scanner.scan_file(Path(sandbox_path) / rel)

            verdict = cache[rel]
            impact.av_engine = verdict.engine
            impact.av_status = verdict.status
            impact.av_signature = verdict.signature
