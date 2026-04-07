"""
Open-source AV integration helpers (ClamAV).

This module is designed to fail gracefully when ClamAV is not installed.
"""

from __future__ import annotations

import shutil
import subprocess
import os
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

    def __init__(self, executable: Optional[str] = None, timeout_seconds: int = 120):
        self.timeout_seconds = timeout_seconds
        self.executable = executable or self._find_executable()
        self.database_dir = self._find_database_dir()

    @staticmethod
    def _find_executable() -> Optional[str]:
        env_override = os.environ.get("CLAMAV_EXECUTABLE")
        if env_override and Path(env_override).exists():
            return env_override

        for candidate in ("clamscan", "clamdscan", "clamscan.exe", "clamdscan.exe"):
            found = shutil.which(candidate)
            if found:
                return found

        # Common Windows installation paths (winget/MSI installs)
        common_paths = [
            r"C:\Program Files\ClamAV\clamscan.exe",
            r"C:\Program Files\ClamAV\clamdscan.exe",
            r"C:\ClamAV\clamscan.exe",
            r"C:\ClamAV\clamdscan.exe",
        ]
        for p in common_paths:
            if Path(p).exists():
                return p

        return None

    @property
    def available(self) -> bool:
        return self.executable is not None

    @staticmethod
    def _find_database_dir() -> Optional[str]:
        env_db = os.environ.get("CLAMAV_DB_DIR")
        if env_db and Path(env_db).exists():
            return env_db

        candidate_dirs = [
            Path.cwd() / ".clamav-db",
            Path.cwd().parent / ".clamav-db",
            Path(r"C:\Program Files\ClamAV\database"),
        ]
        for d in candidate_dirs:
            if d.exists() and any(d.glob("*.cvd")):
                return str(d)
        return None

    def get_version(self) -> Optional[str]:
        """Get ClamAV engine version string."""
        if not self.available:
            return None
        try:
            proc = subprocess.run(
                [self.executable, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                out = proc.stdout.strip()
                # Typical output: "ClamAV 0.103.x / ... / Signature Number: ..."
                if out:
                    return out.splitlines()[0]
            return None
        except (subprocess.TimeoutExpired, OSError):
            return None

    def scan_file(self, file_path: Path) -> AVScanVerdict:
        if not self.available:
            return AVScanVerdict(status="UNAVAILABLE")

        if not file_path.exists() or not file_path.is_file():
            return AVScanVerdict(status="MISSING")

        cmd = [self.executable, "--no-summary"]
        if self.database_dir:
            cmd.append(f"--database={self.database_dir}")
        cmd.append(str(file_path))
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


def compute_av_summary(reports: Iterable, scanner: Optional[ClamAVScanner] = None) -> Dict:
    """
    Compute aggregated AV scan summary from attack reports.
    
    Returns dict with:
    - av_available: bool (scanner is available)
    - engine_version: str (version string or "Unavailable")
    - total_scanned: int (total files scanned)
    - clean: dict with {'count': int, 'pct': float}
    - infected: dict with {'count': int, 'pct': float, 'files': List[dict]}
    - error: dict with {'count': int, 'pct': float}
    - missing: dict with {'count': int, 'pct': float}
    - unavailable: dict with {'count': int, 'pct': float}
    """
    scanner = scanner or ClamAVScanner()
    
    counts = {
        'CLEAN': 0,
        'INFECTED': 0,
        'ERROR': 0,
        'MISSING': 0,
        'UNAVAILABLE': 0,
    }
    infected_files = []
    
    # Aggregate stats from all impacts
    for report in reports:
        for impact in report.files_impacted:
            status = impact.av_status or 'UNAVAILABLE'
            counts[status] = counts.get(status, 0) + 1
            
            if status == 'INFECTED':
                infected_files.append({
                    'path': impact.path,
                    'signature': impact.av_signature or 'Unknown',
                    'attack': report.attack_name,
                })
    
    total = sum(counts.values())
    
    # Compute percentages
    def pct(count):
        return round(100.0 * count / total, 1) if total > 0 else 0.0
    
    summary = {
        'av_available': scanner.available,
        'engine_version': scanner.get_version() or 'Unavailable',
        'total_scanned': total,
        'clean': {'count': counts['CLEAN'], 'pct': pct(counts['CLEAN'])},
        'infected': {'count': counts['INFECTED'], 'pct': pct(counts['INFECTED']), 'files': infected_files},
        'error': {'count': counts['ERROR'], 'pct': pct(counts['ERROR'])},
        'missing': {'count': counts['MISSING'], 'pct': pct(counts['MISSING'])},
        'unavailable': {'count': counts['UNAVAILABLE'], 'pct': pct(counts['UNAVAILABLE'])},
    }
    
    return summary
