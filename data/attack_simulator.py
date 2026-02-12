"""
Enhanced Attack Simulator
=========================
Generates more distinctive attack patterns for better detection.
"""

import random
import time
from typing import List

from .schemas import RawEvent, ResourceType, Direction


class EnhancedAttackSimulator:
    """
    Generates attack patterns that are clearly distinguishable from normal behavior.
    
    Attack characteristics that differ from normal:
    - Unusual process-to-file access patterns (e.g., web server reading /etc/shadow)
    - Rapid sequential access to multiple sensitive files
    - Network connections to unknown/unusual ports
    - Privilege escalation attempts
    - Unusual process chains (web server spawning shells)
    """
    
    def __init__(self):
        # Sensitive files that are rarely accessed
        self.sensitive_files = [
            "/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa",
            "/home/admin/.bash_history", "/var/log/auth.log",
            "/etc/sudoers", "/proc/self/environ", "/var/lib/mysql/users.db",
            "/etc/ssl/private/key.pem", "/root/.bashrc"
        ]
        
        # Suspicious network targets
        self.suspicious_sockets = [
            "185.143.172.3:4444",  # Known C2 port
            "45.33.32.156:31337",  # Suspicious port
            "198.51.100.1:6666",   # Unusual port
            "evil.c2server.net:8080",
            "malware.download.com:443"
        ]
        
        # Processes that shouldn't be doing certain things
        self.attack_processes = [
            "apache2", "nginx", "mysql", "postgres",  # Web/DB shouldn't shell out
            "www-data", "nobody", "httpd"  # Low-priv users
        ]
        
        # Normal processes for mixing
        self.normal_processes = [
            "systemd", "cron", "bash", "python", "node"
        ]
    
    def _generate_normal_background(self, count: int = 200) -> List[RawEvent]:
        """Generate some normal background events to mix with attack"""
        events = []
        base_time = int(time.time() * 1000)
        
        normal_files = ["/var/log/syslog", "/tmp/data.txt", "/home/user/doc.txt"]
        normal_sockets = ["localhost:80", "127.0.0.1:3306"]
        syscalls = ["read", "write", "open"]
        
        for i in range(count):
            events.append(RawEvent(
                timestamp=base_time + random.randint(0, 5000),
                process_id=random.randint(1000, 2000),
                parent_process_id=random.randint(1, 100),
                process_name=random.choice(self.normal_processes),
                syscall_name=random.choice(syscalls),
                target_resource=random.choice(normal_files),
                resource_type=ResourceType.FILE,
                direction=random.choice([Direction.IN, Direction.OUT])
            ))
        
        return events

    def generate_reverse_shell_attack(self) -> List[RawEvent]:
        """
        Generate reverse shell attack pattern.
        
        Pattern: Web server unexpectedly spawns shell → connects to C2 → reads sensitive files
        This creates unusual edges in the graph that shouldn't exist.
        """
        events = []
        base_time = int(time.time() * 1000)
        
        # Add some normal background
        events.extend(self._generate_normal_background(300))
        
        # ATTACK: Web server spawning shell (UNUSUAL!)
        attacker_process = "apache2"
        
        # Stage 1: Apache executes bash multiple times (very unusual!)
        for i in range(15):
            events.append(RawEvent(
                timestamp=base_time + 1000 + i * 10,
                process_id=7001,
                parent_process_id=1,
                process_name=attacker_process,
                syscall_name="execve",
                target_resource="/bin/bash",
                resource_type=ResourceType.PROCESS,
                direction=Direction.OUT
            ))
            events.append(RawEvent(
                timestamp=base_time + 1000 + i * 10 + 5,
                process_id=7001,
                parent_process_id=1,
                process_name=attacker_process,
                syscall_name="fork",
                target_resource="bash",
                resource_type=ResourceType.PROCESS,
                direction=Direction.OUT
            ))
        
        # Stage 2: Connect to multiple C2 servers (unusual outbound from apache!)
        for i, socket in enumerate(self.suspicious_sockets * 3):
            events.append(RawEvent(
                timestamp=base_time + 2000 + i * 10,
                process_id=7002,
                parent_process_id=7001,
                process_name="bash",
                syscall_name="connect",
                target_resource=socket,
                resource_type=ResourceType.SOCKET,
                direction=Direction.OUT
            ))
        
        # Stage 3: Bash reading MANY sensitive files (unusual for shell spawned by web server)
        for i, filepath in enumerate(self.sensitive_files * 4):
            events.append(RawEvent(
                timestamp=base_time + 3000 + i * 5,
                process_id=7002,
                parent_process_id=7001,
                process_name="bash",
                syscall_name="read",
                target_resource=filepath,
                resource_type=ResourceType.FILE,
                direction=Direction.IN
            ))
        
        # Stage 4: Exfiltrate - lots of writes to suspicious sockets
        for i in range(20):
            events.append(RawEvent(
                timestamp=base_time + 4000 + i * 10,
                process_id=7002,
                parent_process_id=7001,
                process_name="bash",
                syscall_name="write",
                target_resource=random.choice(self.suspicious_sockets),
                resource_type=ResourceType.SOCKET,
                direction=Direction.OUT
            ))
        
        return events
    
    def generate_privilege_escalation_attack(self) -> List[RawEvent]:
        """Generate privilege escalation attack pattern"""
        events = []
        base_time = int(time.time() * 1000)
        
        # Add normal background
        events.extend(self._generate_normal_background(250))
        
        # ATTACK: www-data trying to escalate
        # Stage 1: Read sudoers and other priv files
        for i in range(20):
            events.append(RawEvent(
                timestamp=base_time + 1000 + i * 10,
                process_id=8001,
                parent_process_id=1,
                process_name="www-data",
                syscall_name="read",
                target_resource=random.choice(["/etc/sudoers", "/etc/passwd", "/etc/shadow"]),
                resource_type=ResourceType.FILE,
                direction=Direction.IN
            ))
        
        # Stage 2: Multiple setuid attempts
        for i in range(25):
            events.append(RawEvent(
                timestamp=base_time + 2000 + i * 10,
                process_id=8001,
                parent_process_id=1,
                process_name="www-data",
                syscall_name="setuid",
                target_resource="root",
                resource_type=ResourceType.PROCESS,
                direction=Direction.OUT
            ))
        
        # Stage 3: Execute sudo/su
        for i in range(15):
            events.append(RawEvent(
                timestamp=base_time + 3000 + i * 10,
                process_id=8001,
                parent_process_id=1,
                process_name="www-data",
                syscall_name="execve",
                target_resource=random.choice(["/usr/bin/sudo", "/bin/su", "/usr/bin/pkexec"]),
                resource_type=ResourceType.PROCESS,
                direction=Direction.OUT
            ))
        
        # Stage 4: Now as root, access everything
        for i, filepath in enumerate(self.sensitive_files * 3):
            events.append(RawEvent(
                timestamp=base_time + 4000 + i * 5,
                process_id=8002,
                parent_process_id=8001,
                process_name="root",
                syscall_name="read",
                target_resource=filepath,
                resource_type=ResourceType.FILE,
                direction=Direction.IN
            ))
        
        return events
    
    def generate_data_exfiltration_attack(self) -> List[RawEvent]:
        """Generate data exfiltration pattern"""
        events = []
        base_time = int(time.time() * 1000)
        
        # Add normal background
        events.extend(self._generate_normal_background(200))
        
        # ATTACK: Mass file reading then network exfil
        # Stage 1: Read LOTS of sensitive files
        for i in range(50):
            events.append(RawEvent(
                timestamp=base_time + 1000 + i * 5,
                process_id=9001,
                parent_process_id=1000,
                process_name="python",
                syscall_name="read",
                target_resource=random.choice(self.sensitive_files),
                resource_type=ResourceType.FILE,
                direction=Direction.IN
            ))
        
        # Stage 2: Compress (exec tar/gzip)
        for i in range(10):
            events.append(RawEvent(
                timestamp=base_time + 2000 + i * 10,
                process_id=9001,
                parent_process_id=1000,
                process_name="python",
                syscall_name="execve",
                target_resource=random.choice(["/usr/bin/tar", "/usr/bin/gzip", "/usr/bin/zip"]),
                resource_type=ResourceType.PROCESS,
                direction=Direction.OUT
            ))
        
        # Stage 3: Connect to external server
        for i in range(10):
            events.append(RawEvent(
                timestamp=base_time + 2500 + i * 10,
                process_id=9001,
                parent_process_id=1000,
                process_name="python",
                syscall_name="connect",
                target_resource=random.choice(self.suspicious_sockets),
                resource_type=ResourceType.SOCKET,
                direction=Direction.OUT
            ))
        
        # Stage 4: Write lots of data to network
        for i in range(40):
            events.append(RawEvent(
                timestamp=base_time + 3000 + i * 10,
                process_id=9001,
                parent_process_id=1000,
                process_name="python",
                syscall_name="write",
                target_resource=random.choice(self.suspicious_sockets),
                resource_type=ResourceType.SOCKET,
                direction=Direction.OUT
            ))
        
        return events
    
    def generate_all_attacks(self) -> List[RawEvent]:
        """Generate all attack types combined"""
        all_events = []
        all_events.extend(self.generate_reverse_shell_attack())
        all_events.extend(self.generate_privilege_escalation_attack())
        all_events.extend(self.generate_data_exfiltration_attack())
        
        # Sort by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        return all_events
