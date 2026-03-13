"""
Data Collector Module
=====================
Collects system events for behavior analysis.

Supports:
- Simulated data (for demo/testing)
- Real auditd logs (Linux production)
"""

import random
import time
from typing import List, Generator, Optional
from abc import ABC, abstractmethod

from .schemas import RawEvent, ResourceType, Direction, MANDATORY_SYSCALLS


class DataCollector(ABC):
    """Abstract base class for data collection"""
    
    @abstractmethod
    def collect_events(self, duration_seconds: int) -> List[RawEvent]:
        """Collect events for specified duration"""
        pass
    
    @abstractmethod
    def stream_events(self) -> Generator[RawEvent, None, None]:
        """Stream events in real-time"""
        pass


class SimulatedCollector(DataCollector):
    """
    Simulates system events for demo and testing.
    
    Generates realistic-looking events based on common patterns.
    """
    
    def __init__(self, events_per_second: int = 50):
        self.events_per_second = events_per_second
        
        # Common process names
        self.processes = [
            "bash", "python", "node", "java", "nginx", "apache2",
            "mysql", "postgres", "redis", "docker", "systemd",
            "cron", "sshd", "curl", "wget", "cat", "grep", "ls"
        ]
        
        # Common file paths
        self.files = [
            "/etc/passwd", "/etc/shadow", "/var/log/syslog",
            "/tmp/data.txt", "/home/user/document.pdf",
            "/var/www/html/index.html", "/etc/nginx/nginx.conf",
            "/usr/bin/python", "/bin/bash", "/etc/crontab"
        ]
        
        # Common network targets
        self.sockets = [
            "192.168.1.1:80", "10.0.0.1:443", "8.8.8.8:53",
            "localhost:3306", "127.0.0.1:6379", "0.0.0.0:22"
        ]
        
        self.syscalls = list(MANDATORY_SYSCALLS)
        self._pid_counter = 1000
    
    def _generate_event(self) -> RawEvent:
        """Generate a single random event"""
        syscall = random.choice(self.syscalls)
        
        # Determine resource type based on syscall
        if syscall in ["connect", "accept"]:
            resource_type = ResourceType.SOCKET
            target = random.choice(self.sockets)
        elif syscall in ["execve", "fork"]:
            resource_type = ResourceType.PROCESS
            target = random.choice(self.processes)
        else:
            resource_type = ResourceType.FILE
            target = random.choice(self.files)
        
        # Determine direction
        if syscall in ["read", "accept"]:
            direction = Direction.IN
        else:
            direction = Direction.OUT
        
        return RawEvent(
            timestamp=int(time.time() * 1000),
            process_id=random.randint(1000, 9999),
            parent_process_id=random.randint(1, 999),
            process_name=random.choice(self.processes),
            syscall_name=syscall,
            target_resource=target,
            resource_type=resource_type,
            direction=direction
        )
    
    def collect_events(self, duration_seconds: int) -> List[RawEvent]:
        """Collect events for specified duration"""
        events = []
        total_events = self.events_per_second * duration_seconds
        
        base_time = int(time.time() * 1000)
        
        for i in range(total_events):
            event = self._generate_event()
            # Spread timestamps across the duration
            event.timestamp = base_time + int((i / total_events) * duration_seconds * 1000)
            events.append(event)
        
        return events
    
    def stream_events(self) -> Generator[RawEvent, None, None]:
        """Stream events continuously"""
        while True:
            yield self._generate_event()
            time.sleep(1.0 / self.events_per_second)


class AttackSimulator(DataCollector):
    """
    Simulates attack patterns for testing detection capabilities.
    
    NOTE: Used for EVALUATION only, never for training!
    """
    
    def __init__(self):
        self.normal_collector = SimulatedCollector(events_per_second=30)
    
    def generate_reverse_shell_attack(self) -> List[RawEvent]:
        """Generate events mimicking a reverse shell attack"""
        events = []
        base_time = int(time.time() * 1000)
        
        # Stage 1: Suspicious process execution
        events.append(RawEvent(
            timestamp=base_time,
            process_id=5001,
            parent_process_id=1000,
            process_name="apache2",
            syscall_name="execve",
            target_resource="/bin/bash",
            resource_type=ResourceType.PROCESS,
            direction=Direction.OUT
        ))
        
        # Stage 2: Spawning shell
        events.append(RawEvent(
            timestamp=base_time + 100,
            process_id=5001,
            parent_process_id=1000,
            process_name="apache2",
            syscall_name="fork",
            target_resource="bash",
            resource_type=ResourceType.PROCESS,
            direction=Direction.OUT
        ))
        
        # Stage 3: Network connection to attacker
        events.append(RawEvent(
            timestamp=base_time + 200,
            process_id=5002,
            parent_process_id=5001,
            process_name="bash",
            syscall_name="connect",
            target_resource="evil.attacker.com:4444",
            resource_type=ResourceType.SOCKET,
            direction=Direction.OUT
        ))
        
        # Stage 4: Reading sensitive files
        for i, filepath in enumerate(["/etc/passwd", "/etc/shadow"]):
            events.append(RawEvent(
                timestamp=base_time + 300 + i * 100,
                process_id=5002,
                parent_process_id=5001,
                process_name="bash",
                syscall_name="read",
                target_resource=filepath,
                resource_type=ResourceType.FILE,
                direction=Direction.IN
            ))
        
        return events
    
    def generate_data_exfiltration_attack(self) -> List[RawEvent]:
        """Generate events mimicking data exfiltration"""
        events = []
        base_time = int(time.time() * 1000)
        
        # Read many sensitive files
        sensitive_files = [
            "/etc/passwd", "/home/user/.ssh/id_rsa",
            "/var/lib/mysql/data.db", "/etc/shadow"
        ]
        
        for i, filepath in enumerate(sensitive_files):
            events.append(RawEvent(
                timestamp=base_time + i * 50,
                process_id=6001,
                parent_process_id=1000,
                process_name="python",
                syscall_name="read",
                target_resource=filepath,
                resource_type=ResourceType.FILE,
                direction=Direction.IN
            ))
        
        # Send data over network
        events.append(RawEvent(
            timestamp=base_time + 500,
            process_id=6001,
            parent_process_id=1000,
            process_name="python",
            syscall_name="connect",
            target_resource="external.server.com:443",
            resource_type=ResourceType.SOCKET,
            direction=Direction.OUT
        ))
        
        events.append(RawEvent(
            timestamp=base_time + 600,
            process_id=6001,
            parent_process_id=1000,
            process_name="python",
            syscall_name="write",
            target_resource="external.server.com:443",
            resource_type=ResourceType.SOCKET,
            direction=Direction.OUT
        ))
        
        return events
    
    def collect_events(self, duration_seconds: int) -> List[RawEvent]:
        """Collect mixed normal + attack events"""
        # Get normal events
        normal_events = self.normal_collector.collect_events(duration_seconds)
        
        # Inject attack events
        attack_events = self.generate_reverse_shell_attack()
        
        # Mix them together
        all_events = normal_events + attack_events
        all_events.sort(key=lambda e: e.timestamp)
        
        return all_events
    
    def stream_events(self):
        """Stream events (delegates to normal collector)"""
        return self.normal_collector.stream_events()


def create_collector(mode: str = "simulated") -> DataCollector:
    """Factory function to create appropriate collector"""
    if mode == "simulated":
        return SimulatedCollector()
    elif mode == "attack":
        return AttackSimulator()
    else:
        return SimulatedCollector()
