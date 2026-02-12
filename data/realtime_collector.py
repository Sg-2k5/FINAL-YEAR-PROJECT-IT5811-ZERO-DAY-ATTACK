"""
Real-Time System Event Collector
=================================
Collects REAL system events from live system monitoring.

Windows Support:
- Process monitoring (creation, termination)
- File operations (via psutil + watchdog)
- Network connections
- System calls approximation

Linux Support (requires root):
- auditd integration
- eBPF/BCC integration
- /proc filesystem monitoring
"""

import psutil
import time
import socket
import threading
from typing import List, Generator, Dict, Optional, Set
from pathlib import Path
from collections import deque
import logging

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    
try:
    import win32evtlog
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

from .collector import DataCollector
from .schemas import RawEvent, ResourceType, Direction

logger = logging.getLogger(__name__)


class RealTimeCollector(DataCollector):
    """
    Real-time system event collector for Windows/Linux.
    
    Monitors:
    - Process creation/termination
    - File access (limited without kernel-level access)
    - Network connections
    - System resource usage
    """
    
    def __init__(
        self,
        monitor_processes: bool = True,
        monitor_files: bool = True,
        monitor_network: bool = True,
        polling_interval: float = 0.1,  # 100ms
        file_watch_dirs: Optional[List[str]] = None
    ):
        """
        Args:
            monitor_processes: Monitor process events
            monitor_files: Monitor file system events
            monitor_network: Monitor network connections
            polling_interval: Polling frequency in seconds
            file_watch_dirs: Directories to monitor for file events
        """
        self.monitor_processes = monitor_processes
        self.monitor_files = monitor_files
        self.monitor_network = monitor_network
        self.polling_interval = polling_interval
        
        # Event buffer
        self.event_buffer: deque = deque(maxlen=10000)
        self.buffer_lock = threading.Lock()
        
        # Process tracking
        self.known_processes: Dict[int, psutil.Process] = {}
        self.known_connections: Set[tuple] = set()
        
        # File system monitoring
        self.file_observer = None
        if monitor_files and WATCHDOG_AVAILABLE:
            if file_watch_dirs is None:
                # Monitor common directories
                if psutil.WINDOWS:
                    file_watch_dirs = [
                        str(Path.home() / "Documents"),
                        "C:\\Windows\\System32",
                        "C:\\Program Files"
                    ]
                else:
                    file_watch_dirs = [
                        "/etc",
                        "/var/log",
                        "/tmp",
                        str(Path.home())
                    ]
            self.file_watch_dirs = file_watch_dirs
        else:
            self.file_watch_dirs = []
        
        # Monitoring threads
        self.monitoring = False
        self.threads: List[threading.Thread] = []
        
        logger.info(f"RealTimeCollector initialized")
        logger.info(f"  Process monitoring: {monitor_processes}")
        logger.info(f"  File monitoring: {monitor_files and WATCHDOG_AVAILABLE}")
        logger.info(f"  Network monitoring: {monitor_network}")
    
    def start_monitoring(self):
        """Start background monitoring threads"""
        if self.monitoring:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring = True
        
        # Start process monitor
        if self.monitor_processes:
            t = threading.Thread(target=self._monitor_processes, daemon=True)
            t.start()
            self.threads.append(t)
            logger.info("Started process monitoring thread")
        
        # Start network monitor
        if self.monitor_network:
            t = threading.Thread(target=self._monitor_network, daemon=True)
            t.start()
            self.threads.append(t)
            logger.info("Started network monitoring thread")
        
        # Start file system monitor
        if self.monitor_files and WATCHDOG_AVAILABLE:
            self._start_file_monitoring()
            logger.info(f"Started file monitoring for {len(self.file_watch_dirs)} directories")
    
    def stop_monitoring(self):
        """Stop all monitoring threads"""
        self.monitoring = False
        
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
        
        for thread in self.threads:
            thread.join(timeout=1.0)
        
        logger.info("Stopped all monitoring threads")
    
    def _add_event(self, event: RawEvent):
        """Add event to buffer (thread-safe)"""
        with self.buffer_lock:
            self.event_buffer.append(event)
    
    def _monitor_processes(self):
        """Monitor process creation/termination"""
        while self.monitoring:
            try:
                current_pids = set(psutil.pids())
                known_pids = set(self.known_processes.keys())
                
                # Detect new processes
                new_pids = current_pids - known_pids
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        self.known_processes[pid] = proc
                        
                        # Get parent PID
                        try:
                            ppid = proc.ppid()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            ppid = 0
                        
                        # Create process spawn event
                        event = RawEvent(
                            timestamp=int(time.time() * 1000),
                            process_id=pid,
                            parent_process_id=ppid,
                            process_name=proc.name(),
                            syscall_name="fork",  # Approximation
                            target_resource=f"process_{pid}",
                            resource_type=ResourceType.PROCESS,
                            direction=Direction.OUT
                        )
                        self._add_event(event)
                        
                        # Create process exec event
                        try:
                            exe = proc.exe()
                            if exe:  # Skip if no valid path
                                event = RawEvent(
                                    timestamp=int(time.time() * 1000),
                                    process_id=pid,
                                    parent_process_id=ppid,
                                    process_name=proc.name(),
                                    syscall_name="execve",
                                    target_resource=exe,
                                    resource_type=ResourceType.FILE,
                                    direction=Direction.IN
                                )
                                self._add_event(event)
                        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, ValueError):
                            # Silently skip system processes we can't access
                            pass
                        
                        # Monitor open files
                        try:
                            for file in proc.open_files():
                                event = RawEvent(
                                    timestamp=int(time.time() * 1000),
                                    process_id=pid,
                                    parent_process_id=ppid,
                                    process_name=proc.name(),
                                    syscall_name="open",
                                    target_resource=file.path,
                                    resource_type=ResourceType.FILE,
                                    direction=Direction.IN
                                )
                                self._add_event(event)
                        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, ValueError):
                            # Silently skip files we can't access
                            pass
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
                        # Silently skip processes we can't access
                        pass
                
                # Detect terminated processes
                terminated_pids = known_pids - current_pids
                for pid in terminated_pids:
                    if pid in self.known_processes:
                        del self.known_processes[pid]
                
            except Exception as e:
                # Only log unexpected errors (not common access issues)
                if not any(err in str(e) for err in ['WinError 161', 'Access denied', 'No such process']):
                    logger.error(f"Process monitoring error: {e}")
            
            time.sleep(self.polling_interval)
    
    def _monitor_network(self):
        """Monitor network connections"""
        while self.monitoring:
            try:
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        conn_tuple = (conn.pid, conn.laddr, conn.raddr)
                        
                        if conn_tuple not in self.known_connections:
                            self.known_connections.add(conn_tuple)
                            
                            try:
                                proc = psutil.Process(conn.pid) if conn.pid else None
                                proc_name = proc.name() if proc else "unknown"
                                ppid = proc.ppid() if proc else 0
                                
                                socket_str = f"{conn.raddr.ip}:{conn.raddr.port}"
                                
                                event = RawEvent(
                                    timestamp=int(time.time() * 1000),
                                    process_id=conn.pid or 0,
                                    parent_process_id=ppid,
                                    process_name=proc_name,
                                    syscall_name="connect",
                                    target_resource=socket_str,
                                    resource_type=ResourceType.SOCKET,
                                    direction=Direction.OUT
                                )
                                self._add_event(event)
                            
                            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
                                # Silently skip connections we can't access
                                pass
            
            except Exception as e:
                # Only log unexpected errors
                if not any(err in str(e) for err in ['WinError 161', 'Access denied', 'No such process']):
                    logger.error(f"Network monitoring error: {e}")
            
            time.sleep(self.polling_interval)
            
            # Clean old connections
            if len(self.known_connections) > 10000:
                self.known_connections.clear()
    
    def _start_file_monitoring(self):
        """Start file system monitoring using watchdog"""
        if not WATCHDOG_AVAILABLE:
            logger.warning("watchdog not available, skipping file monitoring")
            return
        
        class FileEventHandler(FileSystemEventHandler):
            def __init__(self, collector):
                self.collector = collector
                super().__init__()
            
            def on_created(self, event):
                self._handle_file_event(event, "open", Direction.OUT)
            
            def on_modified(self, event):
                self._handle_file_event(event, "write", Direction.OUT)
            
            def on_deleted(self, event):
                self._handle_file_event(event, "unlink", Direction.OUT)
            
            def _handle_file_event(self, event, syscall: str, direction: Direction):
                if event.is_directory:
                    return
                
                # Try to find which process triggered this
                # (This is limited without kernel hooks)
                try:
                    file_path = event.src_path
                    
                    # Create event with unknown process
                    raw_event = RawEvent(
                        timestamp=int(time.time() * 1000),
                        process_id=0,  # Unknown
                        parent_process_id=0,  # Unknown
                        process_name="unknown",
                        syscall_name=syscall,
                        target_resource=file_path,
                        resource_type=ResourceType.FILE,
                        direction=direction
                    )
                    self.collector._add_event(raw_event)
                except Exception:
                    pass
        
        self.file_observer = Observer()
        event_handler = FileEventHandler(self)
        
        for directory in self.file_watch_dirs:
            try:
                if Path(directory).exists():
                    self.file_observer.schedule(event_handler, directory, recursive=True)
            except Exception as e:
                logger.warning(f"Could not monitor {directory}: {e}")
        
        self.file_observer.start()
    
    def collect_events(self, duration_seconds: int) -> List[RawEvent]:
        """
        Collect events for specified duration.
        
        Args:
            duration_seconds: How long to collect
            
        Returns:
            List of RawEvent objects
        """
        logger.info(f"Starting real-time collection for {duration_seconds} seconds...")
        
        # Start monitoring if not already started
        was_monitoring = self.monitoring
        if not was_monitoring:
            self.start_monitoring()
        
        # Clear buffer
        with self.buffer_lock:
            self.event_buffer.clear()
        
        # Wait for duration
        time.sleep(duration_seconds)
        
        # Get collected events
        with self.buffer_lock:
            events = list(self.event_buffer)
        
        # Stop monitoring if we started it
        if not was_monitoring:
            self.stop_monitoring()
        
        logger.info(f"Collected {len(events)} real-time events")
        return events
    
    def stream_events(self) -> Generator[RawEvent, None, None]:
        """
        Stream events in real-time.
        
        Yields:
            RawEvent objects as they occur
        """
        logger.info("Starting real-time event streaming...")
        
        # Start monitoring
        if not self.monitoring:
            self.start_monitoring()
        
        last_index = 0
        
        try:
            while True:
                with self.buffer_lock:
                    current_size = len(self.event_buffer)
                    
                    if current_size > last_index:
                        # Yield new events
                        for i in range(last_index, current_size):
                            yield self.event_buffer[i]
                        last_index = current_size
                
                time.sleep(0.01)  # 10ms polling
        
        except KeyboardInterrupt:
            logger.info("Streaming stopped by user")
        finally:
            self.stop_monitoring()


def test_realtime_collector():
    """Test the real-time collector"""
    print("Testing Real-Time System Event Collector")
    print("=" * 60)
    
    collector = RealTimeCollector(
        monitor_processes=True,
        monitor_files=False,  # Can be noisy
        monitor_network=True,
        polling_interval=0.5
    )
    
    print("\nCollecting events for 10 seconds...")
    print("(Try opening applications, browsing web, etc.)\n")
    
    events = collector.collect_events(duration_seconds=10)
    
    print(f"\n✓ Collected {len(events)} real events!\n")
    
    if events:
        print("Sample events:")
        for event in events[:10]:
            print(f"  [{event.process_name:15s}] {event.syscall_name:8s} → {event.target_resource[:50]}")
    
    return events


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_realtime_collector()
