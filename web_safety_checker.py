"""
Web Application Safety Checker
================================

Extends the AV verdict system to scan and rate web content, URLs, and downloads
for safety. Provides real-time indicators (Safe/Warning/Dangerous) when users
access files or download content.

Usage:
    - Scan downloaded files
    - Check URLs against known malware databases
    - Analyze web content/files
    - Display safety badges in web app
"""

import hashlib
import json
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime

from fyp2.src.utils.av_scanner import ClamAVScanner, AVScanVerdict


@dataclass
class WebSafetyVerdic:
    """Safety verdict for web content/file"""
    status: str  # SAFE, WARNING, DANGEROUS, UNKNOWN
    confidence: float  # 0.0 to 1.0
    reason: str  # Why it's safe/unsafe
    av_status: str  # From antivirus
    av_signature: str  # Malware signature if detected
    timestamp: str


class WebSafetyChecker:
    """Checks if web content, URLs, or files are safe"""
    
    def __init__(self):
        self.av_scanner = ClamAVScanner()
        self.safe_hashes = set()  # Whitelisted file hashes
        self.dangerous_hashes = set()  # Known malware hashes
        self.warning_hashes = set()  # Suspicious hashes
        
    def check_file_download(self, file_path: Path) -> WebSafetyVerdic:
        """
        Check if a downloaded file is safe
        
        Returns: SAFE, WARNING, DANGEROUS, or UNKNOWN
        """
        if not file_path.exists():
            return WebSafetyVerdic(
                status='UNKNOWN',
                confidence=0.0,
                reason='File not found',
                av_status='MISSING',
                av_signature='',
                timestamp=datetime.now().isoformat()
            )
        
        # Calculate file hash
        file_hash = self._hash_file(file_path)
        
        # Check against whitelists/blacklists
        if file_hash in self.dangerous_hashes:
            return WebSafetyVerdic(
                status='DANGEROUS',
                confidence=1.0,
                reason='File matches known malware hash',
                av_status='INFECTED',
                av_signature='Known malware',
                timestamp=datetime.now().isoformat()
            )
        
        if file_hash in self.safe_hashes:
            return WebSafetyVerdic(
                status='SAFE',
                confidence=1.0,
                reason='File is whitelisted - verified safe',
                av_status='CLEAN',
                av_signature='',
                timestamp=datetime.now().isoformat()
            )
        
        if file_hash in self.warning_hashes:
            return WebSafetyVerdic(
                status='WARNING',
                confidence=0.7,
                reason='File is suspicious - use caution',
                av_status='UNKNOWN',
                av_signature='',
                timestamp=datetime.now().isoformat()
            )
        
        # Scan with antivirus
        verdict = self.av_scanner.scan_file(file_path)
        
        # Convert AV verdict to safety status
        if verdict.status == 'CLEAN':
            return WebSafetyVerdic(
                status='SAFE',
                confidence=0.95,
                reason='File passed antivirus scan - safe to open',
                av_status='CLEAN',
                av_signature='',
                timestamp=datetime.now().isoformat()
            )
        elif verdict.status == 'INFECTED':
            return WebSafetyVerdic(
                status='DANGEROUS',
                confidence=1.0,
                reason=f'Antivirus detected malware: {verdict.signature}',
                av_status='INFECTED',
                av_signature=verdict.signature,
                timestamp=datetime.now().isoformat()
            )
        elif verdict.status == 'ERROR':
            return WebSafetyVerdic(
                status='WARNING',
                confidence=0.5,
                reason='Could not verify - file may be encrypted or locked',
                av_status='ERROR',
                av_signature='',
                timestamp=datetime.now().isoformat()
            )
        else:
            return WebSafetyVerdic(
                status='UNKNOWN',
                confidence=0.3,
                reason='Could not determine safety status',
                av_status=verdict.status,
                av_signature='',
                timestamp=datetime.now().isoformat()
            )
    
    def check_url(self, url: str) -> WebSafetyVerdic:
        """
        Check if a URL is safe
        
        Note: This would integrate with reputation services
        like Google Safe Browsing, URLhaus, etc.
        """
        # Basic URL validation
        if not url.startswith(('http://', 'https://', 'ftp://')):
            return WebSafetyVerdic(
                status='WARNING',
                confidence=0.4,
                reason='Invalid or unknown protocol',
                av_status='UNKNOWN',
                av_signature='',
                timestamp=datetime.now().isoformat()
            )
        
        # In production, check against:
        # - Google Safe Browsing API
        # - PhishTank
        # - URLhaus
        # - Custom threat intelligence
        
        # For now, dummy implementation
        suspicious_patterns = [
            'bit.ly', 'tinyurl', 'shortened',  # Shortened URLs
            'goo.gl', 'ow.ly',
        ]
        
        if any(pattern in url.lower() for pattern in suspicious_patterns):
            return WebSafetyVerdic(
                status='WARNING',
                confidence=0.6,
                reason='Shortened URL - destination unclear',
                av_status='UNKNOWN',
                av_signature='',
                timestamp=datetime.now().isoformat()
            )
        
        return WebSafetyVerdic(
            status='UNKNOWN',
            confidence=0.5,
            reason='URL reputation check not available',
            av_status='UNAVAILABLE',
            av_signature='',
            timestamp=datetime.now().isoformat()
        )
    
    def check_file_type(self, file_path: Path) -> Tuple[str, str]:
        """
        Check if file type is potentially dangerous
        
        Returns: (risk_level, reason)
        """
        dangerous_extensions = {
            '.exe': 'Executable - can run code',
            '.bat': 'Batch script - can run commands',
            '.cmd': 'Command script - can run commands',
            '.ps1': 'PowerShell script - can run code',
            '.vbs': 'VBScript - can run code',
            '.scr': 'Screensaver - often used for malware',
            '.msi': 'Windows installer - can modify system',
            '.dll': 'System library - could be malicious',
            '.sys': 'System driver - dangerous if compromised',
        }
        
        warning_extensions = {
            '.zip': 'Archive - check contents',
            '.rar': 'Archive - check contents',
            '.7z': 'Archive - check contents',
            '.pdf': 'PDF - has known exploits',
            '.doc': 'Word document - can contain macros',
            '.docx': 'Word document - can contain macros',
            '.xls': 'Excel - can contain macros',
            '.xlsx': 'Excel - can contain macros',
            '.js': 'JavaScript - runs code',
        }
        
        ext = file_path.suffix.lower()
        
        if ext in dangerous_extensions:
            return 'DANGEROUS', dangerous_extensions[ext]
        elif ext in warning_extensions:
            return 'WARNING', warning_extensions[ext]
        else:
            return 'SAFE', 'No known risks for this file type'
    
    def get_safety_badge(self, verdict: WebSafetyVerdic) -> Dict:
        """Get HTML badge/icon for displaying safety status"""
        
        badges = {
            'SAFE': {
                'color': '#28a745',  # Green
                'icon': '✓',
                'text': 'SAFE',
                'label': 'Safe to open',
                'css_class': 'badge-success'
            },
            'WARNING': {
                'color': '#ffc107',  # Amber
                'icon': '⚠',
                'text': 'WARNING',
                'label': 'Verify before opening',
                'css_class': 'badge-warning'
            },
            'DANGEROUS': {
                'color': '#dc3545',  # Red
                'icon': '✗',
                'text': 'DANGEROUS',
                'label': 'Do not open',
                'css_class': 'badge-danger'
            },
            'UNKNOWN': {
                'color': '#6c757d',  # Gray
                'icon': '?',
                'text': 'UNKNOWN',
                'label': 'Status unknown',
                'css_class': 'badge-secondary'
            }
        }
        
        badge = badges.get(verdict.status, badges['UNKNOWN']).copy()
        badge['reason'] = verdict.reason
        badge['confidence'] = f"{int(verdict.confidence * 100)}%"
        
        return badge
    
    @staticmethod
    def _hash_file(file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def whitelist_file(self, file_path: Path):
        """Add file to whitelist (trusted)"""
        file_hash = self._hash_file(file_path)
        self.safe_hashes.add(file_hash)
    
    def blacklist_file(self, file_path: Path):
        """Add file to blacklist (dangerous)"""
        file_hash = self._hash_file(file_path)
        self.dangerous_hashes.add(file_hash)
    
    def flag_suspicious(self, file_path: Path):
        """Mark file as suspicious/warning"""
        file_hash = self._hash_file(file_path)
        self.warning_hashes.add(file_hash)


# ============================================================================
# Integration Examples
# ============================================================================

def example_web_app_integration():
    """Example: How to use in a web application"""
    
    checker = WebSafetyChecker()
    
    # Example 1: Check a downloaded file
    print("\n" + "="*80)
    print("EXAMPLE 1: Check Downloaded File")
    print("="*80)
    
    download_path = Path("C:/Downloads/document.pdf")
    if download_path.exists():
        verdict = checker.check_file_download(download_path)
        badge = checker.get_safety_badge(verdict)
        
        print(f"\nFile: {download_path.name}")
        print(f"Safety Status: {badge['text']} ({badge['label']})")
        print(f"Color: {badge['color']}")
        print(f"Reason: {verdict.reason}")
        print(f"Confidence: {badge['confidence']}")
    
    # Example 2: Check file type risk
    print("\n" + "="*80)
    print("EXAMPLE 2: File Type Risk Assessment")
    print("="*80)
    
    test_files = [
        Path("document.pdf"),
        Path("script.exe"),
        Path("archive.zip"),
        Path("image.jpg"),
        Path("presentation.pptx"),
    ]
    
    print("\nFile Type Risk Assessment:")
    for file in test_files:
        risk, reason = checker.check_file_type(file)
        print(f"  {file.name:<25} [{risk:<10}] {reason}")
    
    # Example 3: Check URL safety
    print("\n" + "="*80)
    print("EXAMPLE 3: URL Safety Check")
    print("="*80)
    
    test_urls = [
        "https://www.google.com",
        "http://bit.ly/abc123",
        "https://github.com/user/repo",
        "ftp://suspicious-server.com/file.exe",
    ]
    
    print("\nURL Safety Check:")
    for url in test_urls:
        verdict = checker.check_url(url)
        badge = checker.get_safety_badge(verdict)
        print(f"  {url:<40} [{badge['text']:<10}] {verdict.reason}")
    
    # Example 4: HTML Badge Display
    print("\n" + "="*80)
    print("EXAMPLE 4: HTML Badge for Web Display")
    print("="*80)
    
    # Create a safe badge
    test_result = WebSafetyVerdic(
        status='SAFE',
        confidence=0.95,
        reason='File passed antivirus scan',
        av_status='CLEAN',
        av_signature='',
        timestamp=datetime.now().isoformat()
    )
    
    badge = checker.get_safety_badge(test_result)
    
    html = f"""
    <div class="file-check-result">
        <div class="badge {badge['css_class']}">
            <span class="icon">{badge['icon']}</span>
            <span class="text">{badge['text']}</span>
        </div>
        <p class="label">{badge['label']}</p>
        <p class="reason">{badge['reason']}</p>
        <p class="confidence">Confidence: {badge['confidence']}</p>
    </div>
    """
    
    print("\nGenerated HTML:")
    print(html)


if __name__ == '__main__':
    example_web_app_integration()
