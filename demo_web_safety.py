"""
Web Safety Checker - Live Demo
================================

Run this script to see the safety checker in action.
"""

from web_safety_checker import WebSafetyChecker, WebSafetyVerdic
from pathlib import Path
import json


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)


def demo_file_download_check():
    """Demo 1: Check if a downloaded file is safe"""
    print_section("DEMO 1: File Download Safety Check")
    
    checker = WebSafetyChecker()
    
    # Create dummy test files
    test_files = [
        ("clean_document.pdf", "A safe PDF document"),
        ("suspicious_archive.exe", "An executable file"),
        ("monthly_report.xlsx", "Excel spreadsheet with macros"),
    ]
    
    print("\nScenario: User downloads files from the internet")
    print("\nFiles to check:")
    
    for filename, description in test_files:
        file_path = Path(filename)
        
        # Check file type risk
        risk_level, risk_reason = checker.check_file_type(file_path)
        
        print(f"\n  📄 {filename}")
        print(f"     Description: {description}")
        print(f"     Risk Level: {risk_level}")
        print(f"     Reason: {risk_reason}")
        
        # Show verdict symbol
        symbols = {
            'SAFE': '✓',
            'WARNING': '⚠',
            'DANGEROUS': '✗'
        }
        print(f"     Status: [{symbols.get(risk_level, '?')}]")


def demo_url_check():
    """Demo 2: Check if URLs are safe"""
    print_section("DEMO 2: URL Safety Check")
    
    checker = WebSafetyChecker()
    
    test_urls = [
        "https://www.google.com",
        "https://github.com/user/project",
        "http://bit.ly/abc123",
        "https://suspicious-domain.xyz/download",
        "ftp://file-server.com/files/",
    ]
    
    print("\nScenario: User clicks links in emails or web pages")
    print("\nURLs to check:")
    
    for url in test_urls:
        verdict = checker.check_url(url)
        badge = checker.get_safety_badge(verdict)
        
        print(f"\n  🔗 {url}")
        print(f"     Status: {badge['text']} ({badge['label']})")
        print(f"     Reason: {verdict.reason}")
        print(f"     Confidence: {badge['confidence']}")
        
        # Show emoji indicator
        emoji = {
            'SAFE': '✓',
            'WARNING': '⚠',
            'DANGEROUS': '✗',
            'UNKNOWN': '?'
        }
        print(f"     Indicator: {emoji.get(verdict.status, '?')}")


def demo_badge_display():
    """Demo 3: How badges look in the web interface"""
    print_section("DEMO 3: Safety Badge Display")
    
    checker = WebSafetyChecker()
    
    # Create different verdict types
    verdicts = [
        WebSafetyVerdic(
            status='SAFE',
            confidence=0.95,
            reason='File passed antivirus scan - safe to open',
            av_status='CLEAN',
            av_signature='',
            timestamp='2026-04-05T14:30:00'
        ),
        WebSafetyVerdic(
            status='WARNING',
            confidence=0.6,
            reason='File modified by attack - could be compromised',
            av_status='NOT_APPLICABLE',
            av_signature='',
            timestamp='2026-04-05T14:30:00'
        ),
        WebSafetyVerdic(
            status='DANGEROUS',
            confidence=1.0,
            reason='Antivirus detected: Trojan.Win32.MALWARE',
            av_status='INFECTED',
            av_signature='Trojan.Win32.MALWARE',
            timestamp='2026-04-05T14:30:00'
        ),
    ]
    
    print("\nHow badges appear in the web interface:\n")
    
    for verdict in verdicts:
        badge = checker.get_safety_badge(verdict)
        
        # ASCII representation
        html = f"""
    ┌─────────────────────────────────────────┐
    │ {badge['icon']} {badge['text']:<30} │
    │ {badge['label']:<37} │
    │                                         │
    │ Reason: {verdict.reason:<20}  │
    │ Confidence: {badge['confidence']:<20} │
    │                                         │
    │ [CSS Class: {badge['css_class']:<18}]│
    │ [Color: {badge['color']:<25}]│
    └─────────────────────────────────────────┘
        """
        print(html)


def demo_whitelist_blacklist():
    """Demo 4: Whitelist and blacklist management"""
    print_section("DEMO 4: Whitelist & Blacklist Management")
    
    checker = WebSafetyChecker()
    
    print("\nScenario: Company wants to trust certain files and block others\n")
    
    # Create test files to demonstrate
    safe_file = Path("trusted_software.exe")
    dangerous_file = Path("known_malware.exe")
    
    print("Step 1: Whitelist a trusted file")
    print(f"  - File: {safe_file.name}")
    print(f"  - Action: checker.whitelist_file('{safe_file}')")
    print(f"  - Result: Future checks of this file will return SAFE instantly")
    
    # Simulate whitelist
    checker.safe_hashes.add("dummy_hash_1")
    
    print("\nStep 2: Blacklist a dangerous file")
    print(f"  - File: {dangerous_file.name}")
    print(f"  - Action: checker.blacklist_file('{dangerous_file}')")
    print(f"  - Result: Future checks will return DANGEROUS instantly")
    
    # Simulate blacklist
    checker.dangerous_hashes.add("dummy_hash_2")
    
    print("\nStep 3: Check files")
    print(f"  - Whitelist check: Would return 'SAFE' (no scan needed)")
    print(f"  - Blacklist check: Would return 'DANGEROUS' (blocked)")
    print(f"  - Unknown file: Would run ClamAV scan")
    
    print("\nBenefits:")
    print("  ✓ Faster checks for known files")
    print("  ✓ Instant blocking of known malware")
    print("  ✓ Reduced scanning overhead")
    print("  ✓ Company policy enforcement")


def demo_file_type_risk():
    """Demo 5: File type risk assessment"""
    print_section("DEMO 5: File Type Risk Assessment")
    
    checker = WebSafetyChecker()
    
    test_files = {
        "Executables": ["setup.exe", "app.bat", "script.ps1"],
        "Documents": ["resume.pdf", "contract.docx", "spreadsheet.xlsx"],
        "Archives": ["backup.zip", "files.7z", "data.rar"],
        "Media": ["photo.jpg", "video.mp4", "music.mp3"],
        "Web": ["index.html", "script.js", "style.css"],
    }
    
    print("\nFile type analysis helps predict risk before scanning:\n")
    
    for category, files in test_files.items():
        print(f"\n{category}:")
        for filename in files:
            file_path = Path(filename)
            risk, reason = checker.check_file_type(file_path)
            
            # Risk emoji
            emoji = {
                'DANGEROUS': '🔴',
                'WARNING': '🟡',
                'SAFE': '🟢'
            }
            
            print(f"  {emoji.get(risk, '⚪')} {filename:<25} [{risk:<10}] {reason}")


def demo_integration_example():
    """Demo 6: Real-world integration example"""
    print_section("DEMO 6: Real-World Integration Example")
    
    print("""
Scenario: User's workplace with the safety checker integrated

STEP 1: User receives email with suspicious attachment
        ├─ Attachment: "invoice.exe"
        ├─ System checks file type
        │  └─ Risk: DANGEROUS (executable file)
        ├─ Badge shown: ✗ DANGEROUS
        └─ Result: File blocked, user cannot open

STEP 2: User downloads legitimate software
        ├─ File: "Chrome_Setup.exe"
        ├─ System checks against whitelist
        │  └─ Found: Google Chrome v123 is trusted
        ├─ Badge shown: ✓ SAFE (from whitelist)
        └─ Result: User can download immediately

STEP 3: User accesses shortened URL in message
        ├─ URL: "bit.ly/something"
        ├─ System checks URL reputation
        │  └─ Status: Shortened URL - destination unclear
        ├─ Badge shown: ⚠ WARNING
        └─ Result: Warning displayed, user decides whether to proceed

STEP 4: User opens document with macros
        ├─ File: "report_2026.xlsx"
        ├─ File type check shows macros
        │  └─ Risk: WARNING
        ├─ Badge shown: ⚠ WARNING (potential macro virus)
        └─ Result: User informed about risk
    """)
    
    print("\nIntegration Benefits:")
    print("  ✓ Protection from malware infections")
    print("  ✓ Real-time safety feedback")
    print("  ✓ User education about file risks")
    print("  ✓ Compliance with security policies")
    print("  ✓ Threat intelligence collection")


def demo_json_output():
    """Demo 7: JSON output for API responses"""
    print_section("DEMO 7: API Response Format (JSON)")
    
    checker = WebSafetyChecker()
    
    # Create example verdict
    verdict = WebSafetyVerdic(
        status='WARNING',
        confidence=0.7,
        reason='File is suspicious - use caution',
        av_status='UNKNOWN',
        av_signature='',
        timestamp='2026-04-05T14:30:00'
    )
    
    badge = checker.get_safety_badge(verdict)
    
    # API response
    api_response = {
        'filename': 'document.zip',
        'status': verdict.status,
        'reason': verdict.reason,
        'confidence': verdict.confidence,
        'av_status': verdict.av_status,
        'badge': badge,
        'can_open': verdict.status in ['SAFE', 'WARNING'],
        'timestamp': verdict.timestamp
    }
    
    print("\nExample JSON Response from /api/check-file-safety:\n")
    print(json.dumps(api_response, indent=2))
    
    print("\nUsage in JavaScript:")
    print("""
    const response = await fetch('/api/check-file-safety', {
        method: 'POST',
        body: formData
    });
    
    const safety = await response.json();
    
    // You can now display:
    // - Badge with icon and color
    // - Reason for the verdict
    // - Confidence level
    // - Whether file can be opened
    """)


def main():
    """Run all demos"""
    
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║              Web Safety Checker - Interactive Demo                        ║
║                                                                            ║
║  This demo shows how to protect users by checking if files and URLs       ║
║  are safe before they open them.                                          ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    demos = [
        ("File Download Safety Check", demo_file_download_check),
        ("URL Safety Check", demo_url_check),
        ("Safety Badge Display", demo_badge_display),
        ("Whitelist & Blacklist", demo_whitelist_blacklist),
        ("File Type Risk Assessment", demo_file_type_risk),
        ("Real-World Integration", demo_integration_example),
        ("API Response Format", demo_json_output),
    ]
    
    for i, (name, demo_func) in enumerate(demos, 1):
        print(f"\n\n[{i}/{len(demos)}]", end=" ")
        demo_func()
    
    print_section("Demo Complete!")
    print("""
Summary:

✓ File downloads can be checked for malware
✓ URLs can be evaluated for reputation
✓ File types can be analyzed for risk
✓ Safety badges provide visual feedback
✓ Whitelist/blacklist speeds up repeated checks
✓ Integrates seamlessly with web applications

Next Steps:
1. Read WEB_SAFETY_INTEGRATION.md for detailed guide
2. Deploy web_safety_checker.py to your system
3. Add web_safety_api.py routes to your FastAPI app
4. Include web_safety_component.html in your dashboard
5. Test with real files and URLs

Good luck! 🛡️
    """)


if __name__ == '__main__':
    main()
