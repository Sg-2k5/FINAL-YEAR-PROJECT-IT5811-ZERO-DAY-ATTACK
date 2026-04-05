# Web Application Safety Checker - Integration Guide

## Overview

This guide shows you how to integrate real-time **safety indicators** into your web application. When users open or download anything, you can instantly show whether it's **Safe ✓**, **Warning ⚠**, or **Dangerous ✗**.

---

## Architecture

```
User Downloads File
       ↓
Web Application
       ↓
Safety Checker API
       ↓
1. File Hash Check (whitelist/blacklist)
2. Antivirus Scan (ClamAV)
3. File Type Analysis
       ↓
Safety Status (SAFE / WARNING / DANGEROUS / UNKNOWN)
       ↓
Display Badge to User
```

---

## Quick Start

### 1. **Basic Usage in Python**

```python
from web_safety_checker import WebSafetyChecker
from pathlib import Path

# Create checker instance
checker = WebSafetyChecker()

# Check a downloaded file
file_path = Path("C:/Downloads/document.pdf")
verdict = checker.check_file_download(file_path)

# Get badge for display
badge = checker.get_safety_badge(verdict)

print(f"Status: {badge['text']}")       # Output: SAFE, WARNING, DANGEROUS, UNKNOWN
print(f"Reason: {verdict.reason}")      # Output: File passed antivirus scan...
print(f"Confidence: {badge['confidence']}")  # Output: 95%
```

### 2. **Web API Integration**

Include the FastAPI endpoints from `web_safety_api.py`:

```python
# Routes available:
GET  /api/check-url-safety/{url}      # Check if URL is safe
POST /api/check-file-safety           # Check if file is safe
```

### 3. **HTML/JavaScript Integration**

Use the component from `web_safety_component.html`:

```html
<!-- Import the safety checker component -->
<link rel="stylesheet" href="/static/web_safety.css">
<script src="/static/web_safety.js"></script>

<!-- Add to your dashboard/page -->
<div id="safety-checker"></div>
```

---

## Safety Status Options

| Status | Icon | Color | Meaning | Action |
|--------|------|-------|---------|--------|
| **SAFE** | ✓ | 🟢 Green | File is verified safe | Safe to open |
| **WARNING** | ⚠ | 🟡 Amber | File is suspicious | Ask user to verify |
| **DANGEROUS** | ✗ | 🔴 Red | File is malware | Block download |
| **UNKNOWN** | ? | ⚪ Gray | Status unclear | Limit functionality |

---

## Detailed Implementation Examples

### Example 1: File Download Check

**JavaScript (Frontend)**:

```javascript
// When user clicks download button
document.getElementById('downloadBtn').addEventListener('click', async (e) => {
    e.preventDefault();
    
    const file = document.getElementById('fileInput').files[0];
    if (!file) return;
    
    // Create form data
    const formData = new FormData();
    formData.append('file', file);
    
    // Check safety
    const response = await fetch('/api/check-file-safety', {
        method: 'POST',
        body: formData
    });
    
    const safety = await response.json();
    
    // Show badge
    showSafetyBadge(safety.status, safety.reason);
    
    // Allow download only if safe or warning
    if (safety.can_open) {
        // Proceed with download
        downloadFile(file);
    } else {
        // Block download
        alert('⚠️ This file may be dangerous and was blocked');
    }
});

function showSafetyBadge(status, reason) {
    const colors = {
        'SAFE': '#28a745',
        'WARNING': '#ffc107',
        'DANGEROUS': '#dc3545',
        'UNKNOWN': '#6c757d'
    };
    
    const badge = document.getElementById('badge');
    badge.style.backgroundColor = colors[status];
    badge.textContent = `${status}: ${reason}`;
    badge.style.display = 'block';
}
```

**Python (Backend - FastAPI)**:

```python
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from web_safety_checker import WebSafetyChecker
from pathlib import Path

app = FastAPI()
checker = WebSafetyChecker()

@app.post("/api/check-file-safety")
async def check_file_safety(file: UploadFile = File(...)):
    # Save file temporarily
    temp_path = Path(f"/tmp/{file.filename}")
    content = await file.read()
    temp_path.write_bytes(content)
    
    # Check safety
    verdict = checker.check_file_download(temp_path)
    badge = checker.get_safety_badge(verdict)
    
    # Return result
    return {
        'filename': file.filename,
        'status': verdict.status,
        'reason': verdict.reason,
        'confidence': verdict.confidence,
        'badge': badge,
        'can_open': verdict.status in ['SAFE', 'WARNING']
    }
```

---

### Example 2: URL Safety Check Before Navigation

**JavaScript**:

```javascript
// Before navigating to a link
document.querySelectorAll('a[data-check-safety]').forEach(link => {
    link.addEventListener('click', async (e) => {
        e.preventDefault();
        const url = link.href;
        
        // Check URL safety
        const response = await fetch(`/api/check-url-safety/${encodeURIComponent(url)}`);
        const safety = await response.json();
        
        // Show confirmation based on safety
        if (safety.status === 'SAFE') {
            // Go directly
            window.location.href = url;
        } else if (safety.status === 'WARNING') {
            // Ask user
            const proceed = confirm(`⚠️ Warning: ${safety.reason}\n\nProceed anyway?`);
            if (proceed) window.location.href = url;
        } else if (safety.status === 'DANGEROUS') {
            // Block
            alert('🚫 This URL is blocked due to security concerns');
        }
    });
});
```

---

### Example 3: Real-Time File Type Analysis

**Python**:

```python
from web_safety_checker import WebSafetyChecker
from pathlib import Path

checker = WebSafetyChecker()

# Check file type risk
file_path = Path("contract.exe")
risk_level, reason = checker.check_file_type(file_path)

# Different handling based on file type
if risk_level == 'DANGEROUS':
    # Block execution
    raise PermissionError(f"Cannot open {file_path}: {reason}")
elif risk_level == 'WARNING':
    # Warn user
    print(f"⚠️ Warning: {reason}")
```

---

### Example 4: Whitelist/Blacklist Management

**Python**:

```python
from web_safety_checker import WebSafetyChecker
from pathlib import Path

checker = WebSafetyChecker()

# Whitelist trusted files
checker.whitelist_file(Path("/Documents/safe_document.pdf"))

# Blacklist dangerous files
checker.blacklist_file(Path("/Downloads/malware.exe"))

# Flag suspicious files (warning level)
checker.flag_suspicious(Path("/Downloads/unknown_file.bin"))

# Now checking these files returns instant verdict (no scanning needed)
verdict = checker.check_file_download(Path("/Documents/safe_document.pdf"))
print(verdict.status)  # Output: SAFE (from whitelist)
```

---

### Example 5: Dashboard Integration

**HTML Dashboard**:

```html
<html>
<head>
    <link rel="stylesheet" href="web_safety_component.html" />
</head>
<body>
    <div class="dashboard">
        <h1>Attack Detection & File Safety</h1>
        
        <!-- Show detected files -->
        <table id="filesTable">
            <thead>
                <tr>
                    <th>File Name</th>
                    <th>Status</th>
                    <th>Safety</th>  <!-- NEW -->
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="filesBody">
                <!-- Populated by JavaScript -->
            </tbody>
        </table>
    </div>
    
    <script>
        async function updateFilesSafety() {
            // Get list of detected files
            const files = await getDetectedFiles();
            
            for (const file of files) {
                // Check safety of each file
                const formData = new FormData();
                formData.append('file', file);
                
                const response = await fetch('/api/check-file-safety', {
                    method: 'POST',
                    body: formData
                });
                
                const safety = await response.json();
                
                // Add to table
                addFileRow(file, safety);
            }
        }
        
        function addFileRow(file, safety) {
            const badge = safety.badge;
            const row = document.createElement('tr');
            
            row.innerHTML = `
                <td>${file.name}</td>
                <td>Detected</td>
                <td>
                    <span class="safety-badge" style="background: ${badge.color}">
                        ${badge.icon} ${badge.text}
                    </span>
                </td>
                <td>
                    ${safety.can_open ? 
                        '<button onclick="openFile(this)">Open</button>' : 
                        '<button disabled>Blocked</button>'
                    }
                </td>
            `;
            
            document.getElementById('filesBody').appendChild(row);
        }
    </script>
</body>
</html>
```

---

## Advanced Features

### 1. **Custom Verdict Logic**

```python
class CustomChecker(WebSafetyChecker):
    def check_file_download(self, file_path):
        # Add custom logic
        verdict = super().check_file_download(file_path)
        
        # Maybe check file size
        if file_path.stat().st_size > 100_000_000:  # > 100MB
            verdict.status = 'WARNING'
            verdict.reason = 'Large file - may consume bandwidth'
        
        return verdict
```

### 2. **Integration with External APIs**

```python
import requests

def check_with_external_service(file_hash):
    """Check against VirusTotal, URLhaus, etc."""
    
    # Check VirusTotal
    response = requests.get(
        f'https://www.virustotal.com/api/v3/files/{file_hash}',
        headers={'x-apikey': YOUR_API_KEY}
    )
    
    if response.ok:
        data = response.json()
        # Parse results...
        return verdicts...
```

### 3. **Logging & Monitoring**

```python
from datetime import datetime

class LoggingChecker(WebSafetyChecker):
    def check_file_download(self, file_path):
        verdict = super().check_file_download(file_path)
        
        # Log the check
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'file': str(file_path),
            'status': verdict.status,
            'signature': verdict.av_signature
        }
        
        # Save to database/log file
        self.log_check(log_entry)
        
        return verdict
```

---

## CSS Styling Guide

### Badge Styling

```css
/* Safe (Green) */
.badge-success {
    background: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

/* Warning (Amber) */
.badge-warning {
    background: #fff3cd;
    color: #856404;
    border: 1px solid #ffeeba;
}

/* Dangerous (Red) */
.badge-danger {
    background: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

/* Unknown (Gray) */
.badge-secondary {
    background: #e2e3e5;
    color: #383d41;
    border: 1px solid #d6d8db;
}
```

---

## Common Questions

### Q: How often should I scan files?
**A:** 
- First time: Always scan
- Whitelist: Never scan again (trust)
- Blacklist: Block immediately
- Update ClamAV signatures weekly

### Q: What about large files?
**A:**
```python
if file_size > 1_GB:
    # Skip heavy scanning
    return WebSafetyVerdic(
        status='WARNING',
        reason='File too large to scan'
    )
```

### Q: Can I scan network files?
**A:** Yes, but mount them first:
```python
from pathlib import Path
network_path = Path("\\\\server\\share\\file.zip")
verdict = checker.check_file_download(network_path)
```

### Q: How do I update malware signatures?
**A:**
```bash
# Linux/Mac
freshclam

# Windows
C:\Program Files\ClamAV\freshclam.exe

# Python
import subprocess
subprocess.run(['freshclam'])
```

---

## Testing

```python
# test_web_safety.py
from web_safety_checker import WebSafetyChecker
from pathlib import Path

checker = WebSafetyChecker()

# Test case 1: Clean file
assert checker.check_file_download(Path("document.pdf")).status == 'SAFE'

# Test case 2: Executable (warning)
risk, _ = checker.check_file_type(Path("script.exe"))
assert risk == 'DANGEROUS'

# Test case 3: URL check
verdict = checker.check_url("https://www.google.com")
assert verdict.status in ['SAFE', 'UNKNOWN']
```

---

## Deployment Checklist

- [ ] Install ClamAV: `apt-get install clamav` (Linux) or download from clamav.net (Windows)
- [ ] Update signatures: `freshclam`
- [ ] Test antivirus scanning
- [ ] Configure FastAPI endpoints
- [ ] Deploy `web_safety_checker.py`
- [ ] Deploy `web_safety_api.py`
- [ ] Deploy `web_safety_component.html` to templates
- [ ] Test file upload/download flow
- [ ] Test URL checking
- [ ] Monitor logs for false positives

---

## Files Created

1. **`web_safety_checker.py`** - Core safety checking logic
2. **`web_safety_api.py`** - FastAPI endpoints
3. **`web_safety_component.html`** - Interactive UI component
4. **`WEB_SAFETY_INTEGRATION.md`** - This guide

---

## Integration Timeline

```
Day 1: Core implementation
  ├─ web_safety_checker.py
  └─ web_safety_api.py

Day 2: Frontend
  ├─ HTML component
  └─ JavaScript handlers

Day 3: Testing
  ├─ Unit tests
  ├─ Integration tests
  └─ User acceptance testing

Day 4: Deployment
  ├─ Production setup
  ├─ ClamAV configuration
  └─ Monitoring & logging
```

---

## Support

For issues or questions:
1. Check ClamAV logs
2. Review safety_checker debug output
3. Test with known malware samples (in sandboxed environment only!)

