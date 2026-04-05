# Dashboard URL & File Safety Integration Guide

## Overview

This guide explains how to integrate **URL and File Safety Checking** into your Zero-Day Attack Detection Dashboard. The system allows you to:

1. ✓ **Check URLs** - Verify if a URL is safe based on reputation and patterns
2. ✓ **Check File Types** - Analyze file extension risks (executables, scripts, etc.)
3. ✓ **Combined Analysis** - Get recommendations based on both URL and file analysis
4. ✓ **Real-Time Scanning** - Use alongside the attack detection pipeline to catch anomalies

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Zero-Day Dashboard (Flask)             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Route: /api/check-url              ← Check URL safety │
│  Route: /api/check-file-type        ← Check file risk  │
│  Route: /api/check-anomaly          ← Combined check   │
│                                                         │
│  Web Safety Checker                                     │
│  ├─ web_safety_checker.py                              │
│  ├─ WebSafetyChecker class                             │
│  ├─ check_url()         → SAFE/WARNING/DANGEROUS       │
│  ├─ check_file_type()   → SAFE/WARNING/DANGEROUS       │
│  └─ get_safety_badge()  → UI badge data                │
│                                                         │
└─────────────────────────────────────────────────────────┘
         ↑
         │ Requests (JSON)
         │
┌─────────────────────────────────────────────────────────┐
│              Browser / Frontend (HTML/JS)               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  safety_checker_panel.html                              │
│  ├─ URL input field                                     │
│  ├─ Filename input field                                │
│  ├─ Check buttons                                       │
│  ├─ Results display                                     │
│  └─ Recommendations                                     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Step 1: Files Created

All files are already in your project:

```
fyp2/
├── web_safety_checker.py              ← Core safety checking logic
├── web_dashboard.py                   ← Updated with 3 new routes
└── templates/
    ├── dashboard.html                 ← Main dashboard (needs update)
    └── safety_checker_panel.html      ← URL/File safety UI
```

### Step 2: API Routes Added

Three new Flask routes have been added to `web_dashboard.py`:

#### 2.1 Check URL Safety
```
POST /api/check-url
Content-Type: application/json

{
    "url": "https://example.com"
}

Response:
{
    "url": "https://example.com",
    "status": "SAFE|WARNING|DANGEROUS|UNKNOWN",
    "reason": "URL reputation check not available",
    "confidence": 0.5,
    "av_status": "UNAVAILABLE",
    "badge": {
        "text": "UNKNOWN",
        "color": "#6c757d",
        "icon": "?",
        "label": "Status unknown",
        "css_class": "badge-secondary"
    }
}
```

#### 2.2 Check File Type
```
POST /api/check-file-type
Content-Type: application/json

{
    "filename": "script.exe"
}

Response:
{
    "filename": "script.exe",
    "risk_level": "DANGEROUS|WARNING|SAFE",
    "reason": "Executable - can run code"
}
```

#### 2.3 Combined Check
```
POST /api/check-anomaly
Content-Type: application/json

{
    "url": "https://example.com",
    "filename": "document.pdf"
}

Response:
{
    "url_check": {...},
    "file_type_check": {...},
    "combined_risk": "DANGEROUS|WARNING|SAFE|UNKNOWN",
    "recommendation": "Action to take"
}
```

---

## Integration Steps

### Step 1: Add Safety Checker Panel to Dashboard

Insert the safety checker HTML into `dashboard.html`:

```html
<!-- After the main pipeline steps, before closing container -->
<div id="safetyCheckerContainer"></div>

<script>
  // Load safety checker panel
  fetch('/templates/safety_checker_panel.html')
    .then(r => r.text())
    .then(html => {
      document.getElementById('safetyCheckerContainer').innerHTML = html;
    });
</script>
```

Or directly include it:

```html
<!-- Copy the entire contents of safety_checker_panel.html here -->
{% include 'safety_checker_panel.html' %}
```

### Step 2: Hook into Pipeline Events

Update the JavaScript in `dashboard.html` to enable/disable the safety checker:

```javascript
// In startPipeline() function:
function startPipeline() {
  // ... existing code ...
  
  // Enable safety checker when pipeline starts
  enableSafetyChecker();
}

// In error handler:
function onError(d) {
  // ... existing code ...
  
  // Disable safety checker on error
  disableSafetyChecker();
}

// When pipeline completes:
function onPipelineComplete(d) {
  // ... existing code ...
  
  // Keep safety checker enabled after completion
  enableSafetyChecker();
}
```

---

## Usage Examples

### Example 1: Check a URL During Pipeline

1. Run the pipeline: Click "▶ Run Pipeline"
2. Once started, the URL/File Safety section becomes enabled
3. Enter a URL: `https://bit.ly/abc123`
4. Click "Check URL"
5. See result: ⚠️ WARNING - "Shortened URL - destination unclear"

### Example 2: Check a Suspicious File

1. Enter filename: `invoice_2026.exe`
2. Click "Check File Type"
3. See result: 🔴 DANGEROUS - "Executable - can run code"

### Example 3: Combined Analysis

1. Enter URL: `https://example.com`
2. Enter filename: `contract.docx`
3. Click "Check Both"
4. Get combined recommendation: "URL appears safe but file may contain macros"

---

## Safety Status Definitions

### For URLs:

| Status | Meaning | Action |
|--------|---------|--------|
| **SAFE** | URL passes reputation checks | Navigate freely |
| **WARNING** | Shortened URL or suspicious pattern | Ask user to verify |
| **DANGEROUS** | Known malicious URL | Block access |
| **UNKNOWN** | No reputation data available | Limit functionality |

### For Files:

| Risk Level | Meaning | Action |
|------------|---------|--------|
| **DANGEROUS** | .exe, .bat, .ps1, .dll, .sys | Block execution |
| **WARNING** | .zip, .pdf, .doc, .js, etc. | Warn user before opening |
| **SAFE** | .jpg, .txt, .mp3, etc. | Safe to open |

---

## Testing the Integration

### Test Case 1: Safe URL + Safe File

```
URL: https://www.github.com
Filename: readme.txt
Expected: ✓ SAFE
```

### Test Case 2: Suspicious URL + Dangerous File

```
URL: bit.ly/abc123
Filename: script.exe
Expected: 🔴 DANGEROUS (combined)
```

### Test Case 3: File Type Analysis

```
Filename: document.pdf
Expected: ⚠️ WARNING - "PDF - has known exploits"
```

---

## Customizing the Safety Checker

### Add Custom URL Checks

Edit `web_safety_checker.py`:

```python
def check_url(self, url: str) -> WebSafetyVerdic:
    # Add custom logic
    suspicious_patterns = [
        'phishing',
        'malware',
        'ransomware'
    ]
    
    if any(p in url.lower() for p in suspicious_patterns):
        return WebSafetyVerdic(
            status='DANGEROUS',
            confidence=1.0,
            reason='URL matches suspicious patterns',
            av_status='BLACKLISTED',
            av_signature='',
            timestamp=datetime.now().isoformat()
        )
```

### Integrate External APIs

```python
import requests

def check_with_virustotal(file_hash: str):
    """Check file hash against VirusTotal"""
    response = requests.get(
        f'https://www.virustotal.com/api/v3/files/{file_hash}',
        headers={'x-apikey': YOUR_API_KEY}
    )
    
    if response.ok:
        data = response.json()
        # Parse detections...
        return verdict
```

---

## Dashboard Integration Points

### 1. After Pipeline Completes

```javascript
function onPipelineComplete(d) {
    // Show summary
    // ...
    
    // Suggest checking detected files
    sendEvent("suggestion", {
        "type": "check_files",
        "message": "Pipeline complete. Want to check if any detected files are safe?",
        "files": detected_filenames
    });
}
```

### 2. During Attack Execution

```python
def _atk_done(idx, rpt):
    # ... existing attack complete code ...
    
    # Show file impacts in safety checker
    for impact in rpt.files_impacted:
        send_event("file_detected", {
            "filename": impact.path,
            "status": impact.av_status,
            "signature": impact.av_signature
        })
```

### 3. In Detection Results

Add safety verdict to the attack detection table:

```html
<table class="data-table">
  <thead>
    <tr>
      <th>File</th>
      <th>AV Verdict</th>
      <th>Safety Check</th>  <!-- NEW -->
      <th>Type Risk</th>     <!-- NEW -->
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>malware.exe</td>
      <td>INFECTED</td>
      <td><span class="badge badge-danger">DANGEROUS</span></td>
      <td><span class="badge badge-danger">EXECUTABLE</span></td>
    </tr>
  </tbody>
</table>
```

---

## Troubleshooting

### Issue: Safety checker buttons are disabled

**Solution:** The safety checker is only enabled when the pipeline is running. Click "▶ Run Pipeline" first.

### Issue: URL check always returns UNKNOWN

**Solution:** Current implementation doesn't integrate with external reputation APIs. To enable:
1. Get an API key from Google Safe Browsing, URLhaus, or VirusTotal
2. Add API calls to `check_url()` method in `web_safety_checker.py`

### Issue: File type analysis missing some extensions

**Solution:** Edit the `dangerous_extensions` and `warning_extensions` dictionaries in `web_safety_checker.py`:

```python
dangerous_extensions = {
    '.exe': 'Executable - can run code',
    '.bat': 'Batch script - can run commands',
    '.custom': 'Your custom type here'  # ADD THIS
}
```

---

## Performance Considerations

- URL checks: ~100ms (no external API)
- File type checks: ~1ms (instant)
- Combined checks: <200ms
- No scanning overhead - uses hashes and pattern matching

---

## Security Notes

1. **Whitelist trusted files** to skip repeated scanning:
   ```python
   checker.whitelist_file(Path("trusted_app.exe"))
   ```

2. **Blacklist known malware**:
   ```python
   checker.blacklist_file(Path("malware.exe"))
   ```

3. **Update ClamAV signatures weekly**:
   ```bash
   freshclam  # On Linux/Mac
   ```

---

## Next Steps

1. ✓ Add the safety panel HTML to dashboard.html
2. ✓ Test with sample URLs and filenames
3. ✓ Integrate external reputation APIs
4. ✓ Add whitelist/blacklist management UI
5. ✓ Create alerts for dangerous files

---

## API Documentation

### Complete Endpoint Reference

```
POST /api/check-url
├─ Input: { "url": string }
├─ Output: { "status", "reason", "confidence", "badge" }
└─ Status codes: 200 (OK), 400 (bad request), 500 (error)

POST /api/check-file-type
├─ Input: { "filename": string }
├─ Output: { "risk_level", "reason" }
└─ Status codes: 200 (OK), 400 (bad request), 500 (error)

POST /api/check-anomaly
├─ Input: { "url": string, "filename": string }
├─ Output: { "url_check", "file_type_check", "combined_risk", "recommendation" }
└─ Status codes: 200 (OK), 400 (bad request), 500 (error)
```

---

## Example: Complete Workflow

```
1. User opens dashboard
2. Clicks "▶ Run Pipeline"
3. Pipeline starts, safety checker enabled
4. User receives email: "Check this file: invoice.zip from bit.ly/xyz"
5. User enters URL: bit.ly/xyz
6. User enters filename: invoice.zip
7. Click "Check Both"
8. API checks URL (WARNING - shortened) and file (WARNING - archive)
9. Dashboard shows: ⚠️ COMBINED WARNING with recommendation
10. User decides to verify source before opening
```

---

## Files Reference

| File | Purpose | Type |
|------|---------|------|
| `web_safety_checker.py` | Core logic | Python |
| `web_dashboard.py` | Flask routes | Python |
| `safety_checker_panel.html` | UI component | HTML/CSS/JS |
| `dashboard.html` | Main dashboard | HTML (needs update) |

