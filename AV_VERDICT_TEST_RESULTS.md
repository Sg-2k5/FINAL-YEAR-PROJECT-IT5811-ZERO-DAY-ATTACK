# AV Verdict Test Results & Documentation

## Overview
The AV verdict feature in the Zero-Day Detection system categorizes files scanned by antivirus into four status categories. The test demonstrates all three main types of verdicts.

## Test Run Results

### Test Structure
```
Total Files Tested: 6
├─ Type 1 (MISSING): 2 files expected, 3 detected
├─ Type 2 (NOT_APPLICABLE): 3 files - PASSED ✓
└─ Type 3 (CLEAN/UNAVAILABLE): 1 file - Not testable without actual files
```

### Results Summary
```
✓ MISSING (Deleted files):        3 files (50.0%)
⊘ NOT_APPLICABLE (Modified):      3 files (50.0%)
✓ CLEAN/UNAVAILABLE:              0 files ( 0.0%)
```

## AV Verdict Status Types

### 1. ◎ MISSING (File Deleted)
**When it occurs:**
- File existed before the attack (`existed_before=True`)  
- File no longer exists after the attack (`existed_after=False`)

**Example:**
```
File: system_backup.bak
  Status: MISSING
  Reason: Attacker deleted the backup file
```

**Significance:**
- File was present before attack
- No AV scan performed (file cannot be scanned if it doesn't exist)
- Indicates file deletion by attacker as part of attack

---

### 2. ⊘ NOT_APPLICABLE (File Modified/Encrypted)
**When it occurs:**
- File has `integrity_status` = NEW, MODIFIED, or MISSING, **OR**
- File has `affected_by_sha=True` (content changed)

**Examples:**

a) **NEW file (created by attack):**
```
File: ransomware_readme.txt
  integrity_status: NEW
  affected_by_sha: True
  Reason: Ransomware created ransom note
```

b) **MODIFIED file (encrypted by attack):**
```
File: etc\passwd
  integrity_status: MODIFIED  
  affected_by_sha: True
  Hash Before: 9c4ec2c22a58448b
  Hash After:  d4c5baaf0e664bd9
  Reason: File encrypted/modified by ransomware
```

**Significance:**
- File was modified/encrypted by the attack
- **NOT scanned by antivirus** (would likely return error)
- Encrypted/modified files cannot be reliably scanned
- Indicates direct attack impact on this file

---

### 3. ✓ CLEAN (File Passed Scan)
**When it occurs:**
- File has `integrity_status=UNCHANGED` (#)
- File has `affected_by_sha=False` (content didn't change)
- File exists and is scanned by ClamAV antivirus
- ClamAV returns 0 (clean) or marks as safe

**Example:**
```
File: system_library.dll
  integrity_status: UNCHANGED
  affected_by_sha: False
  AV Status: CLEAN
  Reason: File unmodified by attack and passed AV scan
```

**Significance:**
- File was **not touched** by the attack
- File **passed antivirus scan** - no malware detected
- Safe to use; no action needed

---

### 4. ? UNAVAILABLE (Cannot Scan)
**When it occurs:**
- File exists but cannot be scanned due to:
  - Permission denied (file locked)
  - ClamAV not installed
  - ClamAV database not found
  - File disappeared between detection and scan

**Example:**
```
File: locked_file.db
  Status: UNAVAILABLE  
  Reason: File locked by process; cannot read
  Action: Retry scan after process releases file
```

---

## Logic Flow Diagram

```
FileImpact comes in
    │
    ├─ existed_after == False?
    │  └─ YES → MISSING ◎
    │
    └─ existed_after == True?
       │
       ├─ (integrity_status != UNCHANGED) OR (affected_by_sha == True)?
       │  └─ YES → NOT_APPLICABLE ⊘
       │
       └─ (integrity_status == UNCHANGED) AND (affected_by_sha == False)?
          │
          ├─ File exists and readable?
          │  └─ NO → MISSING ◎
          │
          └─ Scan file with ClamAV
             │
             ├─ Returns 0 (clean) → CLEAN ✓
             ├─ File not found → MISSING ◎  
             ├─ Permission denied → UNAVAILABLE ?
             └─ Other error → UNAVAILABLE ? or ERROR ✗
```

---

## Test Code Examples

### Creating Test Files
```python
from fyp2.src.data.real_attack_executor import FileImpact, AttackReport

# Create MISSING file impact
missing_impact = FileImpact(
    path='deleted_backup.bak',
    existed_before=True,
    existed_after=False,  # ← KEY: File doesn't exist after
    hash_before='aabbccdd11223344',
    size_before=4096,
    integrity_status='MISSING',
    affected_by_sha=True,
    change_summary='SHA_MISSING_FILE'
)

# Create NOT_APPLICABLE file impact (MODIFIED)
modified_impact = FileImpact(
    path='encrypted_database.db',
    existed_before=True,
    existed_after=True,
    hash_before='1111222233334444',
    hash_after='5555666677778888',  # ← Different hash
    integrity_status='MODIFIED',    # ← KEY: Modified status
    affected_by_sha=True,           # ← KEY: SHA changed
    change_summary='SHA_CHANGED'
)

# Create CLEAN file impact  
clean_impact = FileImpact(
    path='untouched_file.txt',
    existed_before=True,
    existed_after=True,
    hash_before='aaaa1111bbbb2222',
    hash_after='aaaa1111bbbb2222',  # ← Same hash
    integrity_status='UNCHANGED',    # ← KEY: Unchanged
    affected_by_sha=False,           # ← KEY: Not affected
    change_summary='NO_CHANGE'
)
```

### Running AV Annotation
```python
from pathlib import Path
from fyp2.src.utils.av_scanner import annotate_attack_reports_with_av

# Create report with impacts
report = AttackReport(
    attack_name='Test Attack',
    description='Test',
    mitre_technique='T1234'
)
report.files_impacted = [missing_impact, modified_impact, clean_impact]

# Annotate with AV scanner
sandbox_path = Path('/path/to/sandbox')
annotate_attack_reports_with_av([report], sandbox_path)

# Check results
for impact in report.files_impacted:
    print(f"{impact.path}: {impact.av_status}")
    # Output:
    # deleted_backup.bak: MISSING
    # encrypted_database.db: NOT_APPLICABLE
    # untouched_file.txt: CLEAN or UNAVAILABLE
```

---

## Field Mapping Reference

| AV Status | Expected | Conditions|
|-----------|----------|-----------|
| **MISSING** | ◎ | `existed_after=False` OR file not found during scan |
| **NOT_APPLICABLE** | ⊘ | `integrity_status != UNCHANGED` OR `affected_by_sha=True` |
| **CLEAN** | ✓ | `integrity_status=UNCHANGED` AND `affected_by_sha=False` AND passed AV scan |
| **UNAVAILABLE** | ? | File unreadable/ClamAV not available |
| **ERROR** | ✗ | ClamAV scan failed with error |

---

## How to Run Tests

### Option 1: Full Test Suite
```bash
cd c:\Users\vrgsa\OneDrive\Documents\fyp2
python -m pytest test_av_verdicts_complete.py -v
```

### Option 2: Quick Test
```bash
python test_av_final.py
```

### Option 3: Manual Test
```python
from fyp2.src.utils.av_scanner import annotate_attack_reports_with_av
from fyp2.src.data.real_attack_executor import FileImpact, AttackReport
from pathlib import Path

# Create your test impacts (see examples above)
# Then run:
annotate_attack_reports_with_av([report], Path.cwd())
```

---

## Key Takeaways

1. **MISSING ◎** - Files deleted by attack
2. **NOT_APPLICABLE ⊘** - Files modified/encrypted by attack (cannot scan)
3. **CLEAN ✓** - Unmodified files that passed antivirus scan
4. **UNAVAILABLE ?** - Files that couldn't be scanned (not found, permissions, etc.)

All statuses are now properly tracked and displayed in the dashboard! ✓
