"""
Web Dashboard Integration: Safety Indicator Component
======================================================

Shows real-time safety status when users download or access files.
Integrates with web_safety_checker.py to provide live safety feedback.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import asyncio
from web_safety_checker import WebSafetyChecker


app = FastAPI()
safety_checker = WebSafetyChecker()


@app.post("/api/check-file-safety")
async def check_file_safety(file: UploadFile = File(...)):
    """
    Check if uploaded file is safe
    
    Example usage in JavaScript:
    ```
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    const response = await fetch('/api/check-file-safety', {
        method: 'POST',
        body: formData
    });
    
    const safety = await response.json();
    // Display badge based on safety.status
    ```
    """
    try:
        # Save uploaded file temporarily
        temp_path = Path(f"/tmp/{file.filename}")
        content = await file.read()
        temp_path.write_bytes(content)
        
        # Check safety
        verdict = safety_checker.check_file_download(temp_path)
        badge = safety_checker.get_safety_badge(verdict)
        
        # Clean up
        temp_path.unlink()
        
        return {
            'filename': file.filename,
            'status': verdict.status,
            'reason': verdict.reason,
            'confidence': verdict.confidence,
            'badge': badge,
            'can_open': verdict.status in ['SAFE', 'WARNING']
        }
    
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={'error': str(e)}
        )


@app.get("/api/check-url-safety/{url:path}")
async def check_url_safety(url: str):
    """
    Check if URL is safe
    
    Example: GET /api/check-url-safety/https://example.com
    """
    verdict = safety_checker.check_url(url)
    badge = safety_checker.get_safety_badge(verdict)
    
    return {
        'url': url,
        'status': verdict.status,
        'reason': verdict.reason,
        'confidence': verdict.confidence,
        'badge': badge
    }
