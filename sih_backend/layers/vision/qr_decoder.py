# layers/vision/qr_decoder.py
"""
QR code detection and decoding from email images.
Detects quishing (QR phishing) by extracting embedded URLs.
Uses cv2.QRCodeDetector — no external DLL needed on Windows.
"""
from typing import List, Dict, Any
import io
import cv2
import numpy as np
from PIL import Image


def decode_qr_codes(images: List[bytes]) -> Dict[str, Any]:
    """
    Scan each image for QR codes. Returns decoded data and any embedded URLs.

    Returns:
        {
          "qr_found": bool,
          "qr_count": int,
          "qr_urls": list[str],          # URLs decoded from QR codes
          "qr_findings": list,            # per-image breakdown
          "quishing_suspected": bool      # True if any URL-bearing QR found
        }
    """
    detector = cv2.QRCodeDetector()
    qr_urls: List[str] = []
    findings: List[Dict[str, Any]] = []

    for idx, img_bytes in enumerate(images):
        try:
            # PIL → numpy (BGR for OpenCV)
            pil_img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

            data, bbox, _ = detector.detectAndDecode(cv_img)

            if data:
                is_url = data.lower().startswith(("http://", "https://"))
                entry = {
                    "image_index": idx,
                    "decoded_data": data,
                    "is_url": is_url,
                    "error": None,
                }
                findings.append(entry)
                if is_url:
                    qr_urls.append(data)
            else:
                findings.append({
                    "image_index": idx,
                    "decoded_data": None,
                    "is_url": False,
                    "error": None,
                })

        except Exception as exc:
            findings.append({
                "image_index": idx,
                "decoded_data": None,
                "is_url": False,
                "error": str(exc),
            })

    qr_found = any(f["decoded_data"] for f in findings)
    return {
        "qr_found": qr_found,
        "qr_count": sum(1 for f in findings if f["decoded_data"]),
        "qr_urls": qr_urls,
        "qr_findings": findings,
        "quishing_suspected": len(qr_urls) > 0,
    }