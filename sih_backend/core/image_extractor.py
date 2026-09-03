# core/image_extractor.py
"""
Extract all inline and attached images from raw .eml bytes.
Returns a list of raw image bytes (one entry per image part).
"""
import email
from typing import List


def extract_images_from_eml(eml_bytes: bytes) -> List[bytes]:
    """Walk the MIME tree and collect every image/* part as raw bytes."""
    try:
        msg = email.message_from_bytes(eml_bytes)
    except Exception:
        return []

    images: List[bytes] = []
    for part in msg.walk():
        ct = part.get_content_type() or ""
        if ct.startswith("image/"):
            payload = part.get_payload(decode=True)
            if payload and len(payload) > 100:   # skip tiny 1×1 tracking pixels
                images.append(payload)
    return images