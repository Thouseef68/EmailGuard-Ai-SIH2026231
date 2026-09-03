# layers/vision/ocr_extractor.py
"""
OCR extraction from email-embedded images.
Uses EasyOCR (en + hi) to surface text hidden in images.
"""
from typing import List, Dict, Any
import io

_reader = None


def _get_reader():
    global _reader
    if _reader is None:
        import easyocr
        _reader = easyocr.Reader(["en", "hi"], gpu=False, verbose=False)
    return _reader


def extract_ocr_text(images: List[bytes]) -> Dict[str, Any]:
    """
    Run OCR on each image and return combined text + per-image findings.

    Returns:
        {
          "image_count": int,
          "ocr_text": str,           # all extracted text joined
          "ocr_findings": list,       # per-image breakdown
          "has_image_text": bool
        }
    """
    if not images:
        return {
            "image_count": 0,
            "ocr_text": "",
            "ocr_findings": [],
            "has_image_text": False,
        }

    reader = _get_reader()
    all_texts: List[str] = []
    findings: List[Dict[str, Any]] = []

    for idx, img_bytes in enumerate(images):
        try:
            # EasyOCR accepts raw bytes directly
            result = reader.readtext(img_bytes, detail=0, paragraph=True)
            text = " ".join(result).strip()
            findings.append({
                "image_index": idx,
                "text": text,
                "char_count": len(text),
                "error": None,
            })
            if text:
                all_texts.append(text)
        except Exception as exc:
            findings.append({
                "image_index": idx,
                "text": "",
                "char_count": 0,
                "error": str(exc),
            })

    combined = "\n".join(all_texts)
    return {
        "image_count": len(images),
        "ocr_text": combined,
        "ocr_findings": findings,
        "has_image_text": bool(combined.strip()),
    }