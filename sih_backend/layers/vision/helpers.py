"""
layers/vision/helpers.py
Shared utilities so all vision modules handle both:
  - FakeParsedEmail  (.attachments list of objects with .filename/.content_type/.payload)
  - Real ParsedEmail (.image_parts list of raw email.message.Message objects)
"""

import re

SUPPORTED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp"}


class _MimePartAdapter:
    """Wraps a raw email.message.Message into the same interface as FakeAttachment."""
    def __init__(self, mime_part):
        self.filename     = mime_part.get_filename() or "image.png"
        self.content_type = mime_part.get_content_type() or "image/unknown"
        self.payload      = mime_part.get_payload(decode=True) or b""


def _is_image(att) -> bool:
    ct    = getattr(att, "content_type", "") or ""
    fname = getattr(att, "filename", "") or ""
    ext   = ("." + fname.rsplit(".", 1)[-1].lower()) if "." in fname else ""
    return ct.startswith("image/") or ext in SUPPORTED_IMAGE_EXTENSIONS


def get_image_attachments(parsed_email) -> list:
    """
    Returns a normalised list of image attachments regardless of
    which ParsedEmail variant is passed in.

    Priority:
      1. parsed_email.attachments  — FakeParsedEmail / future real parser
      2. parsed_email.image_parts  — current real ParsedEmail (raw MIME parts)
    """
    # Path 1 — already-normalised attachment objects
    if hasattr(parsed_email, "attachments") and parsed_email.attachments:
        imgs = [a for a in parsed_email.attachments if _is_image(a)]
        if imgs:
            return imgs

    # Path 2 — raw MIME Message objects from real ParsedEmail.image_parts
    if hasattr(parsed_email, "image_parts") and parsed_email.image_parts:
        result = []
        for part in parsed_email.image_parts:
            try:
                if callable(getattr(part, "get_payload", None)):
                    # It's a MIME Message — wrap it
                    adapted = _MimePartAdapter(part)
                    if _is_image(adapted):
                        result.append(adapted)
                elif hasattr(part, "payload") and _is_image(part):
                    result.append(part)
            except Exception:
                pass
        return result

    return []


def get_payload_bytes(att) -> bytes:
    payload = getattr(att, "payload", None)
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8", errors="replace")
    return b""