# core/attachment_extractor.py
"""
Extract file attachments from raw .eml bytes.
Each layer filters by is_pdf / is_office as needed.
"""
import email
from dataclasses import dataclass
from typing import List

OFFICE_EXTENSIONS = {
    '.doc', '.docx', '.docm', '.dotm',
    '.xls', '.xlsx', '.xlsm', '.xlsb', '.xltm',
    '.ppt', '.pptx', '.pptm',
}
OFFICE_MIME_TYPES = {
    'application/msword',
    'application/vnd.ms-excel',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-excel.sheet.macroEnabled.12',
    'application/vnd.ms-word.document.macroEnabled.12',
    'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
}


@dataclass
class EmailAttachment:
    filename: str
    content_type: str
    data: bytes

    @property
    def extension(self) -> str:
        if '.' in self.filename:
            return '.' + self.filename.rsplit('.', 1)[-1].lower()
        return ''

    @property
    def is_pdf(self) -> bool:
        return (
            self.content_type == 'application/pdf'
            or self.extension == '.pdf'
        )

    @property
    def is_office(self) -> bool:
        return (
            self.content_type in OFFICE_MIME_TYPES
            or self.extension in OFFICE_EXTENSIONS
        )


def extract_attachments(eml_bytes: bytes) -> List[EmailAttachment]:
    """Return all named, non-inline attachments from the email."""
    try:
        msg = email.message_from_bytes(eml_bytes)
    except Exception:
        return []

    results: List[EmailAttachment] = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue

        filename = part.get_filename() or ''
        if not filename:
            continue                          # skip unnamed body parts

        ct = part.get_content_type() or 'application/octet-stream'
        payload = part.get_payload(decode=True)
        if payload:
            results.append(EmailAttachment(
                filename=filename,
                content_type=ct,
                data=payload,
            ))
    return results