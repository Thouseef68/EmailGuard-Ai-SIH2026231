from core.attachment_extractor import EmailAttachment
from layers.attachments.office_macro_scan import scan_office_attachments

# Read a real .doc/.xls with macros if you have one
with open("sample_macro.doc", "rb") as f:
    data = f.read()

att = EmailAttachment(filename="sample_macro.doc", content_type="application/msword", data=data)
result = scan_office_attachments([att])
print(result)