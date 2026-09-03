"""
diagnose_body.py — inspect exactly what text is being fed to DeBERTa

No core files touched. Just prints what parse_eml() extracts so we can see
if it's dominated by quoted-reply/mailing-list noise.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.eml_parser import parse_eml

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python diagnose_body.py path/to/email.eml")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        eml_bytes = f.read()

    parsed = parse_eml(eml_bytes)

    print(f"Subject: {parsed.subject}")
    print(f"From   : {parsed.from_addr}")
    print(f"Body text length: {len(parsed.body_text)} characters, {len(parsed.body_text.split())} words")
    print()
    print("=" * 90)
    print("FIRST 800 CHARACTERS OF EXTRACTED BODY TEXT:")
    print("=" * 90)
    print(parsed.body_text[:800])
    print()
    print("=" * 90)
    print("LAST 400 CHARACTERS OF EXTRACTED BODY TEXT:")
    print("=" * 90)
    print(parsed.body_text[-400:])
    print()
    quote_lines = sum(1 for line in parsed.body_text.split("\n") if line.strip().startswith(">"))
    print(f"Lines starting with '>' (quoted reply markers): {quote_lines}")
