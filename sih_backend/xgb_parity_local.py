import csv
from pathlib import Path
import numpy as np
import xgboost as xgb

from core.eml_parser import parse_eml
from layers.text_structural.xgboost_model import build_xgb_features

BASE = Path(__file__).resolve().parent

EML_DIR = BASE / "sih_phase4_real_100_eml"
MODEL = BASE / "models" / "xgboost_phishing_v2.json"
META = BASE / "models" / "xgboost_feature_cols_v2.json"
OUT = BASE / "xgb_parity_local.csv"

CASES = [1,21,24,25,29,41,64,74,75,87,92,94]

import json

booster = xgb.Booster()
booster.load_model(str(MODEL))

with open(META, encoding="utf-8") as f:
    meta = json.load(f)

COLS = meta["features"] if isinstance(meta, dict) else meta
assert len(COLS) == 42

rows = []

for n in CASES:

    files = list(
        EML_DIR.glob(
            f"{n:03d}_*.eml"
        )
    )

    if not files:
        print(f"SKIP {n:03d}")
        continue

    path = files[0]

    parsed = parse_eml(
        path.read_bytes()
    )

    vec = build_xgb_features(
        parsed,
        COLS
    )[0].astype(float)

    prob = float(
        booster.predict(
            xgb.DMatrix(
                vec.reshape(1,-1),
                feature_names=COLS
            )
        )[0]
    )

    print(
        f"\n{path.name} | XGB={prob:.6f}"
    )

    for i,(c,v) in enumerate(
        zip(COLS,vec),1
    ):
        print(
            f"{i:02d} | "
            f"{c:<36} | "
            f"{v}"
        )

    row = {
        "case": n,
        "filename": path.name,
        "xgb_probability": prob,
        "body_length": len(
            parsed.body_text
        ),
        "header_length": len(
            parsed.header_block_text
        ),
        "received_count": len(
            parsed.received_headers
        ),
        "attachment_count":
            parsed.attachment_count,
        "multipart":
            int(parsed.is_multipart),
        "html_present":
            int(parsed.has_html),
        "plain_text_present":
            int(parsed.has_plain),
    }

    row.update(
        dict(zip(COLS,vec))
    )

    rows.append(row)

with open(
    OUT,
    "w",
    newline="",
    encoding="utf-8"
) as f:

    w = csv.DictWriter(
        f,
        fieldnames=rows[0].keys()
    )

    w.writeheader()
    w.writerows(rows)

print(
    "\n✅ Saved:",
    OUT
)