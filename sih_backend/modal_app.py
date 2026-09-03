from pathlib import Path
import modal


# ============================================================
# SETTINGS
# ============================================================

APP_NAME = "emailguard-api"
HF_REPO = "thouseeff/sih-phishing-models"
MODEL_VOLUME_NAME = "emailguard-models"
MODEL_DIR = "/app/models"


# ============================================================
# MODAL APP
# ============================================================

app = modal.App(APP_NAME)


# ============================================================
# PERSISTENT MODEL STORAGE
# ============================================================

model_volume = modal.Volume.from_name(
    MODEL_VOLUME_NAME,
    create_if_missing=True,
)


# ============================================================
# CONTAINER IMAGE
# ============================================================

ROOT = Path(__file__).parent

image = (
    modal.Image.debian_slim(
        python_version="3.11"
    )
    .pip_install_from_requirements(
        ROOT / "requirements.txt"
    )
    .pip_install(
        "huggingface_hub"
    )
    .workdir("/app")
    .add_local_dir(
        ROOT / "core",
        "/app/core",
    )
    .add_local_dir(
        ROOT / "layers",
        "/app/layers",
    )
    .add_local_dir(
        ROOT / "infra",
        "/app/infra",
    )
    .add_local_file(
        ROOT / "main.py",
        "/app/main.py",
    )
    .add_local_file(
        ROOT / "config.py",
        "/app/config.py",
    )
)


# ============================================================
# DOWNLOAD MODELS FROM HF HUB
# ============================================================

@app.function(
    image=image,
    volumes={
        MODEL_DIR: model_volume,
    },
    secrets=[
        modal.Secret.from_name("emailguard-secrets"),
    ],
    timeout=1800,
)
def download_models():
    from huggingface_hub import snapshot_download

    print("Downloading EmailGuard models from Hugging Face...")
    print(f"Repository: {HF_REPO}")
    print(f"Target: {MODEL_DIR}")

    snapshot_download(
        repo_id=HF_REPO,
        local_dir=MODEL_DIR,
    )

    model_volume.commit()

    print("\nModel download complete.")

    for path in sorted(Path(MODEL_DIR).rglob("*")):
        if path.is_file():
            print(path)


# ============================================================
# FASTAPI SERVICE
# ============================================================

@app.function(
    image=image,
    gpu="T4",
    cpu=4,
    memory=16384,
    timeout=900,
    volumes={
        MODEL_DIR: model_volume,
    },
    secrets=[
        modal.Secret.from_name("emailguard-secrets"),
    ],
)
@modal.asgi_app()
def web():
    import os
    import sys

    # Tell config.py where the Modal model volume is mounted.
    os.environ["EMAILGUARD_MODEL_DIR"] = MODEL_DIR

    # Make /app explicitly importable.
    if "/app" not in sys.path:
        sys.path.insert(0, "/app")

    from main import app as fastapi_app

    return fastapi_app