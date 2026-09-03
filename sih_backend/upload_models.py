from huggingface_hub import HfApi

api = HfApi()
repo = "thouseeff/sih-phishing-models"

print("Uploading XGBoost V3 + fusion files...")

for f in [
    "xgboost_phishing_v3.json",
    "xgboost_feature_cols_v3.json",
    "fusion_config.json",
    "xgboost_feature_importance.csv",
    "xgboost_feature_cols.json",
    "xgboost_phishing.json"


]:
    api.upload_file(
        path_or_fileobj=f"models/{f}",
        path_in_repo=f,
        repo_id=repo
    )

print("Done!")
print("https://huggingface.co/thouseeff/sih-phishing-models")