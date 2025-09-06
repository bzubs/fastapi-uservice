import numpy as np
import joblib
from pathlib import Path

# -------------------- Load Model & Preprocessors --------------------
MODEL_DIR = Path("app/models")
model = joblib.load(MODEL_DIR / "log_reg_model.pkl")
scaler = joblib.load(MODEL_DIR / "scaler.pkl")
imputer = joblib.load(MODEL_DIR / "imputer.pkl")

# -------------------- Hardcoded Test Row --------------------
# Use your X_test_imputed[0] here


# -------------------- Prediction Function --------------------
def predict_drive_health(features):
    """
    Returns probability score (0-1) and health class (0/1).
    If features=None, uses hardcoded X_test row.
    """

    features = np.array(features)
    features = features.reshape(1, -1)

    # Handle NaNs using imputer
    features_imputed = imputer.transform(features)
    features_scaled = scaler.transform(features_imputed)

    # Logistic Regression probability
    prob = model.predict_proba(features_scaled)[:, 1][0]
    health_class = int(prob > 0.5)

    return round(prob, 4), health_class
