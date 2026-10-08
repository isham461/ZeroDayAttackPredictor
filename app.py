"""
Zero-Day Attack Detection ML Microservice (FastAPI)
===================================================
Phase 3: Provides real-time inference via a hybrid machine learning pipeline:
- Unsupervised Anomaly Detection: Isolation Forest (Zero-Day Detector)
- Supervised Attack Classification: XGBoost Classifier
- Decision Explainability: SHAP (TreeExplainer)
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
import numpy as np
import pandas as pd
import joblib
import shap
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [ML-SERVICE] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Global model cache
MODELS: Dict[str, Any] = {}
METADATA: Dict[str, Any] = {}
FEATURE_NAMES: List[str] = []

MODELS_DIR = os.getenv("MODELS_DIR", "models")


def load_artifacts() -> None:
    """Load serialized models, explainer, and feature schema from disk."""
    global MODELS, METADATA, FEATURE_NAMES

    if all(k in MODELS for k in ["isolation_forest", "xgboost", "shap_explainer"]):
        return

    meta_path = os.path.join(MODELS_DIR, "metadata.json")
    iso_path = os.path.join(MODELS_DIR, "isolation_forest.joblib")
    xgb_path = os.path.join(MODELS_DIR, "xgboost_model.joblib")
    shap_path = os.path.join(MODELS_DIR, "shap_explainer.joblib")

    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"Metadata file missing: '{meta_path}'. Run train.py first.")

    with open(meta_path, "r") as f:
        METADATA = json.load(f)
    FEATURE_NAMES = METADATA.get("feature_names", [])
    logger.info("Loaded schema metadata: %d expected features.", len(FEATURE_NAMES))

    logger.info("Loading Isolation Forest model from '%s'...", iso_path)
    MODELS["isolation_forest"] = joblib.load(iso_path)

    logger.info("Loading XGBoost model from '%s'...", xgb_path)
    MODELS["xgboost"] = joblib.load(xgb_path)

    logger.info("Loading SHAP Explainer from '%s'...", shap_path)
    MODELS["shap_explainer"] = joblib.load(shap_path)

    logger.info("All ML artifacts loaded successfully.")


# Load immediately on module load as well for direct testing
try:
    load_artifacts()
except Exception as _e:
    logger.warning("Startup immediate load warning (will retry on lifespan): %s", _e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager to load models on startup."""
    try:
        load_artifacts()
    except Exception as e:
        logger.error("Failed to load ML artifacts on startup: %s", e, exc_info=True)
        raise e
    yield
    MODELS.clear()
    logger.info("ML Microservice shut down.")


app = FastAPI(
    title="ZeroGuard: Zero-Day Network Attack Detection ML Engine",
    description="Hybrid Isolation Forest + XGBoost + SHAP API for real-time intrusion detection.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for cross-origin orchestration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class NetworkTrafficRequest(BaseModel):
    """Network traffic input payload. Accepts flexible feature map or raw dictionary."""
    features: Dict[str, float] = Field(
        ...,
        description="Key-value mapping of network flow features (aligned with NSL-KDD schema)."
    )
    raw_payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional raw network metadata for auditing."
    )


class ShapFeatureContribution(BaseModel):
    feature: str
    value: float
    shap_value: float
    impact: str
    risk_direction: str


class ShapExplanation(BaseModel):
    base_value: float
    top_contributing_features: List[ShapFeatureContribution]
    summary_text: str


class PredictionResponse(BaseModel):
    status: str  # "Anomaly" or "Normal"
    threat_category: str  # "Zero-Day Threat", "Known Attack", or "Normal Traffic"
    verdict: str
    alert_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    isolation_forest_anomaly: bool
    anomaly_score: float
    xgboost_prediction: str
    attack_probability: float
    shap_explanation: ShapExplanation
    timestamp: str


def construct_feature_vector(input_features: Dict[str, float]) -> pd.DataFrame:
    """
    Constructs an aligned 1-row DataFrame strictly matching the 122 training features.
    Missing features are imputed with standard 0.0.
    """
    row_data = {}
    for feature in FEATURE_NAMES:
        row_data[feature] = float(input_features.get(feature, 0.0))
    return pd.DataFrame([row_data], columns=FEATURE_NAMES)


def extract_shap_explanation(
    explainer: shap.TreeExplainer,
    df_vector: pd.DataFrame,
    top_k: int = 6
) -> ShapExplanation:
    """
    Computes SHAP feature importance for the single inference vector.
    """
    shap_values = explainer(df_vector)
    
    # Handle single sample output
    values = shap_values.values[0]
    base_val = float(shap_values.base_values[0]) if hasattr(shap_values.base_values, "__len__") else float(shap_values.base_values)
    
    # Sort features by absolute SHAP contribution
    feature_impacts = []
    for feat_name, val, s_val in zip(FEATURE_NAMES, df_vector.iloc[0], values):
        s_val_float = float(s_val)
        direction = "Increases Threat Risk" if s_val_float > 0 else "Reduces Threat Risk"
        impact_level = "High" if abs(s_val_float) > 0.5 else ("Medium" if abs(s_val_float) > 0.1 else "Low")
        
        feature_impacts.append({
            "feature": feat_name,
            "value": round(float(val), 4),
            "shap_value": round(s_val_float, 4),
            "impact": impact_level,
            "risk_direction": direction,
            "abs_impact": abs(s_val_float)
        })

    # Pick top K most influential features
    feature_impacts.sort(key=lambda x: x["abs_impact"], reverse=True)
    top_features = [
        ShapFeatureContribution(
            feature=f["feature"],
            value=f["value"],
            shap_value=f["shap_value"],
            impact=f["impact"],
            risk_direction=f["risk_direction"]
        )
        for f in feature_impacts[:top_k]
    ]

    top_names = [f.feature for f in top_features[:3]]
    summary = f"Decision primarily driven by network attributes: {', '.join(top_names)}."

    return ShapExplanation(
        base_value=round(base_val, 4),
        top_contributing_features=top_features,
        summary_text=summary
    )


@app.get("/health", tags=["Monitoring"])
def health_check():
    """Health check endpoint to verify ML microservice status."""
    is_ready = all(k in MODELS for k in ["isolation_forest", "xgboost", "shap_explainer"])
    return {
        "status": "online" if is_ready else "initializing",
        "service": "Zero-Day Attack Detection ML Engine",
        "models_loaded": list(MODELS.keys()),
        "features_count": len(FEATURE_NAMES)
    }


@app.get("/sample-payload", tags=["Testing"])
def get_sample_payloads():
    """Provides sample network payloads for Normal, Known Attack, and Zero-Day anomaly testing."""
    return {
        "normal_traffic": {
            "duration": 0.0,
            "src_bytes": -0.0076,
            "dst_bytes": -0.0044,
            "logged_in": 1.23,
            "count": -0.71,
            "srv_count": -0.35,
            "same_srv_rate": 0.77,
            "diff_srv_rate": -0.34,
            "dst_host_count": 0.73,
            "dst_host_srv_count": 1.25,
            "dst_host_same_srv_rate": 1.06,
            "flag_SF": 1.0,
            "protocol_type_tcp": 1.0,
            "service_http": 1.0
        },
        "known_attack_syn_flood": {
            "duration": 0.0,
            "src_bytes": -0.0076,
            "dst_bytes": -0.0044,
            "logged_in": -0.81,
            "count": 2.14,
            "srv_count": 0.45,
            "serror_rate": 1.60,
            "srv_serror_rate": 1.60,
            "same_srv_rate": -1.37,
            "diff_srv_rate": 0.25,
            "dst_host_serror_rate": 1.60,
            "dst_host_srv_serror_rate": 1.60,
            "flag_S0": 1.0,
            "protocol_type_tcp": 1.0,
            "service_private": 1.0
        },
        "zero_day_threat": {
            "duration": 5.42,
            "src_bytes": 14.85,
            "dst_bytes": 22.10,
            "hot": 8.50,
            "num_compromised": 12.0,
            "root_shell": 1.0,
            "num_root": 9.40,
            "count": 4.80,
            "srv_diff_host_rate": 3.90,
            "dst_host_count": 1.80,
            "dst_host_diff_srv_rate": 4.20,
            "flag_SF": 1.0,
            "protocol_type_tcp": 1.0,
            "service_other": 1.0
        }
    }


@app.post("/predict", response_model=PredictionResponse, tags=["Inference"])
def predict_network_traffic(payload: NetworkTrafficRequest):
    """
    Orchestrated Inference Pipeline:
    1. Align input to 122 feature space
    2. Stage 1: Isolation Forest Anomaly Detection
    3. Stage 2: XGBoost Attack Classification
    4. Stage 3: SHAP Feature Attribution
    """
    if "isolation_forest" not in MODELS or "xgboost" not in MODELS:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML models not fully initialized."
        )

    try:
        # 1. Feature Alignment
        df_input = construct_feature_vector(payload.features)

        # 2. Stage 1: Isolation Forest (Zero-Day Anomaly Detection)
        iso_forest: IsolationForest = MODELS["isolation_forest"]
        iso_pred = int(iso_forest.predict(df_input)[0])  # -1 = anomaly, 1 = normal
        anomaly_score = float(iso_forest.decision_function(df_input)[0])
        is_anomaly = (iso_pred == -1)

        # 3. Stage 2: XGBoost Classifier (Known Attack Classification)
        xgb_clf = MODELS["xgboost"]
        xgb_probs = xgb_clf.predict_proba(df_input)[0]
        attack_prob = float(xgb_probs[1])
        xgb_pred = int(xgb_clf.predict(df_input)[0])  # 0 = normal, 1 = malicious

        # 4. Hybrid Zero-Day Decision Matrix
        if is_anomaly and xgb_pred == 0:
            # Outlier flagged by Isolation Forest that is NOT a known pattern in supervised dataset!
            status_label = "Anomaly"
            threat_category = "Zero-Day Threat"
            verdict = "Zero-Day Attack Detected (Unsupervised Outlier Signature)"
            alert_level = "CRITICAL"
        elif is_anomaly and xgb_pred == 1:
            status_label = "Anomaly"
            threat_category = "Known Attack"
            verdict = "High-Confidence Known Malicious Attack"
            alert_level = "CRITICAL" if attack_prob > 0.90 else "HIGH"
        elif not is_anomaly and xgb_pred == 1:
            status_label = "Anomaly"
            threat_category = "Known Attack"
            verdict = "Supervised Classifier Signature Match"
            alert_level = "MEDIUM"
        else:
            status_label = "Normal"
            threat_category = "Normal Traffic"
            verdict = "Normal Network Traffic (Benign Flow Verified)"
            alert_level = "LOW"

        # 5. Stage 3: Explainability with SHAP
        explainer: shap.TreeExplainer = MODELS["shap_explainer"]
        shap_explanation = extract_shap_explanation(explainer, df_input)

        import datetime
        response = PredictionResponse(
            status=status_label,
            threat_category=threat_category,
            verdict=verdict,
            alert_level=alert_level,
            isolation_forest_anomaly=is_anomaly,
            anomaly_score=round(anomaly_score, 4),
            xgboost_prediction="Malicious" if xgb_pred == 1 else "Normal",
            attack_probability=round(attack_prob, 4),
            shap_explanation=shap_explanation,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )

        logger.info(
            "Verdict: [%s - %s] (Anomaly Score: %.3f, Attack Prob: %.2f%%)",
            response.alert_level, response.threat_category, anomaly_score, attack_prob * 100
        )
        return response

    except Exception as e:
        logger.error("Inference failed: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing hybrid inference pipeline: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    logger.info("Starting FastAPI ML Microservice on http://0.0.0.0:%d", port)
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
