"""
Hybrid ML Model Training Pipeline for Zero-Day Network Attack Detection
=======================================================================
Phase 2: Trains an Unsupervised Anomaly Detector (Isolation Forest),
a Supervised Classifier (XGBoost), generates SHAP explainability artifacts,
and exports all serialized models for FastAPI inference (Phase 3).
"""

import os
import sys
import json
import logging
from typing import Tuple, Dict, Any, Optional
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless server execution
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)
import xgboost as xgb
import shap

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class HybridModelTrainer:
    """
    Manages the data splitting, model training (Isolation Forest & XGBoost),
    SHAP explainability generation, and model artifact exports.
    """

    def __init__(
        self,
        data_path: str = "cleaned_nsl_kdd.csv",
        models_dir: str = "models",
        random_state: int = 42
    ) -> None:
        """
        Initialize the model trainer.

        :param data_path: Path to the preprocessed NSL-KDD dataset.
        :param models_dir: Destination directory for exported models.
        :param random_state: Seed for reproducibility.
        """
        self.data_path = data_path
        self.models_dir = models_dir
        self.random_state = random_state

        self.isolation_forest: Optional[IsolationForest] = None
        self.xgb_model: Optional[xgb.XGBClassifier] = None
        self.shap_explainer: Optional[shap.TreeExplainer] = None
        self.feature_names: list[str] = []

    def load_and_split_data(
        self,
        test_size: float = 0.2
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
        """
        Load cleaned dataset, separate features from label, and split into train/test sets.

        :param test_size: Proportion of data to include in test split (default 0.2).
        :return: (X_train, X_test, y_train, y_test)
        """
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"Cleaned dataset not found at: '{self.data_path}'")

        logger.info("Loading cleaned dataset from '%s'...", self.data_path)
        df = pd.read_csv(self.data_path)
        logger.info("Loaded dataset with shape: %s", df.shape)

        if "attack_type" not in df.columns:
            raise KeyError("Target column 'attack_type' missing from dataset.")

        # Binary classification target: 0 = Normal, 1 = Attack (Malicious)
        logger.info("Mapping target labels to binary (0 = Normal, 1 = Malicious/Attack)...")
        y = (df["attack_type"] != "normal").astype(int)

        # Drop non-feature columns
        cols_to_drop = ["attack_type"]
        if "difficulty_level" in df.columns:
            cols_to_drop.append("difficulty_level")

        X = df.drop(columns=cols_to_drop)
        self.feature_names = X.columns.tolist()
        logger.info("Features count: %d. Total samples: %d", len(self.feature_names), len(X))

        # Stratified train-test split (80/20)
        logger.info("Splitting data into 80%% train and 20%% test (stratified)...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=self.random_state, stratify=y
        )

        logger.info("X_train shape: %s, X_test shape: %s", X_train.shape, X_test.shape)
        logger.info(
            "Train class balance: Normal=%d (%.1f%%), Malicious=%d (%.1f%%)",
            (y_train == 0).sum(), (y_train == 0).mean() * 100,
            (y_train == 1).sum(), (y_train == 1).mean() * 100
        )
        return X_train, X_test, y_train, y_test

    def train_isolation_forest(
        self,
        X_train: pd.DataFrame,
        X_test: pd.DataFrame,
        contamination: float = 0.1,
        n_estimators: int = 100
    ) -> IsolationForest:
        """
        Stage 1: Train unsupervised Isolation Forest on features to detect zero-day/anomalous traffic.

        :param X_train: Training features (without labels).
        :param X_test: Testing features.
        :param contamination: Expected proportion of outliers in the data.
        :param n_estimators: Number of isolation trees.
        :return: Trained IsolationForest instance.
        """
        logger.info("=" * 60)
        logger.info("Stage 1: Training Isolation Forest (Zero-Day Threat Detector)...")
        logger.info("=" * 60)

        iso_forest = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=self.random_state,
            n_jobs=-1
        )

        logger.info("Fitting Isolation Forest on %d training samples...", len(X_train))
        iso_forest.fit(X_train)
        self.isolation_forest = iso_forest

        # Predictions on test set: 1 for normal, -1 for anomaly
        logger.info("Predicting anomalies on test set...")
        iso_preds = iso_forest.predict(X_test)
        anomalies_detected = (iso_preds == -1).sum()
        normal_detected = (iso_preds == 1).sum()

        logger.info(
            "Isolation Forest Results on Test Set: Normal=%d (%.2f%%), Anomalies/Zero-Day Candidates=%d (%.2f%%)",
            normal_detected, (normal_detected / len(X_test)) * 100,
            anomalies_detected, (anomalies_detected / len(X_test)) * 100
        )
        return iso_forest

    def train_xgboost(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_test: pd.DataFrame,
        y_test: pd.Series,
        n_estimators: int = 150,
        max_depth: int = 6,
        learning_rate: float = 0.1
    ) -> xgb.XGBClassifier:
        """
        Stage 2: Train supervised XGBoost Classifier for known attack vs normal classification.

        :param X_train: Training features.
        :param y_train: Training binary labels.
        :param X_test: Testing features.
        :param y_test: Testing binary labels.
        :param n_estimators: Number of gradient boosted trees.
        :param max_depth: Maximum tree depth.
        :param learning_rate: Boosting learning rate.
        :return: Trained XGBClassifier instance.
        """
        logger.info("=" * 60)
        logger.info("Stage 2: Training XGBoost Classifier (Known Attack Detector)...")
        logger.info("=" * 60)

        xgb_clf = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            eval_metric="logloss",
            random_state=self.random_state,
            n_jobs=-1,
            tree_method="hist"  # Fast histogram-based tree building with low memory footprint
        )

        logger.info("Fitting XGBoost Classifier on %d samples...", len(X_train))
        xgb_clf.fit(X_train, y_train)
        self.xgb_model = xgb_clf

        # Evaluation on test set
        logger.info("Evaluating XGBoost model on test set (%d samples)...", len(X_test))
        y_pred = xgb_clf.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        print("\n" + "=" * 60)
        print("           XGBOOST CLASSIFICATION PERFORMANCE")
        print("=" * 60)
        print(f"  Accuracy  : {acc * 100:.2f}%")
        print(f"  Precision : {prec * 100:.2f}%")
        print(f"  Recall    : {rec * 100:.2f}%")
        print(f"  F1-Score  : {f1 * 100:.2f}%")
        print("-" * 60)
        print("Confusion Matrix:")
        print(f"  [TN={cm[0][0]:<5} FP={cm[0][1]:<5}]")
        print(f"  [FN={cm[1][0]:<5} TP={cm[1][1]:<5}]")
        print("-" * 60)
        print("Full Classification Report:")
        print(classification_report(y_test, y_pred, target_names=["Normal (0)", "Malicious (1)"], digits=4))
        print("=" * 60 + "\n")

        return xgb_clf

    def explain_with_shap(
        self,
        X_test: pd.DataFrame,
        sample_size: int = 1500,
        output_plot_filename: str = "shap_summary_plot.png"
    ) -> shap.TreeExplainer:
        """
        Explainability: Compute SHAP values for the XGBoost model and save a summary plot.
        Handles memory efficiently by subsampling representative test instances.

        :param X_test: Test features.
        :param sample_size: Number of samples to use for SHAP calculation to prevent memory spikes.
        :param output_plot_filename: Name of the output image file.
        :return: Initialized TreeExplainer instance.
        """
        if self.xgb_model is None:
            raise ValueError("XGBoost model must be trained before computing SHAP values.")

        logger.info("=" * 60)
        logger.info("Explainability: Initializing SHAP TreeExplainer...")
        logger.info("=" * 60)

        # Initialize TreeExplainer for the XGBoost model
        explainer = shap.TreeExplainer(self.xgb_model)
        self.shap_explainer = explainer

        # Subsample test set if larger than sample_size to prevent memory bloat
        if len(X_test) > sample_size:
            logger.info("Subsampling %d instances from test set for memory-efficient SHAP calculation...", sample_size)
            X_shap_sample = X_test.sample(n=sample_size, random_state=self.random_state)
        else:
            X_shap_sample = X_test

        logger.info("Calculating SHAP values...")
        shap_values = explainer(X_shap_sample)

        # Ensure destination directory exists
        os.makedirs(self.models_dir, exist_ok=True)
        plot_path = os.path.join(self.models_dir, output_plot_filename)

        logger.info("Generating and saving SHAP summary plot to '%s'...", plot_path)
        plt.figure(figsize=(12, 8))
        shap.summary_plot(shap_values, X_shap_sample, show=False, max_display=20)
        plt.title("SHAP Feature Importance Summary (XGBoost Attack Classifier)", fontsize=14, pad=15)
        plt.tight_layout()
        plt.savefig(plot_path, dpi=300, bbox_inches="tight")
        plt.close()

        logger.info("SHAP summary plot successfully saved to '%s'", plot_path)
        return explainer

    def export_models(self) -> Dict[str, str]:
        """
        Serialize and export trained models, explainer, and feature schema to the models directory.

        :return: Dictionary of saved file paths.
        """
        logger.info("=" * 60)
        logger.info("Model Export: Saving artifacts for Phase 3 API...")
        logger.info("=" * 60)

        os.makedirs(self.models_dir, exist_ok=True)
        saved_paths = {}

        # 1. Export Isolation Forest
        if self.isolation_forest is not None:
            iso_path = os.path.join(self.models_dir, "isolation_forest.joblib")
            joblib.dump(self.isolation_forest, iso_path)
            saved_paths["isolation_forest"] = iso_path
            logger.info("Saved Isolation Forest to: '%s'", iso_path)

        # 2. Export XGBoost Model
        if self.xgb_model is not None:
            xgb_path = os.path.join(self.models_dir, "xgboost_model.joblib")
            joblib.dump(self.xgb_model, xgb_path)
            saved_paths["xgboost_model"] = xgb_path
            logger.info("Saved XGBoost Model to: '%s'", xgb_path)

        # 3. Export SHAP Explainer
        if self.shap_explainer is not None:
            shap_path = os.path.join(self.models_dir, "shap_explainer.joblib")
            joblib.dump(self.shap_explainer, shap_path)
            saved_paths["shap_explainer"] = shap_path
            logger.info("Saved SHAP Explainer to: '%s'", shap_path)

        # 4. Export Feature Schema Metadata
        metadata = {
            "feature_names": self.feature_names,
            "num_features": len(self.feature_names),
            "label_encoding": {"0": "Normal", "1": "Malicious/Attack"},
            "anomaly_encoding": {"1": "Normal", "-1": "Zero-Day Anomaly Candidate"}
        }
        metadata_path = os.path.join(self.models_dir, "metadata.json")
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=4)
        saved_paths["metadata"] = metadata_path
        logger.info("Saved Feature Metadata to: '%s'", metadata_path)

        logger.info("All artifacts successfully saved to '%s/'", self.models_dir)
        return saved_paths

    def run_pipeline(self) -> Dict[str, str]:
        """
        Execute full training, explainability, and export pipeline.

        :return: Dictionary of exported artifact paths.
        """
        logger.info("Starting Phase 2 Hybrid ML Training Pipeline...")

        # 1. Data loading & splitting
        X_train, X_test, y_train, y_test = self.load_and_split_data(test_size=0.2)

        # 2. Stage 1 - Isolation Forest Anomaly Detection
        self.train_isolation_forest(X_train, X_test)

        # 3. Stage 2 - XGBoost Attack Classification
        self.train_xgboost(X_train, y_train, X_test, y_test)

        # 4. Explainability with SHAP
        self.explain_with_shap(X_test)

        # 5. Model Export
        saved_paths = self.export_models()

        logger.info("Phase 2 Model Training completed successfully!")
        return saved_paths


def main() -> None:
    """CLI entry point for Phase 2 training."""
    data_file = os.getenv("CLEANED_DATA_PATH", "cleaned_nsl_kdd.csv")
    models_directory = os.getenv("MODELS_DIR", "models")

    trainer = HybridModelTrainer(
        data_path=data_file,
        models_dir=models_directory,
        random_state=42
    )

    try:
        trainer.run_pipeline()
    except FileNotFoundError as e:
        logger.error("Dataset not found: %s", e)
        logger.error("Ensure Phase 1 preprocessing has produced '%s'.", data_file)
        sys.exit(1)
    except Exception as e:
        logger.error("An error occurred during training: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
