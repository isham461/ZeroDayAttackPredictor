"""
NSL-KDD Dataset Preprocessing Pipeline
======================================
Module for loading, cleaning, encoding, and scaling the NSL-KDD dataset
for the Zero-Day Network Attack Detection Machine Learning Framework.
"""

import os
import sys
import logging
from typing import List, Tuple, Optional
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Standard 43 column names for the raw NSL-KDD dataset (41 features + label + difficulty)
NSL_KDD_COLUMNS: List[str] = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "attack_type", "difficulty_level"
]

# Categorical text-based columns that require encoding
CATEGORICAL_COLUMNS: List[str] = ["protocol_type", "service", "flag"]

# Target label / metadata columns
NON_FEATURE_COLUMNS: List[str] = ["attack_type", "difficulty_level"]


class NSLKDDPreprocessor:
    """
    Handles end-to-end preprocessing for NSL-KDD intrusion detection data.
    """

    def __init__(
        self,
        column_names: Optional[List[str]] = None,
        categorical_cols: Optional[List[str]] = None,
        drop_difficulty: bool = False
    ) -> None:
        """
        Initialize the preprocessor.

        :param column_names: Full list of 43 column names. Defaults to NSL_KDD_COLUMNS.
        :param categorical_cols: Categorical columns to encode. Defaults to CATEGORICAL_COLUMNS.
        :param drop_difficulty: Whether to drop the difficulty_level column from the output.
        """
        self.column_names = column_names or NSL_KDD_COLUMNS
        self.categorical_cols = categorical_cols or CATEGORICAL_COLUMNS
        self.drop_difficulty = drop_difficulty
        self.scaler = StandardScaler()

    def load_data(self, file_path: str) -> pd.DataFrame:
        """
        Load raw NSL-KDD data file and assign the 43 standard column headers.

        :param file_path: Path to the raw KDDTrain+.txt / KDDTest+.txt dataset file.
        :return: Loaded pandas DataFrame with assigned headers.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset file not found at: '{file_path}'")

        if os.path.getsize(file_path) == 0:
            raise ValueError(f"Dataset file '{file_path}' is empty.")

        logger.info("Loading dataset from '%s'...", file_path)
        try:
            # NSL-KDD is comma-separated without a header line
            df = pd.read_csv(file_path, names=self.column_names, header=None)
            logger.info("Dataset loaded successfully with shape: %s", df.shape)
            return df
        except Exception as e:
            logger.error("Failed to read dataset: %s", e)
            raise RuntimeError(f"Error loading dataset from '{file_path}': {e}") from e

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Perform basic validation, handle missing/duplicate values, and column pruning.

        :param df: Input DataFrame.
        :return: Cleaned DataFrame.
        """
        logger.info("Cleaning data and validating missing values...")
        df_clean = df.copy()

        # Check and report missing values
        null_counts = df_clean.isnull().sum().sum()
        if null_counts > 0:
            logger.warning("Found %d null values. Dropping rows with nulls...", null_counts)
            df_clean = df_clean.dropna()
        else:
            logger.info("No missing values detected.")

        # Check and remove duplicates if any
        duplicates = df_clean.duplicated().sum()
        if duplicates > 0:
            logger.info("Removing %d duplicate rows.", duplicates)
            df_clean = df_clean.drop_duplicates().reset_index(drop=True)

        if self.drop_difficulty and "difficulty_level" in df_clean.columns:
            logger.info("Dropping 'difficulty_level' column.")
            df_clean = df_clean.drop(columns=["difficulty_level"])

        return df_clean

    def encode_categorical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Encode text-based categorical columns using one-hot encoding.

        :param df: DataFrame containing categorical columns.
        :return: DataFrame with one-hot encoded features.
        """
        logger.info("Encoding categorical features: %s", self.categorical_cols)

        missing_cats = [col for col in self.categorical_cols if col not in df.columns]
        if missing_cats:
            raise KeyError(f"Categorical column(s) not found in DataFrame: {missing_cats}")

        # One-hot encode categorical features (protocol_type, service, flag)
        df_encoded = pd.get_dummies(df, columns=self.categorical_cols, drop_first=False, dtype=int)
        logger.info("Shape after categorical encoding: %s", df_encoded.shape)
        return df_encoded

    def scale_numerical_features(
        self,
        df: pd.DataFrame,
        target_cols: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Scale numerical features using StandardScaler while preserving labels/metadata.

        :param df: DataFrame with encoded features.
        :param target_cols: Columns to exclude from scaling (e.g. attack_type).
        :return: DataFrame with scaled numerical features.
        """
        logger.info("Scaling numerical features with StandardScaler...")
        df_scaled = df.copy()

        targets = target_cols or [col for col in NON_FEATURE_COLUMNS if col in df_scaled.columns]

        # Identify numerical columns (excluding targets)
        numerical_cols = [
            col for col in df_scaled.select_dtypes(include=[np.number]).columns
            if col not in targets
        ]

        if not numerical_cols:
            logger.warning("No numerical columns found to scale.")
            return df_scaled

        logger.info("Scaling %d numerical columns...", len(numerical_cols))
        df_scaled[numerical_cols] = self.scaler.fit_transform(df_scaled[numerical_cols])

        return df_scaled

    def process(self, input_file_path: str, output_file_path: str) -> pd.DataFrame:
        """
        Execute full preprocessing pipeline from raw file to saved CSV.

        :param input_file_path: Path to 'KDDTrain+.txt'.
        :param output_file_path: Path to save 'cleaned_nsl_kdd.csv'.
        :return: Processed DataFrame.
        """
        logger.info("Starting Phase 1 NSL-KDD Preprocessing Pipeline...")

        # 1. Load Data with standard 43 columns
        df_raw = self.load_data(input_file_path)

        # 2. Clean and handle nulls/duplicates
        df_clean = self.clean_data(df_raw)

        # 3. Encode categorical columns
        df_encoded = self.encode_categorical_features(df_clean)

        # 4. Scale numerical columns with StandardScaler
        df_processed = self.scale_numerical_features(df_encoded)

        # 5. Save to destination
        self.save_processed_data(df_processed, output_file_path)

        logger.info("Preprocessing complete! Final DataFrame shape: %s", df_processed.shape)
        return df_processed

    def save_processed_data(self, df: pd.DataFrame, output_path: str) -> None:
        """
        Export processed DataFrame to CSV.

        :param df: Processed DataFrame.
        :param output_path: Destination file path.
        """
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            logger.info("Creating output directory: '%s'", output_dir)
            os.makedirs(output_dir, exist_ok=True)

        logger.info("Saving cleaned dataset to '%s'...", output_path)
        try:
            df.to_csv(output_path, index=False)
            logger.info("Successfully saved %d rows to '%s'", len(df), output_path)
        except Exception as e:
            logger.error("Failed to save processed data: %s", e)
            raise IOError(f"Could not save file to '{output_path}': {e}") from e


def main() -> None:
    """CLI entry point for running data preprocessing."""
    input_file = os.getenv("NSL_KDD_TRAIN_PATH", "KDDTrain+.txt")
    output_file = os.getenv("NSL_KDD_OUTPUT_PATH", "cleaned_nsl_kdd.csv")

    logger.info("Input file:  %s", input_file)
    logger.info("Output file: %s", output_file)

    preprocessor = NSLKDDPreprocessor(drop_difficulty=False)

    try:
        preprocessor.process(input_file_path=input_file, output_file_path=output_file)
    except FileNotFoundError as e:
        logger.error("File error: %s", e)
        logger.error("Please ensure '%s' exists in the current directory or set the NSL_KDD_TRAIN_PATH environment variable.", input_file)
        sys.exit(1)
    except Exception as e:
        logger.error("An unexpected error occurred during preprocessing: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
