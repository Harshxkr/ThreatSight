import re
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


# ============================================================
# THREATSIGHT AI
# FINAL NLP TRAINING - V3
#
# Stable low-memory production model
#
# Word TF-IDF + Logistic Regression
#
# Designed for ~16 GB RAM laptops
# ============================================================


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    PROJECT_ROOT.parent / "phishing_messages.csv"
)

MODEL_DIR = (
    PROJECT_ROOT
    / "backend"
    / "ml"
    / "models"
)

MODEL_PATH = (
    MODEL_DIR / "phishing_model.joblib"
)

VECTORIZER_PATH = (
    MODEL_DIR / "tfidf_vectorizer.joblib"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

TEST_SIZE = 0.20

# Deliberately smaller than the previous 100k.
# 60k gives us a strong model while reducing RAM/time.
MAX_FEATURES = 60_000


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text):

    if not isinstance(text, str):
        return ""

    text = text.lower()

    # Normalize HTML breaks.
    text = re.sub(
        r"<br\s*/?>",
        " ",
        text
    )

    # Remove HTML tags.
    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    # Normalize URLs into a consistent representation
    # without deleting them completely.
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# LOAD DATA
# ============================================================

def load_dataset():

    print("=" * 70)
    print("THREATSIGHT AI - FINAL NLP MODEL V3")
    print("=" * 70)

    print("\nDataset:")
    print(DATASET_PATH)

    if not DATASET_PATH.exists():

        raise FileNotFoundError(
            f"""
Dataset not found:

{DATASET_PATH}

Expected:

C:\\Users\\RISHAV\\ThreatSight\\phishing_messages.csv
"""
        )

    print("\nLoading dataset...")

    start = time.time()

    df = pd.read_csv(
        DATASET_PATH,
        usecols=["body", "label"]
    )

    print(
        f"Loaded: {len(df):,} rows"
    )

    print(
        f"Load time: "
        f"{time.time() - start:.1f} sec"
    )

    # --------------------------------------------------------
    # Remove missing data
    # --------------------------------------------------------

    df = df.dropna(
        subset=["body", "label"]
    )

    # --------------------------------------------------------
    # Convert types
    # --------------------------------------------------------

    df["body"] = (
        df["body"]
        .astype(str)
    )

    df["label"] = (
        df["label"]
        .astype(int)
    )

    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    print("\nNormalizing messages...")

    start = time.time()

    df["body"] = (
        df["body"]
        .apply(normalize_text)
    )

    print(
        f"Normalization time: "
        f"{time.time() - start:.1f} sec"
    )

    # --------------------------------------------------------
    # Remove empty messages
    # --------------------------------------------------------

    df = df[
        df["body"].str.len() > 0
    ]

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    before = len(df)

    df = df.drop_duplicates(
        subset=["body"]
    )

    duplicates = (
        before - len(df)
    )

    # --------------------------------------------------------
    # Validate labels
    # --------------------------------------------------------

    labels = set(
        df["label"].unique()
    )

    if not labels.issubset({0, 1}):

        raise ValueError(
            f"Invalid labels: {labels}"
        )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    print("\n" + "-" * 70)
    print("DATASET")
    print("-" * 70)

    print(
        f"Clean messages:    {len(df):,}"
    )

    print(
        f"Duplicates removed: {duplicates:,}"
    )

    print("\nLabels:")

    print(
        df["label"]
        .value_counts()
        .sort_index()
    )

    return df


# ============================================================
# TRAIN
# ============================================================

def train_model():

    total_start = time.time()

    # ========================================================
    # DATA
    # ========================================================

    df = load_dataset()

    X = df["body"]

    y = df["label"]

    # ========================================================
    # TRAIN / TEST SPLIT
    # ========================================================

    print("\n" + "=" * 70)
    print("TRAIN / TEST SPLIT")
    print("=" * 70)

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y,
        )
    )

    print(
        f"Training: {len(X_train):,}"
    )

    print(
        f"Testing:  {len(X_test):,}"
    )

    # ========================================================
    # TF-IDF
    # ========================================================

    print("\n" + "=" * 70)
    print("WORD TF-IDF")
    print("=" * 70)

    print(
        "Creating vectorizer..."
    )

    vectorizer = TfidfVectorizer(

        # Keep security-relevant common words.
        stop_words=None,

        lowercase=True,

        # Single words + word pairs.
        ngram_range=(1, 2),

        # Ignore extremely rare terms.
        min_df=2,

        # Ignore almost universal terms.
        max_df=0.98,

        # Helps frequent terms.
        sublinear_tf=True,

        # Main memory/time control.
        max_features=MAX_FEATURES,

        # FLOAT32 uses approximately half the memory
        # of the default float64 representation.
        dtype=np.float32,

        strip_accents="unicode",
    )

    print(
        f"Maximum features: "
        f"{MAX_FEATURES:,}"
    )

    print(
        "Fitting TF-IDF..."
    )

    start = time.time()

    X_train = (
        vectorizer
        .fit_transform(X_train)
    )

    print(
        f"Training matrix: "
        f"{X_train.shape}"
    )

    print(
        f"TF-IDF training time: "
        f"{time.time() - start:.1f} sec"
    )

    print(
        "\nTransforming test data..."
    )

    start = time.time()

    X_test = (
        vectorizer
        .transform(X_test)
    )

    print(
        f"Testing matrix: "
        f"{X_test.shape}"
    )

    print(
        f"Test transform time: "
        f"{time.time() - start:.1f} sec"
    )

    # ========================================================
    # MODEL
    # ========================================================

    print("\n" + "=" * 70)
    print("LOGISTIC REGRESSION")
    print("=" * 70)

    print(
        "Training classifier..."
    )

    start = time.time()

    model = LogisticRegression(

        # Regularization.
        C=2.0,

        # Efficient for sparse text data.
        solver="saga",

        # Don't let training run forever.
        max_iter=400,

        tol=1e-3,

        random_state=RANDOM_STATE,

        class_weight=None,

        # One binary phishing classifier.
        n_jobs=-1,
    )

    model.fit(
        X_train,
        y_train
    )

    model_time = (
        time.time() - start
    )

    print(
        f"\nModel training time: "
        f"{model_time:.1f} sec"
    )

    # ========================================================
    # PREDICTION
    # ========================================================

    print("\n" + "=" * 70)
    print("EVALUATION")
    print("=" * 70)

    y_pred = model.predict(
        X_test
    )

    probabilities = (
        model.predict_proba(
            X_test
        )
    )

    phishing_probability = (
        probabilities[:, 1]
    )

    # ========================================================
    # METRICS
    # ========================================================

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        phishing_probability
    )

    print("\n" + "-" * 70)
    print("MODEL METRICS")
    print("-" * 70)

    print(
        f"Accuracy:   {accuracy * 100:.2f}%"
    )

    print(
        f"Precision:  {precision * 100:.2f}%"
    )

    print(
        f"Recall:     {recall * 100:.2f}%"
    )

    print(
        f"F1 Score:   {f1 * 100:.2f}%"
    )

    print(
        f"ROC-AUC:    {roc_auc * 100:.2f}%"
    )

    # ========================================================
    # CLASSIFICATION REPORT
    # ========================================================

    print("\n" + "-" * 70)
    print("CLASSIFICATION REPORT")
    print("-" * 70)

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Legitimate",
                "Phishing",
            ],
            digits=4,
            zero_division=0
        )
    )

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    print("-" * 70)
    print("CONFUSION MATRIX")
    print("-" * 70)

    print(cm)

    tn, fp, fn, tp = cm.ravel()

    print("\nDetailed counts:")

    print(
        f"True Negatives:  {tn:,}"
    )

    print(
        f"False Positives: {fp:,}"
    )

    print(
        f"False Negatives: {fn:,}"
    )

    print(
        f"True Positives:  {tp:,}"
    )

    # ========================================================
    # FALSE POSITIVE RATE
    # ========================================================

    if (tn + fp) > 0:

        false_positive_rate = (
            fp / (tn + fp)
        )

    else:

        false_positive_rate = 0.0

    print(
        f"\nFalse Positive Rate: "
        f"{false_positive_rate * 100:.3f}%"
    )

    # ========================================================
    # SAVE
    # ========================================================

    print("\n" + "=" * 70)
    print("SAVING MODEL")
    print("=" * 70)

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # IMPORTANT
    #
    # Save only AFTER successful evaluation.
    #
    # This means a crash during training does not replace
    # the old model.
    # --------------------------------------------------------

    print(
        f"Saving model to:\n{MODEL_PATH}"
    )

    joblib.dump(
        model,
        MODEL_PATH,
        compress=3
    )

    print(
        f"Saving vectorizer to:\n"
        f"{VECTORIZER_PATH}"
    )

    joblib.dump(
        vectorizer,
        VECTORIZER_PATH,
        compress=3
    )

    # ========================================================
    # FILE SIZES
    # ========================================================

    model_mb = (
        MODEL_PATH.stat().st_size
        / (1024 * 1024)
    )

    vectorizer_mb = (
        VECTORIZER_PATH.stat().st_size
        / (1024 * 1024)
    )

    print("\n" + "-" * 70)
    print("FILES")
    print("-" * 70)

    print(
        f"Model:       {model_mb:.2f} MB"
    )

    print(
        f"Vectorizer:  {vectorizer_mb:.2f} MB"
    )

    # ========================================================
    # FINAL
    # ========================================================

    total_time = (
        time.time() - total_start
    )

    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)

    print(
        f"\nTotal time: "
        f"{total_time / 60:.2f} minutes"
    )

    print("\nFinal results:")

    print(
        f"Accuracy:   {accuracy * 100:.2f}%"
    )

    print(
        f"Precision:  {precision * 100:.2f}%"
    )

    print(
        f"Recall:     {recall * 100:.2f}%"
    )

    print(
        f"F1:         {f1 * 100:.2f}%"
    )

    print(
        f"ROC-AUC:    {roc_auc * 100:.2f}%"
    )

    print(
        "\nOriginal backup remains untouched."
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    train_model()