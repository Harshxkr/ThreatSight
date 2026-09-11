import pandas as pd
import joblib

from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ============================================================
# THREATSIGHT - NLP PHISHING DETECTOR TRAINING
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = PROJECT_ROOT / "data" / "phishing_messages.csv"

MODEL_DIR = PROJECT_ROOT / "backend" / "ml" / "models"

VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.joblib"
MODEL_PATH = MODEL_DIR / "phishing_model.joblib"


def load_and_clean_dataset():

    print("=" * 60)
    print("THREATSIGHT - NLP PHISHING DETECTOR TRAINING")
    print("=" * 60)

    print("\nLoading dataset:")
    print(DATASET_PATH)

    df = pd.read_csv(DATASET_PATH)

    print(f"\nOriginal rows: {len(df):,}")

    # Keep required columns
    df = df[["body", "label"]]

    # Remove missing bodies
    df = df.dropna(subset=["body"])

    # Convert text to string
    df["body"] = df["body"].astype(str)

    # Remove whitespace
    df["body"] = df["body"].str.strip()

    # Remove empty messages
    df = df[df["body"] != ""]

    # Remove duplicate emails
    df = df.drop_duplicates(subset=["body"])

    # Convert labels to integer
    df["label"] = df["label"].astype(int)

    print(f"Clean rows: {len(df):,}")

    print("\nLabel distribution:")
    print(df["label"].value_counts())

    return df


def train_model():

    # --------------------------------------------------------
    # 1. Load and clean dataset
    # --------------------------------------------------------

    df = load_and_clean_dataset()

    X = df["body"]
    y = df["label"]

    # --------------------------------------------------------
    # 2. Split dataset
    # --------------------------------------------------------

    print("\nSplitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples:  {len(X_test):,}")

    # --------------------------------------------------------
    # 3. Convert text into TF-IDF features
    # --------------------------------------------------------

    print("\nCreating TF-IDF features...")

    vectorizer = TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        sublinear_tf=True,
        max_features=100000
    )

    X_train_tfidf = vectorizer.fit_transform(X_train)

    X_test_tfidf = vectorizer.transform(X_test)

    print(f"TF-IDF training matrix: {X_train_tfidf.shape}")
    print(f"TF-IDF testing matrix:  {X_test_tfidf.shape}")

    # --------------------------------------------------------
    # 4. Train Logistic Regression
    # --------------------------------------------------------

    print("\nTraining Logistic Regression model...")

    model = LogisticRegression(
        max_iter=1000,
        random_state=42
    )

    model.fit(X_train_tfidf, y_train)

    print("Training complete!")

    # --------------------------------------------------------
    # 5. Evaluate model
    # --------------------------------------------------------

    print("\nEvaluating model...")

    y_pred = model.predict(X_test_tfidf)

    accuracy = accuracy_score(y_test, y_pred)

    print("\n" + "=" * 60)
    print("MODEL RESULTS")
    print("=" * 60)

    print(f"\nAccuracy: {accuracy * 100:.2f}%")

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        y_pred,
        target_names=["Legitimate", "Phishing"]
    ))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # --------------------------------------------------------
    # 6. Save model
    # --------------------------------------------------------

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(model, MODEL_PATH)

    print("\nModels saved successfully!")

    print(f"\nVectorizer:")
    print(VECTORIZER_PATH)

    print(f"\nModel:")
    print(MODEL_PATH)

    print("\nTraining finished successfully!")


if __name__ == "__main__":
    train_model()