import pandas as pd
from pathlib import Path


# Find the project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Dataset location
DATASET_PATH = PROJECT_ROOT / "data" / "phishing_messages.csv"


def main():
    print("=" * 60)
    print("THREATSIGHT - DATASET INSPECTION")
    print("=" * 60)

    print(f"\nDataset path:")
    print(DATASET_PATH)

    # Check that the file exists
    if not DATASET_PATH.exists():
        print("\nERROR: Dataset file was not found.")
        print(f"Expected location: {DATASET_PATH}")
        return

    # Load dataset
    df = pd.read_csv(DATASET_PATH)

    print("\nDataset loaded successfully!")

    # Basic information
    print("\n--- Shape ---")
    print(f"Rows:    {df.shape[0]}")
    print(f"Columns: {df.shape[1]}")

    print("\n--- Columns ---")
    print(df.columns.tolist())

    # First few rows
    print("\n--- First 5 rows ---")
    print(df.head())

    # Missing values
    print("\n--- Missing values ---")
    print(df.isnull().sum())

    # Label distribution
    if "label" in df.columns:
        print("\n--- Label distribution ---")
        print(df["label"].value_counts())

        print("\n--- Label percentages ---")
        print(df["label"].value_counts(normalize=True) * 100)

    # Duplicate rows
    print("\n--- Duplicate rows ---")
    print(df.duplicated().sum())

    # Empty text
    if "body" in df.columns:
        empty_text = df["body"].isna().sum()
        print("\n--- Empty body values ---")
        print(empty_text)


if __name__ == "__main__":
    main()