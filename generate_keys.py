import os
import pandas as pd
from tqdm import tqdm

CSV_PATH = "models/positive_hits_features.csv"
OUTPUT_FILE = "generated_keys.txt"
SCORE_COLUMN = "score"
PRIV_COLUMN = "priv_hex"
THRESHOLD = 0.9  # top 10% por default


def read_csv_multithread(path: str) -> pd.DataFrame:
    """Read CSV using pyarrow engine if available for multi-threading."""
    try:
        return pd.read_csv(
            path,
            engine="pyarrow",
            use_threads=True,
        )
    except Exception:
        return pd.read_csv(path)


if __name__ == "__main__":
    if not os.path.exists(CSV_PATH):
        print(f"Arquivo {CSV_PATH} não encontrado.")
        exit(1)

    df = read_csv_multithread(CSV_PATH)
    if SCORE_COLUMN not in df.columns or PRIV_COLUMN not in df.columns:
        print("Colunas esperadas nao encontradas no CSV.")
        exit(1)

    threshold_value = df[SCORE_COLUMN].quantile(THRESHOLD)
    candidates = df[df[SCORE_COLUMN] >= threshold_value][PRIV_COLUMN].dropna().unique()

    with open(OUTPUT_FILE, "w") as f:
        for key in tqdm(candidates, desc="Salvando chaves"):
            f.write(f"{key}\n")

    print(f"{len(candidates)} chaves salvas em {OUTPUT_FILE}")

