import pandas as pd
import random
import os

IN_CSV = "models/positive_hits_features.csv"
OUT_CSV = "models/positive_hits_features_augmented.csv"

if not os.path.exists(IN_CSV):
    print(f"Arquivo {IN_CSV} nao encontrado")
    raise SystemExit(1)

df = pd.read_csv(IN_CSV)

mut_rows = []
for _, row in df.iterrows():
    try:
        val = int(str(row['priv_hex']), 16)
    except Exception:
        continue
    for _ in range(3):
        bit = random.randint(0, 10)
        new_val = val ^ (1 << bit)
        new_row = row.copy()
        new_row['priv_hex'] = f"{new_val:064x}"
        mut_rows.append(new_row)

if mut_rows:
    df_aug = pd.concat([df, pd.DataFrame(mut_rows)], ignore_index=True)
else:
    df_aug = df.copy()

df_aug.to_csv(OUT_CSV, index=False)
print(f"{len(df_aug)} entradas salvas em {OUT_CSV}")
