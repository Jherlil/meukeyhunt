import os
import time
import subprocess

def should_retrain(pos_path, neg_path, min_count=100):
    count = 0
    if os.path.exists(pos_path):
        with open(pos_path) as f:
            count += sum(1 for _ in f) - 1
    if os.path.exists(neg_path):
        with open(neg_path) as f:
            count += sum(1 for _ in f) - 1
    return count >= min_count

if __name__ == "__main__":
    POS = "models/positive_hits_features.csv"
    NEG = "models/negative_hits_features.csv"
    while True:
        if should_retrain(POS, NEG):
            print("[AutoTrain] Executando novo treinamento...")
            subprocess.run(["python3", "train.py"])
        else:
            print("[AutoTrain] Aguardando dados suficientes para re-treinar...")
        time.sleep(300)
