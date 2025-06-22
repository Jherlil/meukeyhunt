import pandas as pd
import torch
from train_upgraded import extract_features_chunk


def test_csv_loading():
    df = pd.read_csv('models/positive_hits_features.csv', nrows=5)
    assert 'priv_hex' in df.columns
    assert len(df) <= 5


def test_feature_extraction():
    sample = pd.DataFrame({'priv_hex': ['1'*64], 'wif': ['K'*52], 'address': ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa']})
    feats = extract_features_chunk((sample, 'Chunk1'))
    assert not feats.empty


def test_model_prediction():
    model = torch.jit.load('models/best_model.pt')
    model.eval()
    dummy = torch.zeros(1, 29)
    with torch.no_grad():
        out = model(dummy)
    assert out.numel() == 1
