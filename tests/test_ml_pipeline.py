import pandas as pd
import torch
import pytest
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from train_upgraded import extract_features_chunk


def test_csv_loading():
    df = pd.read_csv('models/positive_hits_features.csv', nrows=5)
    assert 'priv_hex' in df.columns
    assert len(df) <= 5


def test_feature_extraction():
    sample = pd.DataFrame({
        'priv_hex': ['1'*64],
        'wif': ['K'*52],
        'address': ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'],
        'score': [0.0],
    })
    X_chunk, y_chunk, warnings = extract_features_chunk((sample, 'Chunk1'))
    assert X_chunk.shape[0] == 1


def test_model_prediction():
    try:
        model = torch.jit.load('models/best_model.pt')
    except Exception:
        pytest.skip('model file missing or invalid')
    model.eval()
    try:
        in_dim = model.layers._modules['0'].weight.shape[1]
    except Exception:
        in_dim = 29
    dummy = torch.zeros(1, in_dim)
    with torch.no_grad():
        out = model(dummy)
    assert out.numel() == 1
