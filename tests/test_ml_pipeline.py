import pytest
try:
    import numpy as np
except Exception:
    np = None
try:
    import pandas as pd
except Exception:
    pd = None
try:
    import torch
except Exception:
    torch = None
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

try:
    from train_upgraded import extract_features_chunk
except Exception:
    extract_features_chunk = None
try:
    from ml_extra import extract_features, linear_regression
except Exception:
    extract_features = None
    linear_regression = None


def test_csv_loading():
    if pd is None:
        pytest.skip('pandas not available')
    df = pd.read_csv('tests/sample_features.csv')
    assert 'priv_hex' in df.columns
    assert len(df) > 0


def test_feature_extraction():
    if pd is None or extract_features_chunk is None:
        pytest.skip('dependencies not available')
    sample = pd.DataFrame({
        'priv_hex': ['1'*64],
        'wif': ['K'*52],
        'address': ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'],
        'score': [0.0],
    })
    X_chunk, y_chunk, warnings = extract_features_chunk((sample, 'Chunk1'))
    assert X_chunk.shape[0] == 1

def test_extra_feature_functions():
    if np is None or extract_features is None or linear_regression is None:
        pytest.skip('ml_extra not available')
    feats = extract_features('1'*64)
    assert feats.shape[0] > 0
    model = linear_regression(np.arange(5), np.arange(5))
    pred = model.predict([[6]])
    assert pred.shape[0] == 1


def test_model_prediction():
    if torch is None:
        pytest.skip('torch not available')
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
