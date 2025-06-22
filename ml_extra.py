import numpy as np
import hashlib
import math
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
from sklearn.pipeline import make_pipeline
from statistics import median, mode
try:
    from statsmodels.tsa.arima.model import ARIMA
except Exception:
    ARIMA = None
import torch
import torch.nn as nn


# --- Feature extraction utilities ---

def bit_entropy(hex_str: str) -> float:
    if not hex_str:
        return 0.0
    bit_string = bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)
    p1 = bit_string.count('1') / len(bit_string)
    if p1 in (0.0, 1.0):
        return 0.0
    return -(p1 * math.log2(p1) + (1 - p1) * math.log2(1 - p1))

def hamming_weight(hex_str: str) -> int:
    if not hex_str:
        return 0
    return bin(int(hex_str, 16)).count('1')

def hash160_embedding(hex_str: str) -> np.ndarray:
    if not hex_str:
        return np.zeros(16, dtype=np.uint8)
    data = bytes.fromhex(hex_str)
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    return np.frombuffer(ripe[:16], dtype=np.uint8)

def mnemonic_index_vector(words: str, wordlist=None) -> np.ndarray:
    if not words:
        return np.zeros(12, dtype=np.int32)
    wlist = wordlist or []
    result = []
    for w in words.split():
        try:
            idx = wlist.index(w)
        except ValueError:
            idx = -1
        result.append(idx)
    while len(result) < 12:
        result.append(-1)
    return np.array(result[:12], dtype=np.int32)

# --- Numerical sequence utilities ---
def diff_ratio_stats(seq):
    arr = np.asarray(seq, dtype=np.float64)
    if arr.size < 2:
        return {}
    diff = np.diff(arr)
    ratio = np.divide(arr[1:], arr[:-1], out=np.zeros_like(diff), where=arr[:-1]!=0)
    log_diff = np.diff(np.log(arr))
    log2_diff = np.diff(np.log2(arr))
    stats = {
        'diff_mean': float(diff.mean()),
        'diff_std': float(diff.std()),
        'ratio_mean': float(ratio.mean()),
        'ratio_std': float(ratio.std()),
        'log_diff_mean': float(log_diff.mean()),
        'log2_diff_mean': float(log2_diff.mean()),
        'diff_median': float(median(diff)),
        'diff_mode': float(mode(diff)) if len(diff) > 0 else 0.0,
    }
    return stats

def fft_transform(seq):
    arr = np.asarray(seq, dtype=np.float64)
    return np.fft.fft(arr)

def wavelet_transform(seq, wavelet='db1'):
    try:
        import pywt
        arr = np.asarray(seq, dtype=np.float64)
        return pywt.wavedec(arr, wavelet)
    except Exception:
        return []

def extract_features(priv_hex: str, prev_hex: str = None, words: str = "", wordlist=None) -> np.ndarray:
    priv_int = int(priv_hex, 16) if priv_hex else 0
    prev_int = int(prev_hex, 16) if prev_hex else 0
    diff = priv_int - prev_int if prev_hex else 0
    ratio = priv_int / prev_int if prev_hex and prev_int else 0.0
    features = [
        float(priv_int),
        float(diff),
        float(ratio),
        bit_entropy(priv_hex),
        float(hamming_weight(priv_hex)),
    ]
    features.extend(hash160_embedding(priv_hex).astype(float))
    features.extend(mnemonic_index_vector(words, wordlist).astype(float))
    return np.array(features, dtype=np.float32)

# --- Simple statistical models ---

def linear_regression(x: np.ndarray, y: np.ndarray) -> LinearRegression:
    model = LinearRegression()
    x = x.reshape(-1, 1)
    model.fit(x, y)
    return model

def polynomial_regression(x: np.ndarray, y: np.ndarray, degree: int = 2) -> LinearRegression:
    poly_model = make_pipeline(PolynomialFeatures(degree), LinearRegression())
    poly_model.fit(x.reshape(-1, 1), y)
    return poly_model

def arima_predict(series: np.ndarray, order=(1, 0, 0), steps: int = 1) -> np.ndarray:
    if ARIMA is None:
        return np.zeros(steps)
    try:
        model = ARIMA(series, order=order)
        fit = model.fit()
        return fit.forecast(steps)
    except Exception:
        return np.zeros(steps)

# --- Simple MLP model ---
class SimpleMLP(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        if x.ndim == 1:
            x = x.unsqueeze(0)
        return self.net(x)


def mlp_predict(model: SimpleMLP, features: np.ndarray) -> float:
    with torch.no_grad():
        t = torch.tensor(features, dtype=torch.float32)
        out = model(t)
        return out.item()

# --- Placeholders for advanced models ---

def autoencoder_compress(model: nn.Module, features: np.ndarray) -> np.ndarray:
    with torch.no_grad():
        t = torch.tensor(features, dtype=torch.float32)
        encoded = model.encoder(t.unsqueeze(0))
        return encoded.squeeze(0).numpy()

def lstm_sequence_model(model: nn.Module, seq: np.ndarray) -> np.ndarray:
    with torch.no_grad():
        t = torch.tensor(seq, dtype=torch.float32).unsqueeze(0).unsqueeze(-1)
        out, _ = model(t)
        return out.squeeze(0)[-1].numpy()

def cnn_bitpattern_model(model: nn.Module, bits: np.ndarray) -> float:
    with torch.no_grad():
        t = torch.tensor(bits, dtype=torch.float32).unsqueeze(0).unsqueeze(0)
        out = model(t)
        return out.item()

# --- Evolutionary heuristics placeholders ---

def genetic_algorithm(population: np.ndarray) -> np.ndarray:
    return population

def simulated_annealing(start: np.ndarray) -> np.ndarray:
    return start

# --- Reinforcement learning placeholders ---

def rl_agent_decide_range(score: float, hits: int) -> tuple:
    return (0, 1)

def rl_agent_update(hit: bool):
    pass

# --- ECC optimization placeholders ---

def glv_endomorphism(k: int) -> tuple:
    return (k, 0)

def precompute_window_table():
    pass

# --- Dimensionality reduction & clustering placeholders ---

def pca_reduce(data: np.ndarray, n_components: int = 2) -> np.ndarray:
    from sklearn.decomposition import PCA
    return PCA(n_components=n_components).fit_transform(data)

def kmeans_cluster(data: np.ndarray, n_clusters: int = 2) -> np.ndarray:
    from sklearn.cluster import KMeans
    model = KMeans(n_clusters=n_clusters)
    return model.fit_predict(data)

# --- Ensemble score ---

def ensemble_score(xgb: float, mlp: float, cnn: float, rl: float) -> float:
    return (xgb + mlp + cnn + rl) / 4.0

# --- Continuous update placeholders ---

def reload_models():
    pass

def periodic_save_models():
    pass

def periodic_reload_models():
    pass
