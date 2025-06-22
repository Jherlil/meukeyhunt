import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import ctypes
import time
from multiprocessing import Pool, cpu_count
import zlib
import warnings
import shutil  # Para copiar arquivos de modelo
from tqdm import tqdm

# Modelos tradicionais
import xgboost as xgb
import lightgbm as lgb

# Configuração de Avisos e Erros NumPy
warnings.filterwarnings("ignore", message=".*longdouble.*", category=RuntimeWarning)
warnings.filterwarnings("ignore", message=".*is_sparse.*", category=UserWarning) # Comum com XGBoost/LightGBM
# np.seterr(divide='ignore', invalid='ignore') # Cuidado ao ignorar todos os erros de divisão/inválidos

print(f"[Train] NumPy version: {np.__version__}")
print(f"[Train] PyTorch version: {torch.__version__}")
print(f"[Train] Pandas version: {pd.__version__}")
print(f"[Train] XGBoost version: {xgb.__version__}")
print(f"[Train] LightGBM version: {lgb.__version__}")


# --- Constantes e Configurações ---
# Para o MLP e Autoencoder atual, baseado nas features extraídas
MLP_INPUT_DIM = 28  # Alinhado com FeatureSet::to_vector() em C++
AE_INPUT_DIM = 28   # Alinhado com FeatureSet::to_vector() em C++

# Para a CNN (baseado em WIFs)
CNN_SEQ_LENGTH = 52  # Comprimento máximo de uma WIF (ajuste se necessário)
BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# +1 para token de padding (índice 0) ou UNK
CNN_VOCAB_SIZE = len(BASE58_CHARS) + 1
CNN_EMBEDDING_DIM = 32 # Dimensão do embedding para cada caractere
CNN_OUTPUT_CLASSES = 1 # Para saída sigmoide (probabilidade de ser um "hit")


# --- Definições de Modelo ---
class MLP(nn.Module):
    def __init__(self, input_dim=MLP_INPUT_DIM):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(input_dim, 256), nn.BatchNorm1d(256), nn.ReLU(), nn.Dropout(0.5),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.ReLU(), nn.Dropout(0.5),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.ReLU(), nn.Dropout(0.4),
            nn.Linear(64, 1), nn.Sigmoid()
        )
    def forward(self, x):
        if x.ndim == 1: x = x.unsqueeze(0) # Garante que a entrada seja [batch_size, features]
        return self.layers(x)

class Autoencoder(nn.Module):
    def __init__(self, input_dim=AE_INPUT_DIM):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128), nn.ReLU(),
            nn.Linear(128, 64), nn.ReLU(),
            nn.Linear(64, 32), nn.ReLU() # Camada de "gargalo"
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 64), nn.ReLU(),
            nn.Linear(64, 128), nn.ReLU(),
            nn.Linear(128, input_dim),
            nn.Sigmoid() # Assumindo features de entrada normalizadas para [0,1]
        )
    def forward(self, x):
        if x.ndim == 1: x = x.unsqueeze(0)
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

class CNN1D(nn.Module):
    def __init__(self, vocab_size=CNN_VOCAB_SIZE, embedding_dim=CNN_EMBEDDING_DIM, num_classes=CNN_OUTPUT_CLASSES):
        super().__init__()
        # padding_idx=0 significa que o token de índice 0 no vocabulário é usado para padding e não será treinado
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)

        # A entrada da Conv1D será (N, embedding_dim, L_in)
        self.network = nn.Sequential(
            nn.Conv1d(embedding_dim, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.MaxPool1d(kernel_size=2, stride=2), # Reduz o comprimento da sequência pela metade

            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.MaxPool1d(kernel_size=2, stride=2), # Reduz o comprimento da sequência pela metade novamente

            nn.AdaptiveAvgPool1d(1), # Reduz a dimensão da sequência para 1 -> (N, 128, 1)
            nn.Flatten(), # Achata para (N, 128)

            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(64, num_classes),
            nn.Sigmoid() # Para classificação binária (hit ou não)
        )

    def forward(self, x): # x é esperado como (N, L_in) contendo índices de caracteres
        # x deve ser LongTensor para a camada de Embedding
        x_emb = self.embedding(x)  # Saída: (N, L_in, embedding_dim)

        # Conv1D espera (N, C_in, L_in), onde C_in é embedding_dim
        x_permuted = x_emb.permute(0, 2, 1) # Saída: (N, embedding_dim, L_in)
        return self.network(x_permuted)

# --- Extração de Features (Funções Auxiliares) ---
def extract_features_chunk(chunk_df_id_tuple):
    chunk, df_id = chunk_df_id_tuple
    df = chunk.copy()
    df_feat = pd.DataFrame(index=df.index)
    feature_warnings = []

    priv_hex_col = "priv_hex"; wif_col = "wif"; addr1_col = "address"
    addr2_col_expected = "addr2_p2pkh_uncomp"; priv_binary_col_expected = "priv_binary"

    wif_validator_lib = None
    try:
        validator_path = os.path.join(os.path.dirname(__file__), "wif_validator.so")
        if os.path.exists(validator_path):
            wif_validator_lib = ctypes.CDLL(validator_path)
            wif_validator_lib.is_valid_wif.restype = ctypes.c_double
            wif_validator_lib.is_valid_wif.argtypes = [ctypes.c_char_p]
            wif_validator_lib.is_compressed_key.restype = ctypes.c_double
            wif_validator_lib.is_compressed_key.argtypes = [ctypes.c_char_p]
        elif df_id == "Chunk1": # Avisar apenas uma vez
            feature_warnings.append(f"wif_validator.so não encontrado em {validator_path}. Features wif_valid_custom e is_compressed_custom serão 0.")
    except OSError as e:
        if df_id == "Chunk1": feature_warnings.append(f"Erro ao carregar wif_validator.so: {e}. Features dependentes serão 0.")
        wif_validator_lib = None

    def safe_apply(series, func, default_value=0.0, col_name="Unknown"):
        results = []
        for item_idx, item in series.items():
            try:
                results.append(func(item))
            except Exception as e:
                item_preview = str(item)[:30] + "..." if isinstance(item, str) and len(str(item)) > 30 else str(item)
                feature_warnings.append(f"[Chunk {df_id}, Idx {item_idx}] Erro em func para '{col_name}', item '{item_preview}': {e}")
                results.append(default_value)
        return pd.Series(results, index=series.index)

    def entropy(s_data):
        if not isinstance(s_data, str) or not s_data: return 0.0
        s_len = len(s_data)
        freq = {}
        for char_val in s_data: freq[char_val] = freq.get(char_val, 0) + 1
        ent = 0.0
        for char_val in freq:
            p = freq[char_val] / s_len
            if p > 0:
                try: ent -= p * np.log2(p)
                except ValueError: pass # Lida com p muito pequeno que pode causar erro no log2
        return ent

    def symmetry_score(s_data):
        if not isinstance(s_data, str) or len(s_data) < 2: return 1.0
        s_len = len(s_data)
        half_len = s_len // 2
        matches = sum(1 for i in range(half_len) if s_data[i] == s_data[s_len - 1 - i])
        return float(matches) / half_len if half_len > 0 else 1.0

    def longest_one_run(s_bin):
        if not isinstance(s_bin, str) or not s_bin: return 0.0
        try: return float(max((len(run) for run in s_bin.split('0')), default=0))
        except: return 0.0

    def is_palindrome(s_data):
        if not isinstance(s_data, str): return 0.0
        return 1.0 if s_data == s_data[::-1] else 0.0

    def zero_mod(x_val, mod_val):
        if not isinstance(x_val, (int, float)) or mod_val == 0: return 0.0
        try: return 1.0 if x_val % mod_val == 0 else 0.0
        except: return 0.0

    def hex_to_int_safe(hex_str_val):
        if isinstance(hex_str_val, str) and hex_str_val:
            try: return int(hex_str_val, 16)
            except ValueError: return 0
        return 0

    def combined_key_score(s_hex_val):
        if not isinstance(s_hex_val, str) or not s_hex_val or len(s_hex_val) == 0: return 0.0
        try:
            s_bytes = s_hex_val.encode('utf-8', errors='ignore')
            if not s_bytes: return 0.0
            compressed_len = len(zlib.compress(s_bytes))
            kolmogorov = float(compressed_len) / len(s_bytes) if len(s_bytes) > 0 else 0.0
            counts = {}
            for char_val in s_hex_val.lower(): counts[char_val] = counts.get(char_val, 0) + 1
            repetition = float(max(counts.values())) / len(s_hex_val) if counts and len(s_hex_val) > 0 else 0.0
            n_int_val = hex_to_int_safe(s_hex_val)
            primes = [2, 3, 5, 7, 11]
            divisibility = sum(1.0 for p in primes if n_int_val % p == 0) / len(primes) if n_int_val != 0 else 0.0
            max_r_val = 0; current_r_val = 0
            if s_hex_val:
                max_r_val = 1; current_r_val = 1; last_c_val = s_hex_val[0]
                for char_val in s_hex_val[1:]:
                    if char_val == last_c_val: current_r_val += 1
                    else: max_r_val = max(max_r_val, current_r_val); current_r_val = 1; last_c_val = char_val
                max_r_val = max(max_r_val, current_r_val)
            run_length = float(max_r_val) / len(s_hex_val) if len(s_hex_val) > 0 else 0.0
            weights = [0.4, 0.2, 0.2, 0.2]
            score_val_calc = (weights[0]*(1-kolmogorov) + weights[1]*(1-repetition) + weights[2]*(1-divisibility) + weights[3]*(1-run_length))
            return min(max(score_val_calc, 0.0), 1.0)
        except Exception as e_detail:
            feature_warnings.append(f"[Chunk {df_id}] Erro em combined_key_score para '{s_hex_val[:10]}...': {e_detail}")
            return 0.0

    def is_valid_wif_c_func(wif_str_val):
        if wif_validator_lib and isinstance(wif_str_val, str) and wif_str_val:
            try: return float(wif_validator_lib.is_valid_wif(wif_str_val.encode('utf-8')))
            except Exception as e_detail: feature_warnings.append(f"[Chunk {df_id}] Erro is_valid_wif_c: {e_detail}"); return 0.0
        return 0.0

    def is_compressed_key_c_func(wif_str_val):
        if wif_validator_lib and isinstance(wif_str_val, str) and wif_str_val:
            try: return float(wif_validator_lib.is_compressed_key(wif_str_val.encode('utf-8')))
            except Exception as e_detail: feature_warnings.append(f"[Chunk {df_id}] Erro is_compressed_key_c: {e_detail}"); return 0.0
        return 0.0

    def classify_address_type_func(addr_str_val):
        if not isinstance(addr_str_val, str) or not addr_str_val: return 3.0 # Unknown/Invalid
        if addr_str_val.startswith("1"): return 0.0 # P2PKH
        if addr_str_val.startswith("3"): return 1.0 # P2SH
        if addr_str_val.startswith("bc1"): return 2.0 # Bech32
        return 3.0 # Other/Unknown

    # Extração de features
    for col in [priv_hex_col, wif_col, addr1_col]:
        if col not in df.columns:
            feature_warnings.append(f"[Chunk {df_id}] Coluna essencial '{col}' não encontrada. Pulando extração de features neste chunk.")
            return np.array([]).reshape(0, MLP_INPUT_DIM), np.array([]).reshape(0,1), feature_warnings

    df_feat["priv_hex_len"] =         safe_apply(df[priv_hex_col], lambda x: float(len(str(x))), col_name="priv_hex_len")
    df_feat["wif_present"] =          safe_apply(df[wif_col], lambda x: 1.0 if pd.notnull(x) and str(x).strip() != "" else 0.0, col_name="wif_present")
    df_feat["addr1_type"] =           safe_apply(df[addr1_col], lambda x: classify_address_type_func(str(x)), col_name="addr1_type")

    if addr2_col_expected in df.columns:
        df_feat["addr2_present"] =      safe_apply(df[addr2_col_expected], lambda x: 1.0 if pd.notnull(x) and str(x).strip() != "" else 0.0, col_name="addr2_present")
        df_feat["addr2_len"] =          safe_apply(df[addr2_col_expected], lambda x: float(len(str(x))), col_name="addr2_len")
    else:
        df_feat["addr2_present"] = 0.0; df_feat["addr2_len"] = 0.0
        if df_id == "Chunk1": feature_warnings.append(f"Coluna '{addr2_col_expected}' não encontrada.")

    if priv_binary_col_expected in df.columns:
        df_feat["seed_word_count"] =    safe_apply(df[priv_binary_col_expected], lambda x: float(str(x).count("1")) if isinstance(x, str) else 0.0, col_name="seed_word_count")
        df_feat["seed_entropy"] =       safe_apply(df[priv_binary_col_expected], entropy, col_name="seed_entropy")
        df_feat["symmetry"] =           safe_apply(df[priv_binary_col_expected], symmetry_score, col_name="symmetry_priv_binary")
        df_feat["longest_one_run"] =    safe_apply(df[priv_binary_col_expected], longest_one_run, col_name="longest_one_run")
        df_feat["bin_palindrome"] =     safe_apply(df[priv_binary_col_expected], lambda x: is_palindrome(x) if isinstance(x, str) else 0.0, col_name="bin_palindrome")
    else:
        for col in ["seed_word_count", "seed_entropy", "symmetry", "longest_one_run", "bin_palindrome"]: df_feat[col] = 0.0
        if df_id == "Chunk1": feature_warnings.append(f"Coluna '{priv_binary_col_expected}' não encontrada.")

    df_feat["base58_wif_len"] =       safe_apply(df[wif_col], lambda x: float(len(str(x))), col_name="base58_wif_len")
    df_feat["base58_wif_unique"] =    safe_apply(df[wif_col], lambda x: float(len(set(str(x)))) / len(str(x)) if isinstance(x, str) and len(str(x)) > 0 else 0.0, col_name="base58_wif_unique")
    df_feat["addr1_len"] =            safe_apply(df[addr1_col], lambda x: float(len(str(x))), col_name="addr1_len")
    df_feat["priv_hex_zero_prefix"] = safe_apply(df[priv_hex_col], lambda x: float(len(str(x)) - len(str(x).lstrip("0"))) if isinstance(x, str) and str(x) else 0.0, col_name="priv_hex_zero_prefix")
    df_feat["priv_hex_zero_suffix"] = safe_apply(df[priv_hex_col], lambda x: float(len(str(x)) - len(str(x).rstrip("0"))) if isinstance(x, str) and str(x) else 0.0, col_name="priv_hex_zero_suffix")
    df_feat["priv_hex_entropy"] =     safe_apply(df[priv_hex_col], lambda x: entropy(str(x)), col_name="priv_hex_entropy")
    df_feat["priv_hex_palindrome"] =  safe_apply(df[priv_hex_col], lambda x: is_palindrome(str(x)), col_name="priv_hex_palindrome")
    df_feat["is_mod_2"] =             safe_apply(df[priv_hex_col], lambda x: zero_mod(hex_to_int_safe(str(x)), 2), col_name="is_mod_2")
    df_feat["is_mod_4"] =             safe_apply(df[priv_hex_col], lambda x: zero_mod(hex_to_int_safe(str(x)), 4), col_name="is_mod_4")
    df_feat["is_mod_8"] =             safe_apply(df[priv_hex_col], lambda x: zero_mod(hex_to_int_safe(str(x)), 8), col_name="is_mod_8")
    df_feat["priv_hex_sympy_score"] = safe_apply(df[priv_hex_col], lambda x: combined_key_score(str(x)), col_name="priv_hex_sympy_score")
    df_feat["base58_entropy"] =       safe_apply(df[wif_col], lambda x: entropy(str(x)), col_name="base58_entropy_wif")
    df_feat["wif_valid_custom"] =     safe_apply(df[wif_col], is_valid_wif_c_func, col_name="wif_valid_custom")
    df_feat["is_compressed_custom"] = safe_apply(df[wif_col], is_compressed_key_c_func, col_name="is_compressed_custom")
    df_feat["addr_entropy_custom"] =  safe_apply(df[addr1_col], lambda x: entropy(str(x)), col_name="addr_entropy_custom")
    df_feat["addr_type_p2pkh_custom"] = safe_apply(df[addr1_col], lambda x: 1.0 if classify_address_type_func(str(x)) == 0.0 else 0.0, col_name="addr_type_p2pkh_custom") # 0.0 for P2PKH
    df_feat["addr_type_p2sh_custom"] =  safe_apply(df[addr1_col], lambda x: 1.0 if classify_address_type_func(str(x)) == 1.0 else 0.0, col_name="addr_type_p2sh_custom") # 1.0 for P2SH
    df_feat["addr_type_bech32_custom"]= safe_apply(df[addr1_col], lambda x: 1.0 if classify_address_type_func(str(x)) == 2.0 else 0.0, col_name="addr_type_bech32_custom") # 2.0 for Bech32

    expected_feature_order = [
        "priv_hex_len", "wif_present", "addr1_type", "addr2_present", "addr2_len",
        "seed_word_count", "seed_entropy", "symmetry", "longest_one_run", "bin_palindrome",
        "base58_wif_len", "base58_wif_unique", "addr1_len", "priv_hex_zero_prefix",
        "priv_hex_zero_suffix", "priv_hex_entropy", "priv_hex_palindrome",
        "is_mod_2", "is_mod_4", "is_mod_8", "priv_hex_sympy_score",
        "base58_entropy", "wif_valid_custom", "is_compressed_custom",
        "addr_entropy_custom", "addr_type_p2pkh_custom", "addr_type_p2sh_custom",
        "addr_type_bech32_custom"
    ]

    for col in expected_feature_order:
        if col not in df_feat.columns:
            df_feat[col] = 0.0
            if df_id == "Chunk1": feature_warnings.append(f"Feature '{col}' não gerada no chunk, preenchida com 0.0.")

    df_feat_ordered = df_feat.reindex(columns=expected_feature_order, fill_value=0.0)

    if df_feat_ordered.shape[1] != MLP_INPUT_DIM:
        feature_warnings.append(f"ERRO CRÍTICO no Chunk {df_id}: Número final de features ({df_feat_ordered.shape[1]}) != MLP_INPUT_DIM ({MLP_INPUT_DIM}).")
        # Return empty arrays of the correct shape to avoid downstream errors if possible
        return np.array([]).reshape(0, MLP_INPUT_DIM), np.array([]).reshape(0,1), feature_warnings

    X_chunk_data = df_feat_ordered.astype(np.float32).values
    y_chunk_data = df["score"].astype(np.float32).values.reshape(-1, 1)
    return X_chunk_data, y_chunk_data, feature_warnings

def extract_features_parallel(df):
    start_time = time.time()
    num_rows = len(df)
    print(f"[Train] Iniciando extração de features para {num_rows} linhas...")

    if num_rows == 0:
        print("[Train] DataFrame vazio, nenhuma feature para extrair.")
        return np.array([]).reshape(0, MLP_INPUT_DIM), np.array([]).reshape(0,1), pd.DataFrame()

    num_processes = min(cpu_count() -1 if cpu_count() > 1 else 1, 8) # Deixa um CPU livre
    min_chunk_size = 2000 # Aumentado para reduzir overhead

    if num_rows <= min_chunk_size * num_processes : # Se dados pequenos, usar menos processos
        num_processes = max(1, num_rows // min_chunk_size if min_chunk_size > 0 else 1)

    num_chunks = min(max(1, num_rows // min_chunk_size if min_chunk_size > 0 else num_processes), num_processes * 4) # Limita o número de chunks
    chunk_size = (num_rows + num_chunks - 1) // num_chunks

    print(f"[Train] Usando {num_processes} processos com {num_chunks} chunks de tamanho ~{chunk_size}.")
    chunks_with_ids = [(df[i:i+chunk_size], f"Idx{idx+1}") for idx, i in enumerate(range(0, num_rows, chunk_size))]

    all_warnings = []
    pool_results = []
    try:
        with Pool(processes=num_processes) as pool:
            for res in tqdm(
                pool.imap_unordered(extract_features_chunk, chunks_with_ids),
                total=len(chunks_with_ids),
                desc="[Train] Extraindo features",
            ):
                pool_results.append(res)
    except Exception as e_pool:
        print(f"[Train] Erro CRÍTICO durante o processamento em paralelo: {e_pool}")
        # Return empty arrays and original df in case of pool error
        return np.array([]).reshape(0, MLP_INPUT_DIM), np.array([]).reshape(0,1), df

    valid_results_X = [r[0] for r in pool_results if r[0] is not None and r[0].ndim == 2 and r[0].shape[0] > 0 and r[0].shape[1] == MLP_INPUT_DIM]
    valid_results_y = [r[1] for r in pool_results if r[1] is not None and r[1].ndim == 2 and r[1].shape[0] > 0]

    for r_idx, r_content in enumerate(pool_results):
        if r_content[2]: # warnings
            all_warnings.extend([f"[PoolRes {r_idx+1}] {w}" for w in r_content[2]])
        # Check integrity of X part of results
        if not (r_content[0] is not None and r_content[0].ndim == 2 and r_content[0].shape[0] > 0 and r_content[0].shape[1] == MLP_INPUT_DIM):
            all_warnings.append(f"[PoolRes {r_idx+1}, ChunkID: {chunks_with_ids[r_idx][1]}] Chunk problemático, features X podem estar ausentes ou com shape incorreto. Shape: {r_content[0].shape if r_content[0] is not None else 'None'}")
        # Check integrity of y part of results (len should match corresponding X)
        if not (r_content[1] is not None and r_content[1].ndim == 2 and r_content[1].shape[0] > 0 and r_content[1].shape[0] == (r_content[0].shape[0] if r_content[0] is not None else -1) ):
             all_warnings.append(f"[PoolRes {r_idx+1}, ChunkID: {chunks_with_ids[r_idx][1]}] Chunk problemático, labels y podem estar ausentes ou com shape/tamanho incorreto. Shape y: {r_content[1].shape if r_content[1] is not None else 'None'}, Shape X: {r_content[0].shape if r_content[0] is not None else 'None'}")


    if all_warnings:
        unique_warnings = sorted(list(set(all_warnings)))
        print(f"\n[Avisos da Extração de Features em Paralelo (total {len(all_warnings)}, únicos {len(unique_warnings)})]:")
        for warn_msg in unique_warnings[:15]: print(f"- {warn_msg}") # Imprime os 15 primeiros únicos
        if len(unique_warnings) > 15: print(f"- ... e mais {len(unique_warnings)-15} avisos únicos.")
        print()

    if not valid_results_X or not valid_results_y or len(valid_results_X) != len(valid_results_y):
        print("[Train] Nenhum chunk produziu features válidas ou houve inconsistência nos resultados (X/y). Abortando extração.")
        return np.array([]).reshape(0, MLP_INPUT_DIM), np.array([]).reshape(0,1), df

    # Adicionalmente, verificar se todos os X válidos têm o mesmo número de colunas (já feito pelo filtro)
    # e se a soma das linhas de X corresponde à soma das linhas de y
    total_X_rows = sum(x.shape[0] for x in valid_results_X)
    total_y_rows = sum(y.shape[0] for y in valid_results_y)

    if total_X_rows != total_y_rows:
        print(f"[Train] Inconsistência no número total de amostras entre X ({total_X_rows}) e y ({total_y_rows}) após coleta dos chunks. Abortando.")
        return np.array([]).reshape(0, MLP_INPUT_DIM), np.array([]).reshape(0,1), df

    if total_X_rows == 0: # Nenhum dado válido foi coletado
        print("[Train] Nenhum dado válido coletado dos chunks após filtragem. Retornando vazio.")
        return np.array([]).reshape(0, MLP_INPUT_DIM), np.array([]).reshape(0,1), df


    X = np.vstack(valid_results_X)
    y = np.vstack(valid_results_y)

    print(f"[Train] Extração de features concluída ({time.time() - start_time:.2f}s). Shape X: {X.shape}, Shape y: {y.shape}")
    return X, y, df # Retorna df original para pegar a coluna WIF para CNN

def load_data_with_feature_extraction(path):
    if not os.path.exists(path):
        print(f"[Train] Arquivo '{path}' não encontrado.")
        return None, None, None # X, y, df_full
    try:
        print(f"[Train] Lendo CSV completo de '{path}'...")
        # Especificar dtypes para colunas problemáticas e score
        # Manter low_memory=False para melhor inferência de tipos onde não especificado, apesar de consumir mais memória
        try:
            df_full = pd.read_csv(
                path,
                sep=",",
                skipinitialspace=True,
                low_memory=False,
                dtype={
                    'priv_hex': str,
                    'wif': str,
                    'address': str,
                    'addr2_p2pkh_uncomp': str,
                    'priv_binary': str,
                    'score': np.float32,
                },
                engine="pyarrow",
                use_threads=True,
            )
        except Exception:
            df_full = pd.read_csv(
                path,
                sep=",",
                skipinitialspace=True,
                low_memory=False,
                dtype={
                    'priv_hex': str,
                    'wif': str,
                    'address': str,
                    'addr2_p2pkh_uncomp': str,
                    'priv_binary': str,
                    'score': np.float32,
                },
            )
        print(f"[Train] Colunas lidas de '{path}': {list(df_full.columns)}")

        if df_full.empty:
            print(f"[Train] CSV '{path}' está vazio.")
            return None, None, df_full # Retorna df_full vazio

        # Garantir que a coluna 'score' existe e é do tipo correto
        if 'score' not in df_full.columns:
            print(f"[Train] ERRO: Coluna 'score' não encontrada em '{path}'.")
            return None, None, df_full # Retorna df_full mesmo com erro para possível uso da CNN

        df_full['score'] = df_full['score'].astype(np.float32) # Reafirma o tipo

        # X e y são as features extraídas e os scores correspondentes.
        # df_full é o dataframe original lido do CSV.
        X_features, y_labels, df_original_for_cnn = extract_features_parallel(df_full)

        if X_features is None or y_labels is None or X_features.shape[0] == 0:
            print(f"[Train] Nenhuma feature válida extraída de '{path}'.")
            # Retornar df_full para que a CNN possa tentar usar a coluna WIF se existir
            return None, None, df_original_for_cnn

        print(f"[Train] Carregadas {len(X_features)} entradas de '{path}' após extração de features.")
        return X_features, y_labels, df_original_for_cnn
    except KeyError as e_key:
        print(f"[Train] Erro de coluna (KeyError) ao processar '{path}': {e_key}")
        return None, None, None
    except Exception as e_gen:
        print(f"[Train] Erro geral ao carregar ou processar '{path}': {e_gen}")
        return None, None, None

# --- Funções de Treinamento Específicas ---
def train_model(model, X_train_data, y_train_data, X_val_data, y_val_data, criterion, optimizer, scheduler, epochs, batch_size, model_name="Modelo"):
    print(f"\n[Train {model_name}] Iniciando treinamento...")

    # Para AE, y_train e y_val são X_train e X_val respectivamente
    if isinstance(model, Autoencoder):
        y_train_effective = X_train_data
        y_val_effective = X_val_data
        # Para AE, o tipo de X_train/X_val já deve ser float32. Os labels (targets) também serão.
        train_dataset = torch.utils.data.TensorDataset(torch.tensor(X_train_data, dtype=torch.float32), torch.tensor(y_train_effective, dtype=torch.float32))
        val_dataset = torch.utils.data.TensorDataset(torch.tensor(X_val_data, dtype=torch.float32), torch.tensor(y_val_effective, dtype=torch.float32))

    elif isinstance(model, CNN1D):
        # Para CNN, X é LongTensor (índices), y é FloatTensor (labels)
        train_dataset = torch.utils.data.TensorDataset(torch.tensor(X_train_data, dtype=torch.long), torch.tensor(y_train_data, dtype=torch.float32))
        val_dataset = torch.utils.data.TensorDataset(torch.tensor(X_val_data, dtype=torch.long), torch.tensor(y_val_data, dtype=torch.float32))
    else: # MLP e outros modelos que esperam float X e float y
        y_train_effective = y_train_data
        y_val_effective = y_val_data
        train_dataset = torch.utils.data.TensorDataset(torch.tensor(X_train_data, dtype=torch.float32), torch.tensor(y_train_effective, dtype=torch.float32))
        val_dataset = torch.utils.data.TensorDataset(torch.tensor(X_val_data, dtype=torch.float32), torch.tensor(y_val_effective, dtype=torch.float32))


    # Garante que num_workers não exceda o número de CPUs disponíveis ou o limite do sistema
    effective_num_workers = min(4, cpu_count()) if cpu_count() > 0 else 0 # 0 se cpu_count não for confiável

    train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=effective_num_workers, pin_memory=True)
    val_loader = torch.utils.data.DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=effective_num_workers, pin_memory=True)

    best_val_loss = float('inf')
    epochs_no_improve = 0
    patience_early_stopping = 5 # Número de épocas para esperar por melhoria antes de parar (para o modelo CNN1D especificamente)

    for epoch in range(epochs):
        model.train()
        epoch_train_loss = 0.0
        for batch_X, batch_y_target in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y_target)
            loss.backward()
            optimizer.step()
            epoch_train_loss += loss.item() * batch_X.size(0)
        epoch_train_loss /= len(train_loader.dataset)

        model.eval()
        epoch_val_loss = 0.0
        with torch.no_grad():
            for batch_X_val, batch_y_val_target in val_loader:
                val_outputs = model(batch_X_val)
                val_loss = criterion(val_outputs, batch_y_val_target)
                epoch_val_loss += val_loss.item() * batch_X_val.size(0)
        epoch_val_loss /= len(val_loader.dataset)

        current_lr = optimizer.param_groups[0]['lr']
        if scheduler:
            if isinstance(scheduler, optim.lr_scheduler.ReduceLROnPlateau):
                scheduler.step(epoch_val_loss)
            else: # Para outros schedulers como StepLR, CosineAnnealingLR, etc.
                scheduler.step()
            current_lr = optimizer.param_groups[0]['lr'] # Atualiza LR após o step do scheduler

        print(f"[Train {model_name}] Epoch {epoch+1}/{epochs}, Train Loss: {epoch_train_loss:.6f}, Val Loss: {epoch_val_loss:.6f}, LR: {current_lr:.7f}")

        # Lógica de Early Stopping (especialmente útil para CNN que pode ter mais épocas)
        if model_name == "CNN1D": # Aplicar early stopping apenas para CNN por agora
            if epoch_val_loss < best_val_loss:
                best_val_loss = epoch_val_loss
                epochs_no_improve = 0
                # Opcional: Salvar o melhor modelo aqui se desejar um checkpoint
                # torch.save(model.state_dict(), f"models/{model_name}_best_checkpoint.pt")
            else:
                epochs_no_improve += 1

            if epochs_no_improve >= patience_early_stopping:
                print(f"[Train {model_name}] Early stopping at epoch {epoch+1} due to no improvement in Val Loss for {patience_early_stopping} epochs.")
                break
    return model

def save_pytorch_model(model, base_filename):
    os.makedirs("models", exist_ok=True)
    scripted_path = f"models/{base_filename}_scripted.pt"
    statedict_path = f"models/{base_filename}_statedict.pt"
    try:
        model.eval() # Garante que o modelo está em modo de avaliação (desativa dropout, etc.)
        # Antes de scriptar, certifique-se que o modelo não tem chamadas a `self.training` ou outras construções que o TorchScript não lida bem
        # ou que dependem de estado que não é capturado. Para modelos complexos, pode ser necessário refatorar.
        scripted_model = torch.jit.script(model)
        scripted_model.save(scripted_path)
        print(f"[Train] Modelo salvo como TorchScript em {scripted_path}")
        return scripted_path # Retorna o caminho do modelo scriptado que foi salvo com sucesso
    except Exception as e:
        print(f"[Train] Erro ao salvar {base_filename} como TorchScript: {e}")
        print(f"[Train] Tentando salvar apenas state_dict de {base_filename} em {statedict_path} como fallback.")
        try:
            torch.save(model.state_dict(), statedict_path)
            print(f"[Train] State dict de {base_filename} salvo com sucesso em {statedict_path}.")
        except Exception as e_sd:
            print(f"[Train] Erro ao salvar state_dict de {base_filename}: {e_sd}")
        return None # Indica que o scripting falhou

# --- Funções para CNN ---
def preprocess_data_for_cnn(all_wifs_list, all_labels_list, max_len=CNN_SEQ_LENGTH):
    print(f"[Train CNN] Pré-processando {len(all_wifs_list) if all_wifs_list is not None else 'nenhuma'} WIFs para CNN...")

    char_to_int = {char: i + 1 for i, char in enumerate(BASE58_CHARS)} # 0 é reservado para padding
    # CNN_VOCAB_SIZE deve ser len(BASE58_CHARS) + 1 (para o token de padding)

    if all_wifs_list is None or not all_wifs_list:
        # Se all_labels_list também for None ou vazio, definimos um número padrão de amostras dummy.
        # Caso contrário, tentamos usar o tamanho de all_labels_list para y_cnn_data.
        num_samples = len(all_labels_list) if all_labels_list is not None and len(all_labels_list) > 0 else 100
        print(f"[Train CNN] Gerando {num_samples} amostras dummy para X_cnn (WIFs não fornecidas).")
        # Gera sequências aleatórias de inteiros (1 a len(BASE58_CHARS))
        # dtype np.int64 é importante para a camada de Embedding do PyTorch
        X_cnn_data = np.random.randint(1, len(BASE58_CHARS) + 1, size=(num_samples, max_len), dtype=np.int64)

        if all_labels_list is None or len(all_labels_list) != num_samples : # Se labels não batem ou não existem
             y_cnn_data = np.random.randint(0, 2, size=(num_samples, 1)).astype(np.float32)
             print(f"[Train CNN] Gerando {num_samples} labels dummy para y_cnn.")
        else: # Usar os labels fornecidos se o tamanho bater
            y_cnn_data = np.array(all_labels_list, dtype=np.float32).reshape(-1,1)
            print(f"[Train CNN] Usando {len(y_cnn_data)} labels fornecidos para y_cnn.")

        return X_cnn_data, y_cnn_data

    processed_sequences = []
    valid_labels_for_processed_wifs = []

    for idx, wif in enumerate(all_wifs_list):
        if not isinstance(wif, str):
            # Se o WIF não for uma string, podemos pular ou usar uma representação padrão de padding/UNK
            # Por agora, vamos pular para manter a integridade dos dados, mas isso pode reduzir o dataset
            # print(f"[Train CNN] Aviso: WIF na posição {idx} não é string (tipo: {type(wif)}), pulando.")
            # Se for pular, precisa pular o label correspondente também.
            # Alternativamente, tratar como string vazia:
            wif_str = ""
        else:
            wif_str = wif

        sequence = [char_to_int.get(char, 0) for char in wif_str] # Usar 0 para chars não no vocabulário (UNK) ou padding

        # Truncar ou preencher a sequência
        if len(sequence) > max_len:
            sequence = sequence[:max_len]
        else:
            sequence.extend([0] * (max_len - len(sequence))) # Pad com 0 (índice de padding)

        processed_sequences.append(sequence)
        if all_labels_list is not None and idx < len(all_labels_list):
             valid_labels_for_processed_wifs.append(all_labels_list[idx])


    if not processed_sequences: # Se nenhuma WIF válida foi processada
        print("[Train CNN] Nenhuma WIF válida processada. Retornando arrays vazios.")
        return np.array([], dtype=np.int64).reshape(0,max_len), np.array([], dtype=np.float32).reshape(0,1)

    X_cnn_data = np.array(processed_sequences, dtype=np.int64) # Embedding layer espera LongTensor

    if all_labels_list is not None and len(valid_labels_for_processed_wifs) == len(processed_sequences) :
        y_cnn_data = np.array(valid_labels_for_processed_wifs, dtype=np.float32).reshape(-1, 1)
    else: # Se labels não foram fornecidos ou houve desalinhamento. Gerar dummy para y.
        print(f"[Train CNN] Labels para WIFs processadas não disponíveis ou desalinhados. Gerando labels dummy.")
        y_cnn_data = np.random.randint(0, 2, size=(X_cnn_data.shape[0], 1)).astype(np.float32)


    print(f"[Train CNN] Pré-processamento CNN concluído. X_cnn_data shape: {X_cnn_data.shape}, y_cnn_data shape: {y_cnn_data.shape}")
    return X_cnn_data, y_cnn_data

def train_cnn(X_train_cnn, y_train_cnn, X_val_cnn, y_val_cnn):
    # Verifica se há dados suficientes para treinar/validar
    if X_train_cnn.shape[0] < 2 or X_val_cnn.shape[0] < 1: # Pelo menos 2 para treino (batch>1), 1 para val
        print(f"[Train CNN] Dados insuficientes para treinar a CNN. Treino: {X_train_cnn.shape[0]}, Val: {X_val_cnn.shape[0]}. Pulando.")
        return

    model_cnn = CNN1D(vocab_size=CNN_VOCAB_SIZE, embedding_dim=CNN_EMBEDDING_DIM, num_classes=CNN_OUTPUT_CLASSES)
    optimizer_cnn = optim.Adam(model_cnn.parameters(), lr=0.0005, weight_decay=1e-5) # LR um pouco menor para CNN
    criterion_cnn = nn.BCELoss()
    # CORREÇÃO APLICADA AQUI: removido verbose e explicitado mode='min'
    scheduler_cnn = optim.lr_scheduler.ReduceLROnPlateau(optimizer_cnn, mode='min', patience=3, factor=0.5)

    # Os DataLoaders são criados dentro de train_model, não precisa aqui.
    # Apenas certifique-se que os dtypes de X_train_cnn e y_train_cnn estão corretos antes de chamar train_model
    # X_train_cnn deve ser np.int64, y_train_cnn deve ser np.float32

    trained_cnn_model = train_model(model_cnn,
                                    X_train_cnn.astype(np.int64), y_train_cnn.astype(np.float32),
                                    X_val_cnn.astype(np.int64), y_val_cnn.astype(np.float32),
                                    criterion_cnn, optimizer_cnn, scheduler_cnn,
                                    epochs=30, # Aumentar épocas para CNN, com early stopping
                                    batch_size=128, # Batch size pode ser ajustado
                                    model_name="CNN1D")

    saved_path = save_pytorch_model(trained_cnn_model, "cnn_model_base") # Salva como cnn_model_base_scripted.pt
    if saved_path and saved_path.endswith("_scripted.pt"):
        # Renomear para o nome esperado por ml_engine.cpp
        try:
            final_cnn_path = "models/cnn_model.pt"
            if os.path.exists(final_cnn_path):
                try:
                    os.remove(final_cnn_path)
                except OSError as e_rem:
                    print(f"[Train CNN] Aviso: Não foi possível remover o antigo {final_cnn_path}: {e_rem}")

            shutil.move(saved_path, final_cnn_path)
            print(f"[Train CNN] Modelo CNN final salvo como TorchScript em {final_cnn_path}")
        except Exception as e_move:
            print(f"[Train CNN] Erro ao mover/renomear modelo CNN de '{saved_path}' para '{final_cnn_path}': {e_move}")
            print(f"[Train CNN] O modelo pode estar em '{saved_path}'")
    elif not saved_path:
         print(f"[Train CNN] Scripting da CNN falhou. State dict pode ter sido salvo em models/cnn_model_base_statedict.pt.")
    else: # Caso o saved_path não termine com _scripted.pt (improvável com a lógica atual, mas para segurança)
        print(f"[Train CNN] Modelo CNN salvo em '{saved_path}', mas não foi o arquivo scriptado esperado.")


# --- Funções de Treinamento para XGBoost e LightGBM ---
def train_xgboost(X_train, y_train, X_val, y_val):
    if X_train.shape[0] < 1 or X_val.shape[0] < 1:
        print(f"[Train XGBoost] Dados insuficientes para treinar XGBoost. Treino: {X_train.shape[0]}, Val: {X_val.shape[0]}. Pulando.")
        return

    print(f"\n[Train XGBoost] Iniciando treinamento do XGBoost...")
    # y_train e y_val podem ser (N,1), ravel() os transforma em (N,)
    dtrain = xgb.DMatrix(X_train, label=y_train.ravel())
    dval = xgb.DMatrix(X_val, label=y_val.ravel())
    params = {'objective': 'binary:logistic', 'eval_metric': 'logloss', 'eta': 0.05, # Reduzido eta
              'max_depth': 5, 'subsample': 0.7, 'colsample_bytree': 0.7, 'seed': 42, # Ajustes nos hiperparâmetros
              'tree_method': 'hist'} # 'hist' é geralmente mais rápido para datasets maiores
    watchlist = [(dtrain, 'train'), (dval, 'eval')]

    callbacks = []
    if xgb.__version__ >= "1.3.0": # early_stopping_rounds é um callback a partir do 1.3.0
        callbacks.append(xgb.callback.EarlyStopping(rounds=20, metric_name='logloss', data_name='eval', save_best=True))
        num_boost_round_xgb = 200
    else: # Parâmetro direto para versões mais antigas
        num_boost_round_xgb = 200 # Ainda pode usar early_stopping_rounds no xgb.train

    print(f"[Train XGBoost] Treinando com num_boost_round={num_boost_round_xgb} e early_stopping_rounds=20 (se aplicável).")

    bst = xgb.train(params, dtrain, num_boost_round=num_boost_round_xgb,
                    evals=watchlist,
                    callbacks=callbacks if xgb.__version__ >= "1.3.0" else None,
                    early_stopping_rounds=20 if xgb.__version__ < "1.3.0" else None, # Para versões mais antigas
                    verbose_eval=50) # Imprime a cada 50 rounds

    os.makedirs("models", exist_ok=True)
    model_path = "models/xgboost.json"
    bst.save_model(model_path)
    print(f"[Train XGBoost] Modelo XGBoost salvo em {model_path}")
    if hasattr(bst, 'best_iteration') and bst.best_iteration is not None: # Para early stopping
        print(f"[Train XGBoost] Melhor iteração: {bst.best_iteration}")

def train_lightgbm(X_train, y_train, X_val, y_val):
    if X_train.shape[0] < 1 or X_val.shape[0] < 1:
        print(f"[Train LightGBM] Dados insuficientes para treinar LightGBM. Treino: {X_train.shape[0]}, Val: {X_val.shape[0]}. Pulando.")
        return

    print(f"\n[Train LightGBM] Iniciando treinamento do LightGBM...")
    lgb_train = lgb.Dataset(X_train, y_train.ravel())
    lgb_eval = lgb.Dataset(X_val, y_val.ravel(), reference=lgb_train)
    params = {'objective': 'binary', 'metric': 'binary_logloss', 'boosting_type': 'gbdt',
              'num_leaves': 31, 'learning_rate': 0.05, 'feature_fraction': 0.8, 'bagging_fraction':0.8, 'bagging_freq':5, # Adicionado bagging
              'seed': 42, 'verbose': -1, 'n_jobs': -1} # Usar todos os cores disponíveis

    num_boost_round_lgbm = 200
    print(f"[Train LightGBM] Treinando com num_boost_round={num_boost_round_lgbm} e early_stopping_rounds=20.")

    gbm = lgb.train(params, lgb_train, num_boost_round=num_boost_round_lgbm,
                    valid_sets=[lgb_train, lgb_eval],
                    callbacks=[lgb.early_stopping(stopping_rounds=20, verbose=1),
                               lgb.log_evaluation(period=50)])

    os.makedirs("models", exist_ok=True)
    model_path = "models/lightgbm.txt"
    gbm.save_model(model_path)
    print(f"[Train LightGBM] Modelo LightGBM salvo em {model_path}")
    if gbm.best_iteration is not None:
        print(f"[Train LightGBM] Melhor iteração: {gbm.best_iteration}")

# --- Loop Principal de Treinamento ---
def main_train_loop():
    print("[Train] Iniciando processo de treinamento completo...")
    df_all_for_cnn_source_data = [] # Lista para coletar todos os DataFrames ORIGINAIS para dados da CNN

    # Carregar dados e extrair features para modelos tabulares.
    # A função load_data_with_feature_extraction agora retorna X_features, y_labels, e o df_full original.
    X_pos_tab, y_pos_tab, df_pos_full_original = load_data_with_feature_extraction("models/positive_hits_features.csv")
    if df_pos_full_original is not None and not df_pos_full_original.empty:
        df_all_for_cnn_source_data.append(df_pos_full_original)

    X_neg_tab, y_neg_tab, df_neg_full_original = load_data_with_feature_extraction("models/negative_hits_features.csv")
    if df_neg_full_original is not None and not df_neg_full_original.empty:
        df_all_for_cnn_source_data.append(df_neg_full_original)

    # Preparar dados tabulares combinados para MLP, AE, XGBoost, LightGBM
    X_tabular_combined, y_tabular_combined = None, None

    # Lista para guardar os arrays X e y que são válidos para concatenação
    valid_data_list_X_tab, valid_data_list_y_tab = [], []

    if X_pos_tab is not None and y_pos_tab is not None and X_pos_tab.shape[0] > 0 and X_pos_tab.shape[0] == y_pos_tab.shape[0]:
        valid_data_list_X_tab.append(X_pos_tab)
        valid_data_list_y_tab.append(y_pos_tab)
    else:
        print("[Train] Dados positivos para modelos tabulares ausentes, inválidos ou inconsistentes.")
        if X_pos_tab is not None: print(f"  X_pos_tab shape: {X_pos_tab.shape}")
        if y_pos_tab is not None: print(f"  y_pos_tab shape: {y_pos_tab.shape}")


    if X_neg_tab is not None and y_neg_tab is not None and X_neg_tab.shape[0] > 0 and X_neg_tab.shape[0] == y_neg_tab.shape[0]:
        valid_data_list_X_tab.append(X_neg_tab)
        valid_data_list_y_tab.append(y_neg_tab)
    else:
        print("[Train] Dados negativos para modelos tabulares ausentes, inválidos ou inconsistentes.")
        if X_neg_tab is not None: print(f"  X_neg_tab shape: {X_neg_tab.shape}")
        if y_neg_tab is not None: print(f"  y_neg_tab shape: {y_neg_tab.shape}")

    if valid_data_list_X_tab and valid_data_list_y_tab:
        # Verificar consistência de features entre X_pos_tab e X_neg_tab se ambos existirem
        if len(valid_data_list_X_tab) == 2: # Ambos pos e neg estão presentes
            if valid_data_list_X_tab[0].shape[1] != valid_data_list_X_tab[1].shape[1]:
                print(f"[Train] ERRO: Discrepância de features entre datasets. Positivo: {valid_data_list_X_tab[0].shape[1]}, Negativo: {valid_data_list_X_tab[1].shape[1]}. Abortando treinamento tabular.")
                # Zera as listas para pular o treinamento tabular
                valid_data_list_X_tab, valid_data_list_y_tab = [], []

        if valid_data_list_X_tab: # Se ainda há dados válidos após a checagem
            X_tabular_combined = np.vstack(valid_data_list_X_tab)
            y_tabular_combined = np.vstack(valid_data_list_y_tab)

            actual_input_dim = X_tabular_combined.shape[1]
            print(f"[Train] Dados tabulares combinados: X: {X_tabular_combined.shape}, y: {y_tabular_combined.shape}, Features: {actual_input_dim}")

            if actual_input_dim != MLP_INPUT_DIM: # MLP_INPUT_DIM é a referência
                print(f"[Train] ERRO: Número de features extraídas ({actual_input_dim}) != MLP_INPUT_DIM ({MLP_INPUT_DIM}). Abortando treinamento tabular.")
                X_tabular_combined, y_tabular_combined = None, None # Invalida para pular treinamento
            elif X_tabular_combined.shape[0] != y_tabular_combined.shape[0]:
                print(f"[Train] ERRO: Número de amostras em X ({X_tabular_combined.shape[0]}) != y ({y_tabular_combined.shape[0]}). Abortando treinamento tabular.")
                X_tabular_combined, y_tabular_combined = None, None
    else:
        print("[Train] Nenhum dado tabular válido (positivo ou negativo) para combinar.")


    if X_tabular_combined is not None and y_tabular_combined is not None and X_tabular_combined.shape[0] > 0:
        scaler = StandardScaler()
        X_tabular_scaled = scaler.fit_transform(X_tabular_combined) # X_tabular_combined já é float32

        # Para estratificação, y_tabular_combined precisa ser 1D. Também verificar se há classes suficientes.
        y_for_stratify = y_tabular_combined.ravel()
        unique_labels, counts = np.unique(y_for_stratify, return_counts=True)
        can_stratify = len(unique_labels) > 1 and np.all(counts >= 2) # Pelo menos 2 amostras por classe para train_test_split com stratify

        if not can_stratify:
            print(f"[Train] Não é possível estratificar para divisão treino/validação. Labels únicos: {unique_labels}, Contagens: {counts}. Usando divisão não estratificada.")

        # Adicionar try-except para o train_test_split
        try:
            X_train_tab, X_val_tab, y_train_tab, y_val_tab = train_test_split(
                X_tabular_scaled, y_tabular_combined, test_size=0.2, random_state=42,
                stratify=y_for_stratify if can_stratify else None
            )
            print(f"[Train] Dados tabulares divididos: X_train: {X_train_tab.shape}, X_val: {X_val_tab.shape}")

            # Treinar Modelos Tabulares
            mlp_model = MLP(input_dim=MLP_INPUT_DIM) # MLP_INPUT_DIM já deve ser o correto
            mlp_optimizer = optim.Adam(mlp_model.parameters(), lr=0.0005, weight_decay=1e-5) # Reduzido LR
            mlp_criterion = nn.BCELoss()
            # CORREÇÃO APLICADA AQUI: removido verbose=True
            mlp_scheduler = optim.lr_scheduler.ReduceLROnPlateau(mlp_optimizer, mode='min', patience=5, factor=0.2) # Ajustado scheduler
            trained_mlp = train_model(mlp_model, X_train_tab, y_train_tab, X_val_tab, y_val_tab, mlp_criterion, mlp_optimizer, mlp_scheduler, epochs=30, batch_size=128, model_name="MLP Principal") # Ajustado batch e epochs
            mlp_scripted_path = save_pytorch_model(trained_mlp, "best_model_base")
            if mlp_scripted_path:
                try:
                    final_mlp_path = "models/best_model.pt"
                    aux_mlp_path = "models/mlp_aux_model.pt"
                    if os.path.exists(final_mlp_path): os.remove(final_mlp_path)
                    if os.path.exists(aux_mlp_path): os.remove(aux_mlp_path)
                    shutil.copy(mlp_scripted_path, final_mlp_path)
                    shutil.copy(mlp_scripted_path, aux_mlp_path) # Verificar se este aux é realmente necessário
                    print(f"[Train] MLP Principal salvo como TorchScript em {final_mlp_path} e {aux_mlp_path}")
                except Exception as e_copy_mlp: print(f"[Train] Erro ao copiar/renomear MLP: {e_copy_mlp}")


            ae_model = Autoencoder(input_dim=AE_INPUT_DIM) # AE_INPUT_DIM deve ser igual a MLP_INPUT_DIM
            ae_optimizer = optim.Adam(ae_model.parameters(), lr=0.001)
            ae_criterion = nn.MSELoss() # Autoencoders usam MSELoss
            # CORREÇÃO APLICADA AQUI: removido verbose=True
            ae_scheduler = optim.lr_scheduler.ReduceLROnPlateau(ae_optimizer, mode='min', patience=5, factor=0.2)
            # Para Autoencoder, o target é a própria entrada X_train_tab, X_val_tab
            trained_ae = train_model(ae_model, X_train_tab, X_train_tab, X_val_tab, X_val_tab, ae_criterion, ae_optimizer, ae_scheduler, epochs=20, batch_size=128, model_name="Autoencoder Principal")
            ae_scripted_path = save_pytorch_model(trained_ae, "autoencoder_base")
            if ae_scripted_path:
                try:
                    final_ae_path = "models/autoencoder.pt"
                    aux_ae_path = "models/autoencoder_global.pt" # Verificar necessidade
                    if os.path.exists(final_ae_path): os.remove(final_ae_path)
                    if os.path.exists(aux_ae_path): os.remove(aux_ae_path)
                    shutil.copy(ae_scripted_path, final_ae_path)
                    shutil.copy(ae_scripted_path, aux_ae_path)
                    print(f"[Train] Autoencoder Principal salvo como TorchScript em {final_ae_path} e {aux_ae_path}")
                except Exception as e_copy_ae: print(f"[Train] Erro ao copiar/renomear Autoencoder: {e_copy_ae}")

            train_xgboost(X_train_tab, y_train_tab, X_val_tab, y_val_tab)
            train_lightgbm(X_train_tab, y_train_tab, X_val_tab, y_val_tab)

        except ValueError as e_split_tab:
            print(f"[Train] Erro ao dividir dados tabulares para treino/validação: {e_split_tab}.")
            print("[Train] Pulando treinamento de todos os modelos tabulares.")

    else:
        print("[Train] Pulando treinamento de modelos tabulares (MLP, AE, XGBoost, LightGBM) devido à falta de dados combinados ou erro de dimensão.")

    # --- Treinamento da CNN ---
    print("\n[Train CNN] Iniciando preparação e treinamento da CNN...")
    if df_all_for_cnn_source_data:
        # Concatena os DataFrames originais (que contêm 'wif' e 'score')
        df_cnn_combined_source = pd.concat(df_all_for_cnn_source_data, ignore_index=True)

        if "wif" in df_cnn_combined_source.columns and "score" in df_cnn_combined_source.columns:
            all_wifs_for_cnn = df_cnn_combined_source["wif"].astype(str).fillna("").tolist() # Trata NaNs para string vazia
            all_labels_for_cnn = df_cnn_combined_source["score"].astype(np.float32).tolist() # Já deve ser float32

            X_cnn_processed_data, y_cnn_processed_data = preprocess_data_for_cnn(all_wifs_for_cnn, all_labels_for_cnn)

            if X_cnn_processed_data is not None and X_cnn_processed_data.shape[0] > 0 and \
               y_cnn_processed_data is not None and y_cnn_processed_data.shape[0] == X_cnn_processed_data.shape[0]:
                print(f"[Train CNN] Dados para CNN: X_cnn shape: {X_cnn_processed_data.shape}, y_cnn shape: {y_cnn_processed_data.shape}")

                y_cnn_for_stratify = y_cnn_processed_data.ravel()
                y_unique_cnn, y_counts_cnn = np.unique(y_cnn_for_stratify, return_counts=True)
                can_stratify_cnn = len(y_unique_cnn) > 1 and np.all(y_counts_cnn >= 2) # min 2 amostras por classe para split

                # Mínimo de amostras para tentar dividir (e.g., 5 amostras no total)
                min_samples_for_split_cnn = 5

                if X_cnn_processed_data.shape[0] < min_samples_for_split_cnn or not can_stratify_cnn:
                    print(f"[Train CNN] Não há amostras/classes suficientes para dividir para CNN (Total: {X_cnn_processed_data.shape[0]}, Stratify: {can_stratify_cnn}).")
                    if X_cnn_processed_data.shape[0] >= 2 : # Treinar com tudo se tiver pelo menos 2 amostras (batch > 1)
                         print("[Train CNN] Usando todos os dados disponíveis para treino e validação da CNN (sem divisão real).")
                         # Usar uma pequena porção para validação se possível, ou o mesmo dataset se muito pequeno
                         # Aqui, vamos usar o mesmo para simplicidade, mas idealmente seria uma validação mais robusta ou pular.
                         train_cnn(X_cnn_processed_data, y_cnn_processed_data, X_cnn_processed_data, y_cnn_processed_data)
                    else:
                        print("[Train CNN] Realmente muito poucos dados (<2) para treinar a CNN. Pulando.")
                else: # Dados suficientes e possível estratificar
                    try:
                        X_cnn_train, X_cnn_val, y_cnn_train, y_cnn_val = train_test_split(
                            X_cnn_processed_data, y_cnn_processed_data, test_size=0.2, random_state=42, stratify=y_cnn_for_stratify
                        )
                        print(f"[Train CNN] Dados para CNN divididos: X_train: {X_cnn_train.shape}, X_val: {X_cnn_val.shape}")
                        train_cnn(X_cnn_train, y_cnn_train, X_cnn_val, y_cnn_val)
                    except ValueError as e_split_cnn:
                         print(f"[Train CNN] Erro ao dividir dados para CNN: {e_split_cnn}. Pulando treinamento da CNN.")
            else:
                print(f"[Train CNN] Nenhum dado válido (X ou y) foi preparado para a CNN após pré-processamento ou shapes não correspondem.")
        else:
            print(f"[Train CNN] Colunas 'wif' ou 'score' não encontradas nos DataFrames combinados para treinar CNN.")
    else:
        print("[Train CNN] Nenhum DataFrame de origem para coletar WIFs para CNN.")
        # Se nenhum dado real, tentar treinar com dummy data como fallback (principalmente para testar o pipeline)
        print("[Train CNN] Tentando treinar CNN com dados dummy (sem labels reais de WIFs).")
        # preprocess_data_for_cnn(None, None) irá gerar X e y dummy
        X_cnn_dummy, y_cnn_dummy = preprocess_data_for_cnn(None, None, max_len=CNN_SEQ_LENGTH)
        if X_cnn_dummy is not None and X_cnn_dummy.shape[0] > 0:
             # Usar dummy para treino e validação
             print(f"[Train CNN] Treinando CNN com dados dummy. X_dummy shape: {X_cnn_dummy.shape}")
             train_cnn(X_cnn_dummy, y_cnn_dummy, X_cnn_dummy, y_cnn_dummy)
        else:
            print("[Train CNN] Falha ao gerar dados dummy para CNN.")


    print("\n[Train] Processo de treinamento completo finalizado.")

if __name__ == "__main__":
    # Definir sementes no início para reprodutibilidade
    torch.manual_seed(42)
    np.random.seed(42)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(42) # Para GPUs
        print(f"[Train] CUDA disponível. Versão: {torch.version.cuda}")
        # Configurações adicionais para reprodutibilidade em CUDA (podem afetar o desempenho)
        # torch.backends.cudnn.deterministic = True
        # torch.backends.cudnn.benchmark = False
    else:
        print("[Train] CUDA não disponível.")

    # Verifica se a pasta 'models' existe, senão cria
    if not os.path.exists("models"):
        os.makedirs("models")
        print("[Train] Pasta 'models' criada.")

    main_train_loop()