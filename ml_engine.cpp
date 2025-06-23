#include "ml_engine.h"
#include "RL_agent.h"
#include "hash/sha256.h" // Se usado diretamente
#include <torch/torch.h>
#include "helpers.h"
#include "IA_wrapper.h" // Inclui funções: entropy, is_palindrome, get_address_type_internal

#include <torch/script.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <filesystem>
#include <vector>
#include <string>
#include <cmath>
#include <mutex>
#include <xgboost/c_api.h>
#include <LightGBM/c_api.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <iomanip>
#include <cstdio>
#include <set>
#include <zlib.h>
#include <gmpxx.h>
#include <sys/stat.h> // Para stat (verificar existência de arquivos)
#include <deque>      // Para std::deque (usado em recent_scores)

// Inclua seus helpers e utils (certifique-se que os caminhos estão corretos)
#include "ml_helpers.h"      // Para FeatureSet, ::extract_features, etc.
#include "keyutils.h"        // Para priv_hex_to_wif, private_key_to_address
#include "bitcoin_utils.hpp" // Para is_valid_wif, is_compressed_key, etc.

using json = nlohmann::json;

// --- Definições Globais e Variáveis Estáticas ---
torch::jit::script::Module g_model;
static bool g_model_loaded = false;
torch::jit::script::Module g_autoencoder;

static torch::jit::script::Module mlp_model_global;
static torch::jit::script::Module autoencoder_model_global;
static BoosterHandle xgboost_model = nullptr;
static BoosterHandle lightgbm_model = nullptr;
static torch::jit::script::Module cnn_model_global;

static bool mlp_g_loaded = false;
static bool ae_g_loaded = false;
static bool xgb_loaded = false;
static bool lgb_loaded = false;
static bool cnn_g_loaded = false;

const int INPUT_DIM_FEATURES = 29;

static std::vector<std::vector<float>> g_puzzle_pattern_features;
static std::mutex ml_mutex; // Mutex global para operações de ML críticas

static std::vector<std::vector<float>> train_data;
static std::vector<float> train_labels;

static std::deque<float> recent_scores_g;
static std::mutex score_mutex_g; // Mutex separado para recent_scores_g

// --- Implementação de combined_key_score (heurística) ---
float combined_key_score(const std::string& s) {
    if (s.empty()) { return 0.0f; }
    try {
        uLongf compressed_len = compressBound(s.length());
        std::vector<unsigned char> compressed_data(compressed_len);
        if (s.length() == 0) { return 0.0f; }
        if (compress(compressed_data.data(), &compressed_len, (const Bytef*)s.c_str(), s.length()) != Z_OK) {
            std::cerr << "[ML DEBUG CSCORE] Erro zlib compress para: " << s << std::endl; std::cerr.flush();
            return 0.0f;
        }
        float kolmogorov = (s.length() > 0) ? static_cast<float>(compressed_len) / s.length() : 0.0f;

        std::vector<int> counts(16, 0);
        for (char c : s) {
            if (c >= '0' && c <= '9') counts[c - '0']++;
            else if (c >= 'a' && c <= 'f') counts[c - 'a' + 10]++;
            else if (c >= 'A' && c <= 'F') counts[c - 'A' + 10]++;
        }
        float repetition = 0.0f;
        if (s.length() > 0 && !counts.empty()) { 
            repetition = static_cast<float>(*std::max_element(counts.begin(), counts.end())) / s.length();
        }

        mpz_class n_mpz;
        if (!s.empty()) {
             try {
                n_mpz.set_str(s, 16);
             } catch (const std::exception& e_mpz) {
                std::cerr << "[ML DEBUG CSCORE] Erro ao converter hex '" << s << "' para mpz_class: " << e_mpz.what() << std::endl; std::cerr.flush();
                n_mpz = 0;
             }
        } else {
            n_mpz = 0;
        }

        int primes[] = {2, 3, 5, 7, 11};
        float divisibility = 0.0f;
        if (n_mpz != 0) {
            for (int p : primes) if (mpz_divisible_ui_p(n_mpz.get_mpz_t(), p)) divisibility += 1.0f;
        }
        if (sizeof(primes)/sizeof(primes[0]) > 0) { 
            divisibility /= static_cast<float>(sizeof(primes)/sizeof(primes[0]));
        } else {
            divisibility = 0.0f;
        }

        int max_run_len = 0;
        if (!s.empty()) {
            max_run_len = 1;
            int current_run_len = 1;
            char last_char_run = s[0];
            for (size_t i = 1; i < s.length(); ++i) {
                if (s[i] == last_char_run) {
                    current_run_len++;
                } else {
                    max_run_len = std::max(max_run_len, current_run_len);
                    current_run_len = 1;
                    last_char_run = s[i];
                }
            }
            max_run_len = std::max(max_run_len, current_run_len);
        }
        float run_length_feat = s.length() > 0 ? static_cast<float>(max_run_len) / s.length() : 0.0f;

        float w_kolmogorov = 0.4f;
        float w_repetition = 0.3f;
        float w_divisibility = 0.15f;
        float w_run_length = 0.15f;

        float score_val = (
            w_kolmogorov * (1.0f - kolmogorov) +
            w_repetition * (1.0f - repetition) +
            w_divisibility * divisibility +
            w_run_length * (1.0f - run_length_feat)
        );
        float total_weights = w_kolmogorov + w_repetition + w_divisibility + w_run_length;
        if (total_weights == 0.0f) { return 0.0f; }

        float final_score = std::min(std::max(score_val / total_weights, 0.0f), 1.0f);
        return final_score;
    } catch (const std::exception& e) {
        std::cerr << "[ML] Erro em combined_key_score para '" << s << "': " << e.what() << std::endl; std::cerr.flush();
        return 0.0f;
    }
}

float evaluate_mlp(const std::vector<float>& features) {
    if (!mlp_g_loaded) { return 0.0f; }
    if (features.size() != INPUT_DIM_FEATURES) {
        return 0.0f;
    }
    try {
        torch::Tensor input_tensor = torch::from_blob(const_cast<float*>(features.data()), {1, static_cast<long>(features.size())}, torch::kFloat32).clone();
        std::vector<torch::jit::IValue> inputs_vec;
        inputs_vec.push_back(input_tensor);
        at::Tensor output = mlp_model_global.forward(inputs_vec).toTensor();
        float score = output.item<float>();
        return score;
    } catch (const c10::Error& e) { std::cerr << "[ML] Erro c10 (LibTorch) MLP Global: " << e.what() << std::endl; std::cerr.flush(); return 0.0f; }
    catch (const std::exception& e) {std::cerr << "[ML] Erro std::exception MLP Global: " << e.what() << std::endl; std::cerr.flush(); return 0.0f;}
}

float evaluate_autoencoder(const std::vector<float>& features) {
    if (!ae_g_loaded) { return 0.0f; }
    if (features.size() != INPUT_DIM_FEATURES) {
        return 0.0f;
    }
    try {
        torch::Tensor input_tensor = torch::from_blob(const_cast<float*>(features.data()), {1, static_cast<long>(features.size())}, torch::kFloat32).clone();
        std::vector<torch::jit::IValue> inputs_vec;
        inputs_vec.push_back(input_tensor);
        at::Tensor reconstructed_tensor = autoencoder_model_global.forward(inputs_vec).toTensor();
        torch::Tensor loss = torch::mse_loss(reconstructed_tensor, input_tensor);
        float loss_val = loss.item<float>();
        return loss_val;
    } catch (const c10::Error& e) { std::cerr << "[ML] Erro c10 (LibTorch) Autoencoder Global: " << e.what() << std::endl; std::cerr.flush(); return 0.0f; }
    catch (const std::exception& e) {std::cerr << "[ML] Erro std::exception Autoencoder Global: " << e.what() << std::endl; std::cerr.flush(); return 0.0f;}
}

float evaluate_xgboost(const std::vector<float>& features) {
    if (!xgb_loaded || xgboost_model == nullptr) { return 0.0f; }
    if (features.size() != INPUT_DIM_FEATURES) {
        return 0.0f;
    }
    DMatrixHandle dmat;
    if (XGDMatrixCreateFromMat(features.data(), 1, static_cast<bst_ulong>(features.size()), 0.0f, &dmat) != 0) {
        std::cerr << "[ML] Erro DMatrix XGBoost: " << XGBGetLastError() << std::endl; std::cerr.flush(); return 0.0f;
    }
    bst_ulong out_len;
    const float* out_result = nullptr;
    if (XGBoosterPredict(xgboost_model, dmat, 0, 0, 0, &out_len, &out_result) != 0) {
        std::cerr << "[ML] Erro prever XGBoost: " << XGBGetLastError() << std::endl; std::cerr.flush(); XGDMatrixFree(dmat); return 0.0f;
    }
    if (out_len == 0 || out_result == nullptr) { XGDMatrixFree(dmat); return 0.0f; }
    float score = out_result[0];
    XGDMatrixFree(dmat);
    return score;
}

float evaluate_lightgbm(const std::vector<float>& features) {
    if (!lgb_loaded || lightgbm_model == nullptr) { return 0.0f; }
    if (features.size() != INPUT_DIM_FEATURES) {
        return 0.0f;
    }
    double out_result_lgbm[1];
    int64_t out_len_lgbm = 0;
    int status = LGBM_BoosterPredictForMat(lightgbm_model, static_cast<const void*>(features.data()), C_API_DTYPE_FLOAT32, 1, static_cast<int>(features.size()), 1, C_API_PREDICT_NORMAL, 0, -1, "num_threads=1", &out_len_lgbm, out_result_lgbm);
    if (status != 0) { std::cerr << "[ML] Erro prever LightGBM. Código: " << status << ". Mensagem: " << LGBM_GetLastError() << std::endl; std::cerr.flush(); return 0.0f; }
    if (out_len_lgbm == 0) { return 0.0f; }
    float score = static_cast<float>(out_result_lgbm[0]);
    return score;
}

bool load_models(const std::string& mlp_path_param) {
    std::cout << "[DEBUG LM_GLOBAL] Entrando em load_models..." << std::endl; std::cout.flush();
    // std::lock_guard<std::mutex> lock(ml_mutex); // CORREÇÃO: Linha removida
    mlp_g_loaded = false;
    ae_g_loaded = false;
    xgb_loaded = false;
    lgb_loaded = false;
    struct stat buffer_stat;

    std::string actual_mlp_path = mlp_path_param;
    std::cout << "[DEBUG LM_GLOBAL] Ponto LM1: Carregando mlp_model_global de " << actual_mlp_path << "..." << std::endl; std::cout.flush();
    if (!actual_mlp_path.empty() && stat(actual_mlp_path.c_str(), &buffer_stat) == 0) {
        try {
            std::cout << "[DEBUG LM_GLOBAL] Tentando carregar mlp_model_global com torch::jit::load..." << std::endl; std::cout.flush();
            mlp_model_global = torch::jit::load(actual_mlp_path);
            std::cout << "[DEBUG LM_GLOBAL] torch::jit::load concluído." << std::endl; std::cout.flush();
            mlp_model_global.eval();
            mlp_g_loaded = true;
            std::cout << "[ML] Modelo MLP Global Auxiliar carregado: " << actual_mlp_path << std::endl; std::cout.flush();
        } catch (const std::exception& e) { std::cerr << "[ML] Falha ao carregar MLP Global Auxiliar " << actual_mlp_path << ": " << e.what() << std::endl; std::cerr.flush(); }
    } else if (!actual_mlp_path.empty()) { std::cout << "[ML] Arquivo MLP Global Auxiliar não encontrado: " << actual_mlp_path << std::endl; std::cout.flush(); }
    std::cout << "[DEBUG LM_GLOBAL] Ponto LM2: Após mlp_model_global." << std::endl; std::cout.flush();

    std::string ae_model_path = "models/autoencoder_global.pt";
    std::cout << "[DEBUG LM_GLOBAL] Ponto LM3: Carregando autoencoder_model_global de " << ae_model_path << "..." << std::endl; std::cout.flush();
    if (stat(ae_model_path.c_str(), &buffer_stat) == 0) {
        try {
            autoencoder_model_global = torch::jit::load(ae_model_path);
            autoencoder_model_global.eval();
            ae_g_loaded = true;
            std::cout << "[ML] Modelo Autoencoder Global Auxiliar carregado: " << ae_model_path << std::endl; std::cout.flush();
        } catch (const std::exception& e) { std::cerr << "[ML] Falha ao carregar Autoencoder Global Auxiliar " << ae_model_path << ": " << e.what() << std::endl; std::cerr.flush(); }
    } else { std::cout << "[ML] Arquivo Autoencoder Global Auxiliar não encontrado: " << ae_model_path << std::endl; std::cout.flush(); }
    std::cout << "[DEBUG LM_GLOBAL] Ponto LM4: Após autoencoder_model_global." << std::endl; std::cout.flush();

    std::string xgb_model_path = "models/xgboost.json";
    std::cout << "[DEBUG LM_GLOBAL] Ponto LM5: Carregando xgboost_model de " << xgb_model_path << "..." << std::endl; std::cout.flush();
     if (stat(xgb_model_path.c_str(), &buffer_stat) == 0) {
        if (XGBoosterCreate(nullptr, 0, &xgboost_model) == 0) {
            if (XGBoosterLoadModel(xgboost_model, xgb_model_path.c_str()) == 0) {
                xgb_loaded = true;
                std::cout << "[ML] Modelo XGBoost carregado: " << xgb_model_path << std::endl; std::cout.flush();
            } else { std::cerr << "[ML] Falha ao carregar modelo XGBoost: " << XGBGetLastError() << std::endl; std::cerr.flush(); XGBoosterFree(xgboost_model); xgboost_model = nullptr; }
        } else { std::cerr << "[ML] Falha ao criar handler XGBoost: " << XGBGetLastError() << std::endl; std::cerr.flush(); }
    } else { std::cout << "[ML] Arquivo XGBoost não encontrado: " << xgb_model_path << std::endl; std::cout.flush(); }
    std::cout << "[DEBUG LM_GLOBAL] Ponto LM6: Após xgboost_model." << std::endl; std::cout.flush();

    std::string lgb_model_path = "models/lightgbm.txt";
    std::cout << "[DEBUG LM_GLOBAL] Ponto LM7: Carregando lightgbm_model de " << lgb_model_path << "..." << std::endl; std::cout.flush();
    if (stat(lgb_model_path.c_str(), &buffer_stat) == 0) {
        int num_iterations_out = 0;
        if (LGBM_BoosterCreateFromModelfile(lgb_model_path.c_str(), &num_iterations_out, &lightgbm_model) == 0) {
            lgb_loaded = true;
            std::cout << "[ML] Modelo LightGBM carregado: " << lgb_model_path << std::endl; std::cout.flush();
        } else { std::cerr << "[ML] Falha ao carregar modelo LightGBM: " << LGBM_GetLastError() << std::endl; std::cerr.flush(); }
    } else { std::cout << "[ML] Arquivo LightGBM não encontrado: " << lgb_model_path << std::endl; std::cout.flush(); }
    std::cout << "[DEBUG LM_GLOBAL] Ponto LM8: Saindo de load_models." << std::endl; std::cout.flush();

    bool all_loaded = mlp_g_loaded && ae_g_loaded && xgb_loaded && lgb_loaded;
    if (!all_loaded) {
        std::cerr << "[ML] Nem todos os modelos auxiliares foram carregados corretamente." << std::endl;
    }
    return all_loaded;
}

// DEFINIÇÃO DE ml_load_puzzle_patterns MOVIDA PARA ANTES DE ml_init
void ml_load_puzzle_patterns(const std::string& path) {
    std::cout << "[DEBUG PUZZLE_LOAD_PATTERNS] Entrando para " << path << std::endl; std::cout.flush();
    // std::lock_guard<std::mutex> lock(ml_mutex); // REMOVIDO - ml_mutex já está bloqueado por ml_init
    
    std::ifstream file(path);
    if (!file.is_open()) { std::cerr << "[ML] Não foi possível abrir arquivo puzzle: " << path << std::endl; std::cerr.flush(); return; }
    std::string line, header_line_puzzle;
    if (!std::getline(file, header_line_puzzle)) { std::cerr << "[ML] Erro ao ler header ou arquivo puzzle vazio: " << path << std::endl; std::cerr.flush(); return; }

    int loaded_patterns_count_local = 0; 
    int line_num_puzzle_local = 1;       
    
    g_puzzle_pattern_features.clear(); 

    while (std::getline(file, line)) {
        line_num_puzzle_local++;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string s_priv_hex_csv, s_privkey_int_csv, s_wif_csv, s_compressed_pub_csv, s_uncompressed_pub_csv, s_address_csv, s_rmd160_csv, s_score_str_csv;

        if (std::getline(ss, s_priv_hex_csv, ',') && std::getline(ss, s_privkey_int_csv, ',') &&
            std::getline(ss, s_wif_csv, ',') && std::getline(ss, s_compressed_pub_csv, ',') &&
            std::getline(ss, s_uncompressed_pub_csv, ',') && std::getline(ss, s_address_csv, ',') &&
            std::getline(ss, s_rmd160_csv, ',') && std::getline(ss, s_score_str_csv)) {

            FeatureSet f_puzzle_local = ::extract_features(s_priv_hex_csv); 
            std::vector<float> feats_puzzle_local = f_puzzle_local.to_vector(); 

            if (feats_puzzle_local.size() == INPUT_DIM_FEATURES) {
                g_puzzle_pattern_features.push_back(feats_puzzle_local);
                loaded_patterns_count_local++;
            }
        }
    }
    if (loaded_patterns_count_local > 0) {
        std::cout << "[ML] Padrões Puzzle carregados: " << loaded_patterns_count_local << " de " << path << std::endl; std::cout.flush();
    }
    std::cout << "[DEBUG PUZZLE_LOAD_PATTERNS] Saindo de " << path << std::endl; std::cout.flush();
}


bool MLEngine::ml_init(const std::string& model_path, const std::string& positive_features_path) {
    std::cout << "[DEBUG ML_ENGINE_INIT] Entrando em MLEngine::ml_init..." << std::endl; std::cout.flush();
    std::lock_guard<std::mutex> lock(ml_mutex); 
    MLEngine::is_initialized = false;

    struct stat buffer_stat_check;

    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 1: Carregando MLEngine::model de " << model_path << "..." << std::endl; std::cout.flush();
    if (!model_path.empty()) {
        if (stat(model_path.c_str(), &buffer_stat_check) == 0) {
            try {
                MLEngine::model = torch::jit::load(model_path);
                MLEngine::model.eval();
                MLEngine::is_initialized = true;
                std::cout << "[ML] Modelo principal da classe (MLEngine::model) carregado: " << model_path << std::endl; std::cout.flush();
            } catch (const c10::Error& e) {
                std::cerr << "[ML] Falha ao carregar modelo principal da classe (MLEngine::model) " << model_path << ": " << e.what() << std::endl; std::cerr.flush();
            }
        } else {
            std::cout << "[ML] Arquivo do modelo principal da classe (MLEngine::model) não encontrado: " << model_path << std::endl; std::cout.flush();
        }
    } else {
         std::cout << "[ML] Caminho do modelo principal da classe (MLEngine::model) não fornecido." << std::endl; std::cout.flush();
    }
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 2: Após carregar MLEngine::model." << std::endl; std::cout.flush();

    g_model_loaded = false;
    if (!model_path.empty() && stat(model_path.c_str(), &buffer_stat_check) == 0) {
        try {
            std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 3: Carregando g_model (MLP Original) de " << model_path << "..." << std::endl; std::cout.flush();
            g_model = torch::jit::load(model_path);
            g_model.eval();
            g_model_loaded = true;
            std::cout << "[ML] Modelo global g_model (MLP original) carregado: " << model_path << std::endl; std::cout.flush();
        } catch (const c10::Error& e) { std::cerr << "[ML] Falha ao carregar g_model (MLP original) " << model_path << ": " << e.what() << std::endl; std::cerr.flush();}
    }
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 4: Após carregar g_model." << std::endl; std::cout.flush();

    std::string g_ae_path = "models/autoencoder.pt";
    if (stat(g_ae_path.c_str(), &buffer_stat_check) == 0) {
        try {
            std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 5: Carregando g_autoencoder de " << g_ae_path << "..." << std::endl; std::cout.flush();
            g_autoencoder = torch::jit::load(g_ae_path);
            g_autoencoder.eval();
            std::cout << "[ML] Modelo global g_autoencoder carregado: " << g_ae_path << std::endl; std::cout.flush(); 
        } catch (const c10::Error& e) { std::cerr << "[ML] Falha ao carregar g_autoencoder " << g_ae_path << ": " << e.what() << std::endl; std::cerr.flush();}
    } else { std::cout << "[ML] Arquivo do modelo global g_autoencoder não encontrado: " << g_ae_path << std::endl; std::cout.flush(); }
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 6: Após carregar g_autoencoder." << std::endl; std::cout.flush();

    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 7: Antes de MLEngine::ml_load_cnn_model." << std::endl; std::cout.flush();
    MLEngine::ml_load_cnn_model("models/cnn_model.pt"); 
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 8: Depois de MLEngine::ml_load_cnn_model." << std::endl; std::cout.flush();

    std::string mlp_aux_path = "models/mlp_aux_model.pt";
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 9: Antes de ::load_models." << std::endl; std::cout.flush();

    if (stat(mlp_aux_path.c_str(), &buffer_stat_check) == 0 && buffer_stat_check.st_size > 1000) {
    std::cout << "[DEBUG ML_ENGINE_INIT] mlp_aux_model.pt encontrado. Chamando load_models..." << std::endl; std::cout.flush();
    ::load_models(mlp_aux_path); 
    } else {
        std::cout << "[DEBUG ML_ENGINE_INIT] Arquivo ausente ou inválido. Pulando load_models." << std::endl; std::cout.flush();
    }

    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 10: Depois de ::load_models." << std::endl; std::cout.flush();

    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 11: Antes de carregar dados de treinamento positivos de " << positive_features_path << "..." << std::endl; std::cout.flush();
    if (!positive_features_path.empty() && stat(positive_features_path.c_str(), &buffer_stat_check) == 0) {
        if (!MLEngine::ml_load_training_data(positive_features_path, true)) {
             std::cerr << "[ML DEBUG] ml_load_training_data (positive) retornou false." << std::endl; std::cerr.flush();
        }
    } else if (!positive_features_path.empty()) {
        std::cout << "[ML] Arquivo de dados de treinamento positivo não encontrado: " << positive_features_path << std::endl; std::cout.flush();
    }
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 12: Depois de carregar dados de treinamento positivos." << std::endl; std::cout.flush();

    const std::string negative_csv_path = "models/negative_hits_features.csv";
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 13: Antes de carregar dados de treinamento negativos de " << negative_csv_path << "..." << std::endl; std::cout.flush();
    if (stat(negative_csv_path.c_str(), &buffer_stat_check) == 0) {
        if (!MLEngine::ml_load_training_data(negative_csv_path, false)) {
            std::cerr << "[ML DEBUG] ml_load_training_data (negative) retornou false." << std::endl; std::cerr.flush();
        }
    } else {
        std::cout << "[ML] Arquivo de dados de treinamento negativo não encontrado: " << negative_csv_path << std::endl; std::cout.flush();
    }
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 14: Depois de carregar dados de treinamento negativos." << std::endl; std::cout.flush();

    const std::string puzzle_patterns_path_const = "models/puzzle_pattern_model.csv"; // Renomeada para evitar conflito
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 15: Antes de ml_load_puzzle_patterns de " << puzzle_patterns_path_const << "..." << std::endl; std::cout.flush();
    if (stat(puzzle_patterns_path_const.c_str(), &buffer_stat_check) == 0) {
        ml_load_puzzle_patterns(puzzle_patterns_path_const); 
    } else {
        std::cout << "[ML] Arquivo de padrões puzzle não encontrado: " << puzzle_patterns_path_const << std::endl; std::cout.flush();
    }
    std::cout << "[DEBUG ML_ENGINE_INIT] Ponto 16: Depois de ml_load_puzzle_patterns." << std::endl; std::cout.flush();

    std::cout << "[DEBUG ML_ENGINE_INIT] Fim de MLEngine::ml_init. Estado inicializado: " << MLEngine::is_initialized << std::endl; std::cout.flush();
    return MLEngine::is_initialized;
}

// Restante das definições de MLEngine::ml_predict, ml_score, etc.
// ... (como na versão anterior)

float MLEngine::ml_predict(const FeatureSet& f) {
    std::cout << "[DEBUG ML_ENGINE_PREDICT_FS] Entrando..." << std::endl; std::cout.flush();
    std::vector<float> features_vec = f.to_vector();
    if (features_vec.empty()) {
        std::cout << "[DEBUG ML_ENGINE_PREDICT_FS] Vetor de features vazio." << std::endl; std::cout.flush();
        return 0.0f;
    }
    if (features_vec.size() != INPUT_DIM_FEATURES) {
        std::cout << "[DEBUG ML_ENGINE_PREDICT_FS] Tamanho incorreto do vetor de features: " << features_vec.size() << " esperado " << INPUT_DIM_FEATURES << std::endl; std::cout.flush();
        return 0.0f;
    }
    float result = MLEngine::ml_predict(features_vec);
    std::cout << "[DEBUG ML_ENGINE_PREDICT_FS] Saindo com resultado: " << result << std::endl; std::cout.flush();
    return result;
}

float MLEngine::ml_predict(const std::vector<float>& features_vec) {
    std::cout << "[DEBUG ML_ENGINE_PREDICT_VEC] Entrando..." << std::endl; std::cout.flush();
    if (!MLEngine::is_initialized) {
        std::cout << "[DEBUG ML_ENGINE_PREDICT_VEC] MLEngine::model não inicializado." << std::endl; std::cout.flush();
        return 0.0f;
    }
    if (features_vec.size() != INPUT_DIM_FEATURES) {
        std::cout << "[DEBUG ML_ENGINE_PREDICT_VEC] Tamanho de entrada incorreto: " << features_vec.size() << " esperado " << INPUT_DIM_FEATURES << std::endl; std::cout.flush();
        return 0.0f;
    }

    try {
        torch::Tensor x = torch::from_blob(const_cast<float*>(features_vec.data()), {1, static_cast<long>(features_vec.size())}, torch::kFloat32).clone();
        std::vector<torch::jit::IValue> inputs_cls;
        inputs_cls.push_back(x);
        auto output = MLEngine::model.forward(inputs_cls).toTensor();
        float result = output.item<float>();
        std::cout << "[DEBUG ML_ENGINE_PREDICT_VEC] Saindo com resultado: " << result << std::endl; std::cout.flush();
        return result;
    } catch (const c10::Error& e) {
        std::cerr << "[ML] Erro c10 (LibTorch) em MLEngine::ml_predict(vector): " << e.what() << std::endl; std::cerr.flush();
        return 0.0f;
    } catch (const std::exception& e) {
        std::cerr << "[ML] Erro std::exception em MLEngine::ml_predict(vector): " << e.what() << std::endl; std::cerr.flush();
        return 0.0f;
    }
}

float MLEngine::ml_score(const FeatureSet& f) {
    std::vector<float> features_vec = f.to_vector();
    if (features_vec.empty() || features_vec.size() != INPUT_DIM_FEATURES) {
        return 0.0f;
    }

    float score_pytorch_main_cls = 0.0f;
    if (MLEngine::is_initialized) {
        score_pytorch_main_cls = MLEngine::ml_predict(features_vec);
    }

    float score_heuristico = 0.0f;
    if (!f.s_priv_hex.empty()) {
         score_heuristico = ::combined_key_score(f.s_priv_hex);
    }

    float score_mlp_g_aux = mlp_g_loaded ? ::evaluate_mlp(features_vec) : 0.0f;
    float score_ae_loss_g_aux = ae_g_loaded ? ::evaluate_autoencoder(features_vec) : 0.0f;
    float score_xgb_g_aux = xgb_loaded ? ::evaluate_xgboost(features_vec) : 0.0f;
    float score_lgbm_g_aux = lgb_loaded ? ::evaluate_lightgbm(features_vec) : 0.0f;

    float score_cnn_g = 0.0f;
    if (cnn_g_loaded) {
        if (!f.wif_compressed.empty()) {
            score_cnn_g = MLEngine::ml_run_cnn(f.wif_compressed);
        } else if (!f.wif.empty()) {
            score_cnn_g = MLEngine::ml_run_cnn(f.wif);
        }
    }

    float w_pytorch_cls  = 0.30f;
    float w_heuristico   = 0.10f;
    float w_mlp_g_aux    = 0.10f;
    float w_anomalia     = 0.10f;
    float w_xgb_g_aux    = 0.15f;
    float w_lgbm_g_aux   = 0.15f;
    float w_cnn_g        = 0.10f;

    float max_expected_ae_loss = 1.0f;
    float score_anomalia_normalizado = std::max(0.0f, 1.0f - (score_ae_loss_g_aux / (max_expected_ae_loss + 1e-6f)));

    float combined_score_val = 0.0f;
    float total_weight = 1e-6f; 

    if (MLEngine::is_initialized) { combined_score_val += w_pytorch_cls * score_pytorch_main_cls; total_weight += w_pytorch_cls; }
    if (!f.s_priv_hex.empty()) { combined_score_val += w_heuristico * score_heuristico; total_weight += w_heuristico; }
    if (mlp_g_loaded) { combined_score_val += w_mlp_g_aux * score_mlp_g_aux; total_weight += w_mlp_g_aux; }
    if (ae_g_loaded) { combined_score_val += w_anomalia * score_anomalia_normalizado; total_weight += w_anomalia; }
    if (xgb_loaded) { combined_score_val += w_xgb_g_aux * score_xgb_g_aux; total_weight += w_xgb_g_aux; }
    if (lgb_loaded) { combined_score_val += w_lgbm_g_aux * score_lgbm_g_aux; total_weight += w_lgbm_g_aux; }
    if (cnn_g_loaded && (!f.wif.empty() || !f.wif_compressed.empty())){ combined_score_val += w_cnn_g * score_cnn_g; total_weight += w_cnn_g; }
    
    if (total_weight <= 1e-5f) return 0.0f; 

    float final_combined_score = std::min(std::max(combined_score_val / total_weight, 0.0f), 1.0f);
    return final_combined_score;
}

float MLEngine::ml_xgboost_score(const FeatureSet& f) {
    if (!xgb_loaded) {
        return 0.0f;
    }
    std::vector<float> features_vec = f.to_vector();
    if (features_vec.empty() || features_vec.size() != INPUT_DIM_FEATURES) {
        return 0.0f;
    }
    float score = ::evaluate_xgboost(features_vec);
    return score;
}

bool MLEngine::ml_load_training_data(const std::string& path, bool positive_param) {
    // Carregamento de dados pode gerar milhares de linhas; limite a verbosidade
    const int progress_interval = 50000; // Atualiza a cada 50k linhas
    std::uintmax_t total_bytes = 0;
    try {
        total_bytes = std::filesystem::file_size(path);
    } catch (...) {
        total_bytes = 0;
    }
    size_t last_percent = 0;
    // std::lock_guard<std::mutex> lock(ml_mutex); // REMOVIDO - ml_mutex já está bloqueado por ml_init
    
    std::ifstream data_file(path);
    if (!data_file.is_open()) { 
        std::cerr << "[ML] Não foi possível abrir arquivo de dados: " << path << std::endl; std::cerr.flush(); 
        return false; 
    }
    std::string line, header_line;
    if (!std::getline(data_file, header_line)) {
        std::cerr << "[ML] Erro ao ler header ou arquivo CSV vazio: " << path << std::endl; std::cerr.flush(); 
        return false; 
    }
    // Header do CSV lido com sucesso

    int line_count_local = 1;
    int loaded_count_local = 0;
    while (std::getline(data_file, line)) {
        line_count_local++;
        if (line_count_local % progress_interval == 0) {
            std::streampos pos = data_file.tellg();
            if (pos == std::streampos(-1)) pos = 0;
            size_t percent = 0;
            if (total_bytes > 0)
                percent = static_cast<size_t>(100.0 * static_cast<double>(pos) / static_cast<double>(total_bytes));
            if (percent != last_percent) {
                const size_t bar_width = 40;
                size_t filled = percent * bar_width / 100;
                std::cout << "\r[ML] [";
                for (size_t i = 0; i < bar_width; ++i) std::cout << (i < filled ? '#' : '-');
                std::cout << "] " << std::setw(3) << percent << "% (" << line_count_local << " linhas)" << std::flush;
                last_percent = percent;
            }
        }

        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (line.empty()) {
            continue;
        }
        
        std::stringstream ss(line);
        std::string s_priv_hex_csv, s_privkey_int_csv, s_wif_csv, s_compressed_pub_csv, s_uncompressed_pub_csv, s_address_csv, s_rmd160_csv, s_score_str_csv;

        if (std::getline(ss, s_priv_hex_csv, ',') && std::getline(ss, s_privkey_int_csv, ',') &&
            std::getline(ss, s_wif_csv, ',') && std::getline(ss, s_compressed_pub_csv, ',') &&
            std::getline(ss, s_uncompressed_pub_csv, ',') && std::getline(ss, s_address_csv, ',') &&
            std::getline(ss, s_rmd160_csv, ',') && std::getline(ss, s_score_str_csv)) {
            
            try {
                float label_val_local = std::stof(s_score_str_csv);
                FeatureSet f_csv_local = ::extract_features(s_priv_hex_csv);

                std::vector<float> feats_csv_local = f_csv_local.to_vector();

                if (feats_csv_local.size() == INPUT_DIM_FEATURES) {
                    train_data.push_back(feats_csv_local);
                    train_labels.push_back(label_val_local);
                    loaded_count_local++;
                    // dados válidos adicionados
                } else {
                     /* verbose warning removed */
                }
            } catch (const std::exception& e) {
                /* verbose error removed */
            }
        } else if (!line.empty()) {
            /* verbose parse warning removed */
        }
    }
    std::cout << std::endl;
    std::cout << "[ML] Carregadas " << loaded_count_local << " amostras de " << path
              << " (linhas processadas: " << line_count_local << ")" << std::endl;
    return loaded_count_local > 0;
}

void MLEngine::ml_update_model(const unsigned char* address, bool is_hit) {
    std::lock_guard<std::mutex> lock(ml_mutex);
    if (!is_initialized || train_data.empty()) return;
    try {
        std::vector<float> flat;
        for (const auto& row : train_data) flat.insert(flat.end(), row.begin(), row.end());
        torch::Tensor data = torch::from_blob(flat.data(), {(long)train_data.size(), INPUT_DIM_FEATURES}, torch::kFloat32).clone();
        torch::Tensor labels = torch::from_blob(train_labels.data(), {(long)train_labels.size(),1}, torch::kFloat32).clone();
        static torch::optim::SGD opt(model.parameters(), torch::optim::SGDOptions(0.001));
        model.train();
        opt.zero_grad();
        auto out = model.forward({data}).toTensor();
        auto loss = torch::binary_cross_entropy(out, labels);
        loss.backward();
        opt.step();
        model.eval();
        std::cout << "[ML] Modelo atualizado com " << train_data.size() << " exemplos." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ML] Erro em ml_update_model: " << e.what() << std::endl;
    }
}

void MLEngine::ml_report_heatmap() {
    std::cout << "[DEBUG ML_ENGINE_REPORT] Entrando..." << std::endl; std::cout.flush();
    std::lock_guard<std::mutex> lock(ml_mutex); 
    std::cout << "[ML] Amostras de treinamento (buffer): " << train_data.size() << std::endl; std::cout.flush();
    if (!train_labels.empty() && train_data.size() == train_labels.size()) {
        long positive_hits_count_local = std::count_if(train_labels.begin(), train_labels.end(), [](float label){ return label > 0.5f; });
        std::cout << "[ML] Positivas (buffer): " << positive_hits_count_local
                  << ", Negativas (buffer): " << (train_labels.size() - positive_hits_count_local) << std::endl; std::cout.flush();
    }
    std::cout << "[DEBUG ML_ENGINE_REPORT] Saindo." << std::endl; std::cout.flush();
}

void MLEngine::ml_load_cnn_model(const std::string& model_path_cnn) {
    fprintf(stderr, "[DEBUG CNN_LOAD_ENTRY] Função ml_load_cnn_model iniciada com path: %s\n", model_path_cnn.c_str()); fflush(stderr);
    cnn_g_loaded = false;
    if (model_path_cnn.empty()) {
        fprintf(stderr, "[ML] Caminho do modelo CNN não fornecido.\n"); fflush(stderr);
        fprintf(stderr, "[DEBUG CNN_LOAD_EXIT] Saindo (caminho vazio).\n"); fflush(stderr);
        return;
    }
    fprintf(stderr, "[DEBUG CNN_LOAD_STAT] Verificando existência do arquivo: %s\n", model_path_cnn.c_str()); fflush(stderr);
    struct stat buffer_stat_cnn;
    if (stat(model_path_cnn.c_str(), &buffer_stat_cnn) == 0) {
        fprintf(stderr, "[DEBUG CNN_LOAD_STAT_OK] Arquivo encontrado. Tentando carregar com torch::jit::load...\n"); fflush(stderr);
        try {
            cnn_model_global = torch::jit::load(model_path_cnn);
            fprintf(stderr, "[DEBUG CNN_LOAD_TORCH_OK] torch::jit::load concluído. Executando eval()...\n"); fflush(stderr);
            cnn_model_global.eval();
            cnn_g_loaded = true;
            fprintf(stderr, "[ML] Modelo CNN Global carregado: %s\n", model_path_cnn.c_str()); fflush(stderr);
        } catch (const c10::Error& e) {
            fprintf(stderr, "[ML DEBUG] Falha c10::Error ao carregar modelo CNN Global %s: %s\n", model_path_cnn.c_str(), e.what()); fflush(stderr);
        } catch (const std::exception& e) {
            fprintf(stderr, "[ML DEBUG] Falha std::exception ao carregar modelo CNN Global %s: %s\n", model_path_cnn.c_str(), e.what()); fflush(stderr);
        } catch (...) {
            fprintf(stderr, "[ML DEBUG] Falha desconhecida ao carregar modelo CNN Global %s\n", model_path_cnn.c_str()); fflush(stderr);
        }
    } else {
        fprintf(stderr, "[ML] Arquivo do modelo CNN Global não encontrado: %s (erro stat: %s)\n", model_path_cnn.c_str(), strerror(errno)); fflush(stderr);
    }
    fprintf(stderr, "[DEBUG CNN_LOAD_EXIT] Saindo da função ml_load_cnn_model. cnn_g_loaded: %s\n", cnn_g_loaded ? "true" : "false"); fflush(stderr);
}
float MLEngine::ml_run_cnn(const std::string& wif) {
    std::cout << "[DEBUG ML_ENGINE_RUN_CNN] Entrando com WIF: " << wif.substr(0, std::min((size_t)8, wif.length())) << "..." << std::endl; std::cout.flush();
    if (!cnn_g_loaded) {
        std::cout << "[DEBUG ML_ENGINE_RUN_CNN] Modelo CNN não carregado." << std::endl; std::cout.flush();
        return 0.0f;
    }
    if (wif.empty()) {std::cout << "[DEBUG ML_ENGINE_RUN_CNN] WIF vazia." << std::endl; std::cout.flush(); return 0.0f;}
    try {
        torch::Tensor input_tensor_cnn = prepare_base58_tensor(wif);
        std::vector<torch::jit::IValue> inputs_cnn;
        inputs_cnn.push_back(input_tensor_cnn);
        auto output_cnn = cnn_model_global.forward(inputs_cnn).toTensor();
        float score = output_cnn.item<float>();
        std::cout << "[DEBUG ML_ENGINE_RUN_CNN] Saindo com score: " << score << std::endl; std::cout.flush();
        return score;
    } catch (const c10::Error& e) {
        std::cerr << "[ML] Erro c10 (LibTorch) em ml_run_cnn: " << e.what() << std::endl; std::cerr.flush();
        return 0.0f;
    } catch (const std::exception& e) {
        std::cerr << "[ML] Erro std::exception em ml_run_cnn: " << e.what() << std::endl; std::cerr.flush();
        return 0.0f;
    }
}

void ml_log_score(float score) {
    std::cout << "[DEBUG ML_LOG_SCORE_G] Logando score: " << score << std::endl; std::cout.flush();
    std::lock_guard<std::mutex> lock(score_mutex_g);
    recent_scores_g.push_back(score);
    if (recent_scores_g.size() > 100) {
        recent_scores_g.pop_front();
    }
}

float ml_recent_score_avg_global() {
    std::cout << "[DEBUG ML_RECENT_AVG_G] Calculando média..." << std::endl; std::cout.flush();
    std::lock_guard<std::mutex> lock(score_mutex_g); 
    if (recent_scores_g.empty()) {std::cout << "[DEBUG ML_RECENT_AVG_G] Sem scores recentes." << std::endl; std::cout.flush(); return 0.0f;}
    float sum_val = 0;
    for (float s_val : recent_scores_g) sum_val += s_val;
    float avg = sum_val / recent_scores_g.size();
    std::cout << "[DEBUG ML_RECENT_AVG_G] Média: " << avg << std::endl; std::cout.flush();
    return avg;
}

void MLEngine::ml_push_score(float score) { ::ml_log_score(score); }
float MLEngine::ml_recent_score_avg()     { return ::ml_recent_score_avg_global(); }


void ml_online_learning_loop() {
    std::cout << "[DEBUG ONLINE_LEARN_LOOP] Thread de aprendizado online iniciada." << std::endl; std::cout.flush();
    const std::string buffer_csv = "models/online_samples.csv";
    bool loaded_once = false;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (std::filesystem::exists(buffer_csv)) {
            MLEngine::ml_load_training_data(buffer_csv, true);
            std::remove(buffer_csv.c_str());
            loaded_once = true;
        }
        if (loaded_once) {
            std::lock_guard<std::mutex> lock(ml_mutex);
            size_t n = std::min(train_data.size(), train_labels.size());
            for (size_t i = 0; i < n; ++i) {
                bool hit = train_labels[i] > 0.5f;
                MLEngine::ml_update_model(nullptr, hit);
            }
            train_data.clear();
            train_labels.clear();
        }
        MLEngine::ml_report_heatmap();
    }
}

void ml_start_online_learning() {
    std::cout << "[DEBUG START_ONLINE_LEARN] Tentando iniciar thread de aprendizado online..." << std::endl; std::cout.flush();
    std::thread learner_thread(ml_online_learning_loop);
    if (learner_thread.joinable()) {
        learner_thread.detach();
        std::cout << "[ML] Loop aprendizado online iniciado." << std::endl; std::cout.flush();
    } else {
        std::cerr << "[ML] Falha ao iniciar loop aprendizado online." << std::endl; std::cerr.flush();
    }
    std::cout << "[DEBUG START_ONLINE_LEARN] Saindo." << std::endl; std::cout.flush();
}

std::string pubkey_hex_to_address_cpp(const std::string& pubkey_hex) {
    std::cout << "[DEBUG PUB_TO_ADDR] Entrando com pubkey_hex: " << pubkey_hex.substr(0, std::min((size_t)8, pubkey_hex.length())) << "..." << std::endl; std::cout.flush();
    if (pubkey_hex.empty()) return "";
    bool is_compressed = (pubkey_hex.length() == 66 && (pubkey_hex.rfind("02",0)==0 || pubkey_hex.rfind("03",0)==0) );
    std::string addr = private_key_to_address(pubkey_hex, is_compressed); 
    std::cout << "[DEBUG PUB_TO_ADDR] Saindo com endereço: " << addr << std::endl; std::cout.flush();
    return addr;
}

FeatureSet extract_features_from_key(const std::string& priv_hex) {
    std::cout << "[DEBUG EXTRACT_FROM_KEY] Entrando com priv_hex: " << priv_hex.substr(0, std::min((size_t)8, priv_hex.length())) << "..." << std::endl; std::cout.flush();
    FeatureSet fs = ::extract_features(priv_hex); 
    std::cout << "[DEBUG EXTRACT_FROM_KEY] Saindo." << std::endl; std::cout.flush();
    return fs;
}

torch::Tensor prepare_base58_tensor(const std::string& input_wif) {
    std::cout << "[DEBUG PREPARE_B58_TENSOR] Entrando com WIF: " << input_wif.substr(0, std::min((size_t)8, input_wif.length())) << "..." << std::endl; std::cout.flush();
    const int MAX_WIF_LEN_FOR_CNN = 52; 
    
    std::string b58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::map<char, int> char_to_idx;
    for(size_t i=0; i < b58_chars.length(); ++i) {
        char_to_idx[b58_chars[i]] = static_cast<int>(i) + 1; 
    }

    std::vector<int64_t> tensor_indices(MAX_WIF_LEN_FOR_CNN, 0); 

    for (size_t i = 0; i < MAX_WIF_LEN_FOR_CNN; ++i) {
        if (i < input_wif.length()) {
            char c = input_wif[i];
            if(char_to_idx.count(c)) {
                tensor_indices[i] = char_to_idx[c];
            } else {
                tensor_indices[i] = 0; 
            }
        } else {
            tensor_indices[i] = 0; 
        }
    }
    
    torch::Tensor result = torch::from_blob(tensor_indices.data(), {1, MAX_WIF_LEN_FOR_CNN}, torch::kLong).clone();
    
    std::cout << "[DEBUG PREPARE_B58_TENSOR] Saindo. Shape do tensor: " << result.sizes() << ", Tipo: " << result.scalar_type() << std::endl; std::cout.flush();
    return result;
}