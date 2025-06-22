#ifndef ML_ENGINE_H
#define ML_ENGINE_H
#pragma once

#include <torch/script.h>
#include <torch/torch.h>
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>
#include <iostream>
#include "ml_helpers.h" // FeatureSet é definido aqui

class MLEngine {
private:
    static torch::jit::script::Module model;     // Modelo PyTorch principal da classe
    static bool is_initialized;                  // Flag de inicialização para MLEngine::model

public:
    // Inicializa MLEngine::model e outros modelos globais se necessário
    static bool ml_init(const std::string& model_path, const std::string& positive_features_path);
    
    static bool ml_load_training_data(const std::string& csv_path, bool is_positive);
    static void ml_update_model(const unsigned char* address, bool is_hit); // Placeholder
    static void ml_report_heatmap();

    // Predição usando o modelo principal MLEngine::model
    static float ml_predict(const std::vector<float>& features_vec);
    static float ml_predict(const FeatureSet& f); // Wrapper para conveniência

    // CNN (modelo separado)
    static void ml_load_cnn_model(const std::string& path);
    static float ml_run_cnn(const std::string& wif); // Usa o modelo CNN global

    // Score combinado (a ser implementado com a "potência máxima")
    static float ml_score(const FeatureSet& f);

    // Score do XGBoost (se usado, precisa ser implementado)
    static float ml_xgboost_score(const FeatureSet& f);


    // Utilitários de Score (usam as globais `recent_scores` e `score_mutex`)
    static void ml_push_score(float score);
    static float ml_recent_score_avg();


    // Deprecated ou não usado?
    // static bool ml_check_address(const unsigned char* address);
    // static std::vector<float> extract_address_features(const unsigned char* address);

};

// Definições inline para membros estáticos da classe
inline torch::jit::script::Module MLEngine::model;
inline bool MLEngine::is_initialized = false;

// Funções globais e variáveis globais declaradas em ml_engine.cpp
// extern torch::jit::script::Module g_model; // Se ainda precisar de g_model globalmente
// extern torch::jit::script::Module g_autoencoder; // Se ainda precisar de g_autoencoder globalmente

// Função global para preparar tensor para CNN
torch::Tensor prepare_base58_tensor(const std::string& input);

// Função global para carregar modelos auxiliares (MLP, AE, XGB, LGBM)
// A declaração deve estar aqui se você quiser chamá-la de fora de ml_engine.cpp,
// caso contrário, pode ser apenas um protótipo dentro de ml_engine.cpp.
bool load_models(const std::string& mlp_path);
void ml_start_online_learning(); 

#endif // ML_ENGINE_H
