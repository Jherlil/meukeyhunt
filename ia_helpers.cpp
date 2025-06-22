#include "ia_helpers.h"
#include "ml_engine.h"
#include "ml_helpers.h"
#include "IA_wrapper.h"
#include <zlib.h>
#include <numeric>
#include <vector>
#include <string>
#include <cstring>

// Garante visibilidade da função de extração
FeatureSet extract_features(const std::string& priv_hex);

std::vector<float> compress_entropy(const std::string& data) {
    if (data.empty()) {
        return {0.0f};
    }
    uLongf dest_len = compressBound(data.size());
    std::vector<unsigned char> compressed(dest_len);

    if (compress(compressed.data(), &dest_len, (const Bytef*)data.data(), data.size()) != Z_OK) {
        return {1.0f};
    }
    float ratio = (data.size() > 0) ? ((float)dest_len / (float)data.size()) : 0.0f;
    return { ratio };
}

float symmetry_score(const std::string& str) {
    if (str.empty() || str.size() < 2) return 1.0f;
    int sym = 0;
    size_t half_len = str.size() / 2;
    for (size_t i = 0; i < half_len; i++) {
        if (str[i] == str[str.size() - 1 - i]) sym++;
    }
    return static_cast<float>(sym) / static_cast<float>(half_len);
}

int leading_zeros(const std::string& hex) {
    for (size_t i = 0; i < hex.size(); i++) {
        if (hex[i] != '0') return static_cast<int>(i);
    }
    return static_cast<int>(hex.size());
}

namespace ia {
    bool keep_key(const std::string& priv_hex, const ia::Range& r) {
        FeatureSet f = extract_features(priv_hex);

        float mlp_score = MLEngine::ml_score(f);
        float xgb_score = MLEngine::ml_xgboost_score(f);

        std::string wif_input = !f.wif_compressed.empty() ? f.wif_compressed : f.wif;
        float cnn_score = MLEngine::ml_run_cnn(wif_input);

        float final_score = (mlp_score + xgb_score + cnn_score) / 3.0f;

        return final_score >= 0.8f; // Ajuste aqui conforme campo de `Range`
    }
}
