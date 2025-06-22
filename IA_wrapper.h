#pragma once
#include <string>
#include <cstdint>
#include "ml_helpers.h"  // ✅ Necessário para reconhecer FeatureSet

namespace ia {

// Estrutura usada para definir os blocos de busca guiados pela IA
struct Range {
    uint64_t from;
    uint64_t to;
    uint64_t stride;
    float score;
    float min_score;

    Range(uint64_t f = 0, uint64_t t = 0, uint64_t s = 1, float sc = 0.0f, float min_sc = 0.8f)
        : from(f), to(t), stride(s), score(sc), min_score(min_sc) {}
};

// Interface pública do IA_wrapper.cpp
float combined_key_score(const std::string &privkey_hex);
bool keep_key(const std::string &privkey_hex, const Range &r);
Range next_range();
uint64_t get_range_start();
uint64_t get_range_end();
uint64_t get_stride();
// Configure starting range, ending range and stride used by next_range()
void set_range_limits(uint64_t start, uint64_t end, uint64_t stride = 1);
void reward(const Range &r, bool hit, const FeatureSet &features); // ✅ Agora sem "struct"
void start_reporter();
void stop_reporter();
void init(const std::string &model_path, const std::string &pos_data, const std::string &neg_data);
std::vector<std::string> query_promising_keys(size_t n = 1);

} // namespace ia
