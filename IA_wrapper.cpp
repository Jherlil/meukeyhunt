#include "IA_wrapper.h"
#include "ml_engine.h"
#include "ml_helpers.h"
#include "RL_agent.h"
#include "helpers.h"
#include <random>
#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cctype>
#include <vector>

namespace ia {

// Variável de controle do reporter
static std::atomic<bool> g_stop_reporter(false);
static std::atomic<uint64_t> g_range_start(1);
static std::atomic<uint64_t> g_range_end(0xFFFFFFFFULL);
static std::atomic<uint64_t> g_stride(1);
static std::atomic<uint64_t> g_current(1);
static std::vector<int> nibble_hist(16, 1);
static bool hist_loaded = false;

float combined_key_score(const std::string &privkey_hex) {
    FeatureSet f = extract_features(privkey_hex);
    return MLEngine::ml_predict(f.to_vector());
}

Range next_range() {
    Range r;
    uint64_t cur = g_current.load();
    if (cur > g_range_end.load()) {
        r.from = r.to = 0;
        r.stride = g_stride.load();
        return r;
    }

    uint64_t stride = g_stride.load();
    uint64_t block = 0xFFFFF * stride;
    r.from = cur;
    r.to = (cur + block > g_range_end.load()) ? g_range_end.load() : cur + block;
    r.stride = stride;
    r.min_score = 0.8f;
    g_current.store(r.to + stride);
    return r;
}

uint64_t get_range_start() { return g_range_start.load(); }
uint64_t get_range_end() { return g_range_end.load(); }
uint64_t get_stride() { return g_stride.load(); }

void set_range_limits(uint64_t start, uint64_t end, uint64_t stride) {
    if (stride == 0) stride = 1;
    g_range_start.store(start);
    g_range_end.store(end);
    g_stride.store(stride);
    g_current.store(start);
}

void reward(const Range &, bool, const FeatureSet &) {
    // Aprendizado online ainda não implementado
}

void start_reporter() {
    std::thread([]() {
        while (!g_stop_reporter.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            float avg = MLEngine::ml_recent_score_avg();
            std::cout << "[IA] Média de score nos últimos 30s: " << avg << std::endl;
        }
    }).detach();
}

void stop_reporter() {
    g_stop_reporter.store(true);
}

static void load_hist_from_csv(const std::string& pos_csv) {
    if (hist_loaded) return;
    std::ifstream in(pos_csv);
    if (!in.is_open()) return;
    std::string line;
    std::getline(in, line); // header
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string priv_hex;
        if (std::getline(ss, priv_hex, ',')) {
            char c = std::tolower(priv_hex[0]);
            int idx = (c >= '0' && c <= '9') ? c - '0' :
                      (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
            if (idx >= 0) nibble_hist[idx]++;
        }
    }
    hist_loaded = true;
}

void init(const std::string &model_path, const std::string &pos_data, const std::string &neg_data) {
    MLEngine::ml_init(model_path, pos_data);
    MLEngine::ml_load_training_data(pos_data, true);
    MLEngine::ml_load_training_data(neg_data, false);
    load_hist_from_csv(pos_data);
}

std::vector<std::string> query_promising_keys(size_t n) {
    std::vector<std::string> result;
    if (n == 0) return result;

    // 1) melhor chave observada pelo RLAgent
    std::string best = RLAgent::best_key();
    if (!best.empty()) result.push_back(best);

    // 2) outras chaves do histórico do RLAgent (mais recentes)
    auto mem = RLAgent::top_candidates(n);
    for (const auto& f : mem) {
        if (result.size() >= n) break;
        if (!f.s_priv_hex.empty()) result.push_back(f.s_priv_hex);
    }

    // 3) complementa com chaves de generated_keys.txt, se existir
    std::ifstream fin("generated_keys.txt");
    std::string line;
    while (result.size() < n && std::getline(fin, line)) {
        if (!line.empty()) result.push_back(line);
    }
    return result;
}

std::vector<std::string> generate_candidate_keys(size_t n) {
    std::vector<std::string> result;
    if (n == 0) return result;

    static std::default_random_engine eng{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> dist(g_range_start.load(), g_range_end.load());
    std::discrete_distribution<int> nibble_dist(nibble_hist.begin(), nibble_hist.end());

    std::string best = RLAgent::best_key();
    uint64_t best_val = 0;
    if (!best.empty()) {
        try {
            best_val = std::stoull(best.substr(0, 16), nullptr, 16);
        } catch (...) {
            best_val = dist(eng);
        }
    }

    for (size_t i = 0; i < n; ++i) {
        uint64_t base = best_val ? best_val : dist(eng);
        std::uniform_int_distribution<int> delta(-5000, 5000);
        uint64_t candidate = base + delta(eng);
        if (candidate < g_range_start.load() || candidate > g_range_end.load()) {
            candidate = dist(eng);
        }
        std::string hex = to_hex(candidate);
        if (!hex.empty()) {
            hex[0] = "0123456789abcdef"[nibble_dist(eng)];
        }
        result.push_back(hex);
    }

    return result;
}

} // namespace ia
