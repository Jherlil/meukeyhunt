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
#include <algorithm>
#include <utility>

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
    while (true) {
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

        // Consultar RLAgent para ver se vale processar esta faixa
        std::string seed_hex = to_hex(r.from);
        FeatureSet f_seed = extract_features(seed_hex);
        if (RLAgent::decide(f_seed)) {
            return r; // faixa aprovada
        }
        // Caso contrário, tenta a próxima faixa
    }
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

void reward(const Range &, bool hit, const FeatureSet &feat) {
    float score = MLEngine::ml_score(feat);
    RLAgent::observe(feat, score, hit);
    if (hit) {
        RLAgent::learn();
    }
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

    size_t population = std::max<size_t>(n * 10, 50);

    // Sementes: melhores chaves já observadas ou extraídas do histórico
    auto seeds = query_promising_keys(std::max<size_t>(n, 10));
    std::vector<uint64_t> pool;
    pool.reserve(population);
    for (const auto& s : seeds) {
        try {
            pool.push_back(std::stoull(s.substr(0,16), nullptr, 16));
        } catch (...) {}
    }
    while (pool.size() < population) {
        pool.push_back(dist(eng));
    }

    auto score_candidate = [&](uint64_t v) -> float {
        std::string h = to_hex(v);
        FeatureSet f = extract_features(h);
        return MLEngine::ml_predict(f);
    };

    auto mutate = [&](uint64_t base)->uint64_t {
        std::uniform_int_distribution<int64_t> delta(-10000, 10000);
        int64_t cand = static_cast<int64_t>(base) + delta(eng);
        if (cand < static_cast<int64_t>(g_range_start.load()) || cand > static_cast<int64_t>(g_range_end.load())) {
            cand = dist(eng);
        }
        return static_cast<uint64_t>(cand);
    };

    for(int gen = 0; gen < 2; ++gen) {
        std::vector<std::pair<uint64_t,float>> scored;
        for(uint64_t v : pool) {
            scored.emplace_back(v, score_candidate(v));
        }
        std::sort(scored.begin(), scored.end(), [](auto&a, auto&b){ return a.second > b.second; });
        scored.resize(population/2);
        pool.clear();
        for(auto &p : scored) {
            pool.push_back(p.first);
            pool.push_back(mutate(p.first));
        }
    }

    std::vector<std::pair<uint64_t,float>> final_scored;
    for(uint64_t v : pool) {
        final_scored.emplace_back(v, score_candidate(v));
    }
    std::sort(final_scored.begin(), final_scored.end(), [](auto&a, auto&b){ return a.second > b.second; });

    for(size_t i = 0; i < n && i < final_scored.size(); ++i) {
        std::string hex = to_hex(final_scored[i].first);
        if(!hex.empty()) hex[0] = "0123456789abcdef"[nibble_dist(eng)];
        result.push_back(hex);
    }

    return result;
}

} // namespace ia
