#include "RL_agent.h"
#include "IA_wrapper.h"
#include "ml_helpers.h"
#include "ml_engine.h"
#include <iostream>
#include <fstream>
#include <cmath>
#include <sstream>
#include <iomanip>

std::vector<std::pair<FeatureSet, bool>> RLAgent::memory;
std::map<int, std::array<float,2>> RLAgent::q_table;
std::default_random_engine RLAgent::rng(std::random_device{}());
FeatureSet RLAgent::best_feat;
float RLAgent::best_score_value = -1.0f;
bool RLAgent::verbose = false;
float RLAgent::alpha = 0.1f;
float RLAgent::gamma = 0.95f;
float RLAgent::epsilon = 0.1f;
static size_t learn_counter = 0;
static const size_t print_interval = 10;
static float last_report_best = -1.0f;

void RLAgent::init() {
    memory.clear();
    q_table.clear();
    best_score_value = -1.0f;
    best_feat = FeatureSet{};
    std::cout << "[RL] Agente Reinforcement Learning iniciado." << std::endl;
}

int RLAgent::zone_from_feature(const FeatureSet& feat) {
    // Exemplo: usar parte da entropia + palíndromo como indexador de zona
    int bucket = static_cast<int>((feat.priv_hex_entropy * 10.0f) + 5 * feat.priv_hex_palindrome);
    return bucket;
}

void RLAgent::observe(const FeatureSet& feat, float score, bool hit) {
    memory.emplace_back(feat, hit);
    if (memory.size() > 10000) memory.erase(memory.begin());

    if (score > best_score_value) {
        best_score_value = score;
        best_feat = feat;
    }

    int zone = zone_from_feature(feat);
    auto &q = q_table[zone];
    float reward = hit ? 1.0f : -0.05f;
    q[1] = q[1] + alpha * (reward - q[1]);
}

bool RLAgent::decide(const FeatureSet& feat) {
    int zone = zone_from_feature(feat);
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    if (dist(rng) < epsilon) {
        return dist(rng) < 0.5f;
    }
    auto it = q_table.find(zone);
    float keep_q = 0.0f;
    float skip_q = 0.0f;
    if (it != q_table.end()) {
        keep_q = it->second[1];
        skip_q = it->second[0];
    }
    return keep_q >= skip_q;
}

void RLAgent::learn() {
    learn_counter++;
    bool report = false;
    if (best_score_value > last_report_best + 1e-6) {
        report = true;
        last_report_best = best_score_value;
    }
    if (learn_counter % print_interval == 0) {
        report = true;
    }

    if (verbose && report) {
        std::cout << "[RL] Aprendizado com " << memory.size() << " experiências." << std::endl;
        std::cout << "[RL] Q-table:" << std::endl;
        for (const auto& [zone, qvals] : q_table) {
            std::cout << "  Zona " << std::setw(2) << zone << ": skip=" << std::fixed << std::setprecision(2) << qvals[0]
                      << " keep=" << qvals[1] << std::endl;
        }
    }
    epsilon *= 0.99f;
}

void RLAgent::save(const std::string& path) {
    std::ofstream out(path);
    if (!out) return;
    for (const auto& [zone, qvals] : q_table) {
        out << zone << "," << qvals[0] << "," << qvals[1] << "\n";
    }
    out.close();
    std::cout << "[RL] Heatmap salvo em " << path << "\n";
}

void RLAgent::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    q_table.clear();
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        int zone;
        float skip_q, keep_q;
        char comma;
        if (ss >> zone >> comma >> skip_q >> comma >> keep_q) {
            q_table[zone] = {skip_q, keep_q};
        }
    }
    std::cout << "[RL] Modelo RL carregado de " << path << " com " << q_table.size() << " zonas." << std::endl;
}

std::string RLAgent::best_key() {
    return best_feat.s_priv_hex;
}

float RLAgent::best_key_score() {
    return best_score_value;
}

std::vector<FeatureSet> RLAgent::top_candidates(size_t n) {
    std::vector<FeatureSet> out;
    if (n == 0) return out;
    size_t count = 0;
    for (auto it = memory.rbegin(); it != memory.rend() && count < n; ++it) {
        out.push_back(it->first);
        ++count;
    }
    return out;
}

void RLAgent::set_verbose(bool v) {
    verbose = v;
}