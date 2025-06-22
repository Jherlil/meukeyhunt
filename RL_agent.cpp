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
std::map<int, float> RLAgent::heatmap;
std::map<int, int> RLAgent::heatmap_counts;
std::default_random_engine RLAgent::rng(std::random_device{}());
FeatureSet RLAgent::best_feat;
float RLAgent::best_score_value = -1.0f;

void RLAgent::init() {
    memory.clear();
    heatmap.clear();
    heatmap_counts.clear();
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
    float current = heatmap[zone];
    int count = heatmap_counts[zone];

    float new_avg = ((current * count) + (hit ? 1.0f : 0.0f)) / (count + 1);
    heatmap[zone] = new_avg;
    heatmap_counts[zone]++;
}

bool RLAgent::decide(const FeatureSet& feat) {
    int zone = zone_from_feature(feat);
    float zscore = heatmap.count(zone) ? heatmap[zone] : 0.5f;

    // Exemplo: evitar zonas ruins
    if (zscore < 0.25f) {
        return false;
    }

    // Pequena aleatoriedade para explorar zonas medianas
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float rnd = dist(rng);
    return rnd < zscore;
}

void RLAgent::learn() {
    std::cout << "[RL] Aprendizado com " << memory.size() << " experiências." << std::endl;
    std::cout << "[RL] Heatmap:" << std::endl;
    for (const auto& [zone, score] : heatmap) {
        int count = heatmap_counts[zone];
        std::cout << "  Zona " << std::setw(2) << zone << ": média=" << std::fixed << std::setprecision(2) << score
                  << " (" << count << " amostras)" << std::endl;
    }
}

void RLAgent::save(const std::string& path) {
    std::ofstream out(path);
    if (!out) return;
    for (const auto& [zone, score] : heatmap) {
        out << zone << "," << score << "," << heatmap_counts[zone] << "\n";
    }
    out.close();
    std::cout << "[RL] Heatmap salvo em " << path << "\n";
}

void RLAgent::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    heatmap.clear();
    heatmap_counts.clear();
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        int zone, count;
        float score;
        char comma;
        if (ss >> zone >> comma >> score >> comma >> count) {
            heatmap[zone] = score;
            heatmap_counts[zone] = count;
        }
    }
    std::cout << "[RL] Modelo RL carregado de " << path << " com " << heatmap.size() << " zonas." << std::endl;
}

std::string RLAgent::best_key() {
    return best_feat.s_priv_hex;
}

float RLAgent::best_key_score() {
    return best_score_value;
}