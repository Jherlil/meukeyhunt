
#ifndef RL_AGENT_H
#define RL_AGENT_H

#include "ml_engine.h"
#include <vector>
#include <string>
#include <torch/torch.h>
#include <random>
#include "ml_helpers.h"
#include <map>

class RLAgent {
public:
    static void init();
    static void observe(const FeatureSet& feat, float score, bool hit);
    static bool decide(const FeatureSet& feat);
    static void learn();  // Aprendizado adaptativo
    static void save(const std::string& path);
    static void load(const std::string& path);
    static std::string best_key();
    static float best_key_score();

private:
    static std::vector<std::pair<FeatureSet, bool>> memory;
    static std::map<int, float> heatmap;         // zone → sucesso médio
    static std::map<int, int> heatmap_counts;    // zone → número de experiências
    static std::default_random_engine rng;
    static FeatureSet best_feat;
    static float best_score_value;

    static int zone_from_feature(const FeatureSet& feat);
};

#endif