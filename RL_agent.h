#ifndef RL_AGENT_H
#define RL_AGENT_H

#include "ml_engine.h"
#include <vector>
#include <string>
#include <torch/torch.h>
#include <random>
#include "ml_helpers.h"
#include <map>
#include <array>
#include <mutex>
#include <memory>

class RLAgent {
public:
    static constexpr int INPUT_DIM = 29;
    static void init();
    static void observe(const FeatureSet& feat, float score, bool hit);
    static bool decide(const FeatureSet& feat);
    static void learn();  // Aprendizado adaptativo
    static void save(const std::string& path);
    static void load(const std::string& path);
    static void set_verbose(bool v);
    static void set_params(float a, float g, float e);
    static std::string best_key();
    static float best_key_score();
    static std::vector<FeatureSet> top_candidates(size_t n);

private:
    static std::vector<std::pair<FeatureSet, bool>> memory;
    static std::map<int, std::array<float,2>> q_table; // Q-values por zona (skip, keep)
    static std::default_random_engine rng;
    static FeatureSet best_feat;
    static float best_score_value;
    static bool verbose;
    static std::mutex rl_mutex;
    static torch::nn::Sequential net;
    static std::unique_ptr<torch::optim::Adam> optimizer;

    static float alpha;
    static float gamma;
    static float epsilon;

    static int zone_from_feature(const FeatureSet& feat);
};

#endif
