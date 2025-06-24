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
    static constexpr int PCA_DIM = 8;
    static constexpr size_t BATCH_SIZE = 64;
    static constexpr size_t CHECKPOINT_INTERVAL = 50;
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
    static bool pca_ready;
    static torch::Tensor pca_components;
    static torch::Tensor pca_mean;

private:
    struct Experience {
        FeatureSet feat;
        bool hit;
        float priority;
    };
    static std::vector<Experience> memory;
    static std::map<int, std::array<float,2>> q_table; // Q-values por zona (skip, keep)
    static std::default_random_engine rng;
    static FeatureSet best_feat;
    static float best_score_value;
    static bool verbose;
    static std::mutex rl_mutex;
    static torch::nn::Sequential net;
    static torch::nn::Sequential net_target;
    static std::unique_ptr<torch::optim::Adam> optimizer;

    static float alpha;
    static float gamma;
    static float epsilon;

    static int zone_from_feature(const FeatureSet& feat);
};

#endif
