#include "RL_agent.h"
#include "IA_wrapper.h"
#include "ml_helpers.h"
#include "ml_engine.h"
#include <iostream>
#include <fstream>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <memory>
#include <vector>

std::vector<RLAgent::Experience> RLAgent::memory;
std::map<int, std::array<float,2>> RLAgent::q_table;
std::default_random_engine RLAgent::rng(std::random_device{}());
FeatureSet RLAgent::best_feat;
float RLAgent::best_score_value = -1.0f;
bool RLAgent::verbose = false;
float RLAgent::alpha = 0.1f;
float RLAgent::gamma = 0.95f;
float RLAgent::epsilon = 0.1f;
std::mutex RLAgent::rl_mutex;
torch::nn::Sequential RLAgent::net;
torch::nn::Sequential RLAgent::net_target;
std::unique_ptr<torch::optim::Adam> RLAgent::optimizer;
bool RLAgent::pca_ready = false;
torch::Tensor RLAgent::pca_components;
torch::Tensor RLAgent::pca_mean;
static size_t learn_counter = 0;
static const size_t print_interval = 10;
static float last_report_best = -1.0f;

void RLAgent::init() {
    std::lock_guard<std::mutex> lock(rl_mutex);
    memory.clear();
    q_table.clear();
    best_score_value = -1.0f;
    best_feat = FeatureSet{};
    RLAgent::pca_ready = false;
    // Rede neural aprofundada para melhor capacidade de aprendizado
    net = torch::nn::Sequential(
        torch::nn::Linear(INPUT_DIM, 1024),
        torch::nn::ReLU(),
        torch::nn::Dropout(0.3),
        torch::nn::Linear(1024, 512),
        torch::nn::ReLU(),
        torch::nn::Dropout(0.3),
        torch::nn::Linear(512, 256),
        torch::nn::ReLU(),
        torch::nn::Dropout(0.2),
        torch::nn::Linear(256, 128),
        torch::nn::ReLU(),
        torch::nn::Linear(128, 64),
        torch::nn::ReLU(),
        torch::nn::Linear(64, 1),
        torch::nn::Sigmoid()
    );
    optimizer = std::make_unique<torch::optim::Adam>(net->parameters(), torch::optim::AdamOptions(0.001));
    net_target = net;
    std::cout << "[RL] Agente Reinforcement Learning iniciado." << std::endl;
}

int RLAgent::zone_from_feature(const FeatureSet& feat) {
    // Exemplo: usar parte da entropia + palíndromo como indexador de zona
    int bucket = static_cast<int>((feat.priv_hex_entropy * 10.0f) + 5 * feat.priv_hex_palindrome);
    return bucket;
}

static torch::Tensor features_to_tensor(const FeatureSet& feat) {
    auto vec = feat.to_vector();
    torch::Tensor t = torch::from_blob(vec.data(), {RLAgent::INPUT_DIM}, torch::kFloat32).clone();
    if (RLAgent::pca_ready) {
        t = torch::matmul(t - RLAgent::pca_mean, RLAgent::pca_components);
    }
    return t;
}

void RLAgent::observe(const FeatureSet& feat, float score, bool hit) {
    std::lock_guard<std::mutex> lock(rl_mutex);
    float priority = 1.0f;
    if (optimizer) {
        float pred = net->forward(features_to_tensor(feat)).item<float>();
        priority = std::fabs((hit?1.0f:0.0f) - pred) + 1e-3f;
    }
    memory.push_back({feat, hit, priority});
    if (memory.size() > 10000) memory.erase(memory.begin());

    if (score > best_score_value) {
        best_score_value = score;
        best_feat = feat;
    }

    int zone = zone_from_feature(feat);
    auto &q = q_table[zone];
    float reward = hit ? 1.0f : -0.05f;
    float max_future = std::max(q[0], q[1]);
    q[1] += alpha * (reward + gamma * max_future - q[1]);
}

bool RLAgent::decide(const FeatureSet& feat) {
    int zone = zone_from_feature(feat);
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    if (dist(rng) < epsilon) {
        return dist(rng) < 0.5f;
    }
    float keep_q = 0.0f;
    if (optimizer) {
        keep_q = net->forward(features_to_tensor(feat)).item<float>();
    }
    auto it = q_table.find(zone);
    if (it != q_table.end()) {
        keep_q = (keep_q + it->second[1]) / 2.0f; // combinar heurística e rede
    }
    return keep_q >= 0.5f;
}

void RLAgent::learn() {
    std::lock_guard<std::mutex> lock(rl_mutex);
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

    if (!RLAgent::pca_ready && memory.size() >= INPUT_DIM * 2) {
        torch::Tensor all = torch::empty({(long)memory.size(), INPUT_DIM});
        for (size_t i = 0; i < memory.size(); ++i) {
            auto vec = memory[i].feat.to_vector();
            all[i] = torch::from_blob(vec.data(), {INPUT_DIM}, torch::kFloat32).clone();
        }
        RLAgent::pca_mean = all.mean(0);
        auto svd_res = torch::svd(all - RLAgent::pca_mean);
        RLAgent::pca_components = std::get<2>(svd_res).slice(1,0,PCA_DIM);
        RLAgent::pca_ready = true;
    }

    if (!memory.empty() && optimizer) {
        const size_t batch = std::min(BATCH_SIZE, memory.size());
        std::vector<double> weights;
        weights.reserve(memory.size());
        for (const auto& ex : memory) weights.push_back(ex.priority);
        std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
        const int epochs = 3;
        for (int e = 0; e < epochs; ++e) {
            torch::Tensor data = torch::empty({(long)batch, INPUT_DIM});
            torch::Tensor labels = torch::empty({(long)batch, 1});
            std::vector<size_t> indices(batch);
            for (size_t i = 0; i < batch; ++i) {
                size_t idx = dist(rng);
                indices[i] = idx;
                auto vec = memory[idx].feat.to_vector();
                data[i] = torch::from_blob(vec.data(), {INPUT_DIM}, torch::kFloat32).clone();
                labels[i][0] = memory[idx].hit ? 1.0f : 0.0f;
            }
            if (RLAgent::pca_ready) {
                data = torch::matmul(data - RLAgent::pca_mean, RLAgent::pca_components);
            }
            torch::Tensor preds = net->forward(data);
            torch::Tensor loss = torch::binary_cross_entropy(preds, labels);
            optimizer->zero_grad();
            loss.backward();
            optimizer->step();
            for (size_t i = 0; i < batch; ++i) {
                float newp = std::fabs(labels[i].item<float>() - preds[i].item<float>()) + 1e-3f;
                memory[indices[i]].priority = newp;
            }
        }
    }

    if (learn_counter % 20 == 0 && net_target) {
        torch::NoGradGuard g;
        auto p_src = net->named_parameters();
        auto p_dst = net_target->named_parameters();
        for (auto& kv : p_src) {
            p_dst[kv.key()].copy_(kv.value());
        }
    }

    if (learn_counter % CHECKPOINT_INTERVAL == 0) {
        save("rl_checkpoint_" + std::to_string(learn_counter) + ".txt");
    }

    static std::ofstream metrics("rl_metrics.log", std::ios::app);
    metrics << learn_counter << "," << best_score_value << "," << epsilon << "\n";

    epsilon *= 0.99f;
}

void RLAgent::save(const std::string& path) {
    std::lock_guard<std::mutex> lock(rl_mutex);
    std::ofstream out(path);
    if (!out) return;
    for (const auto& [zone, qvals] : q_table) {
        out << zone << "," << qvals[0] << "," << qvals[1] << "\n";
    }
    out.close();
    if (optimizer) {
        torch::save(net, path + ".pt");
        torch::save(net_target, path + ".target.pt");
        if (RLAgent::pca_ready) {
            torch::save(RLAgent::pca_components, path + ".pca.pt");
            torch::save(RLAgent::pca_mean, path + ".pca_mean.pt");
        }
    }
    std::cout << "[RL] Heatmap salvo em " << path << "\n";
}

void RLAgent::load(const std::string& path) {
    std::lock_guard<std::mutex> lock(rl_mutex);
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
    try {
        torch::load(net, path + ".pt");
        torch::load(net_target, path + ".target.pt");
        optimizer = std::make_unique<torch::optim::Adam>(net->parameters(), torch::optim::AdamOptions(0.001));
        try {
            torch::load(RLAgent::pca_components, path + ".pca.pt");
            torch::load(RLAgent::pca_mean, path + ".pca_mean.pt");
            RLAgent::pca_ready = true;
        } catch (...) {}
    } catch (...) {
        // ignore
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
        out.push_back(it->feat);
        ++count;
    }
    return out;
}

void RLAgent::set_verbose(bool v) {
    std::lock_guard<std::mutex> lock(rl_mutex);
    verbose = v;
}

void RLAgent::set_params(float a, float g, float e) {
    std::lock_guard<std::mutex> lock(rl_mutex);
    alpha = a;
    gamma = g;
    epsilon = e;
}
