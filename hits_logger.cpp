#include "hits_logger.h"
#include <vector>
#include <fstream>
#include <iostream>

struct Hit {
    std::string priv, wif, pub, addr;
    int score;
};

std::vector<Hit> hits;

void log_hit(const std::string &priv, const std::string &wif, const std::string &pub, const std::string &addr, int score) {
    hits.push_back({priv, wif, pub, addr, score});
}

void export_hits(const std::string &filename_csv) {
    std::ofstream file(filename_csv);
    file << "priv,wif,pub,addr,score\n";
    for (const auto &h : hits) {
        file << h.priv << "," << h.wif << "," << h.pub << "," << h.addr << "," << h.score << "\n";
    }
}

void export_hits_json(const std::string &filename_json) {
    std::ofstream file(filename_json);
    file << "[\n";
    for (size_t i = 0; i < hits.size(); ++i) {
        file << "  {\"priv\": \"" << hits[i].priv << "\", \"wif\": \"" << hits[i].wif
             << "\", \"pub\": \"" << hits[i].pub << "\", \"addr\": \"" << hits[i].addr
             << "\", \"score\": " << hits[i].score << "}";
        if (i != hits.size() - 1) file << ",";
        file << "\n";
    }
    file << "]\n";
}
