
#pragma once
#ifndef ML_HELPERS_H
#define ML_HELPERS_H

#include <vector>
#include <string>
#include <cstdint>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <cmath>

struct FeatureSet {
    std::string s_priv_hex;
    std::string wif;
    std::string wif_compressed;

    float priv_hex_len            = 0.0f;
    float priv_hex_zero_prefix    = 0.0f;
    float priv_hex_zero_suffix    = 0.0f;
    float priv_hex_entropy        = 0.0f;
    float priv_hex_palindrome     = 0.0f;
    float is_mod_2                = 0.0f;
    float is_mod_4                = 0.0f;
    float is_mod_8                = 0.0f;
    float priv_hex_sympy_score    = 0.0f;

    float wif_present             = 0.0f;
    float base58_wif_len          = 0.0f;
    float base58_wif_unique       = 0.0f;
    float base58_entropy          = 0.0f;
    float addr1_len               = 0.0f;
    float addr1_type              = 0.0f;
    float addr2_present           = 0.0f;
    float addr2_len               = 0.0f;
    float addr2_type              = 0.0f;
    float seed_word_count         = 0.0f;
    float seed_entropy            = 0.0f;
    float symmetry                = 0.0f;
    float longest_one_run         = 0.0f;
    float bin_palindrome          = 0.0f;
    float wif_valid_custom        = 0.0f;
    float is_compressed_custom    = 0.0f;
    float addr_entropy_custom     = 0.0f;
    float addr_type_p2pkh_custom  = 0.0f;
    float addr_type_p2sh_custom   = 0.0f;
    float addr_type_bech32_custom = 0.0f;

    std::vector<float> to_vector() const {
        return {
            priv_hex_len, priv_hex_zero_prefix, priv_hex_zero_suffix,
            priv_hex_entropy, priv_hex_palindrome, is_mod_2, is_mod_4,
            is_mod_8, priv_hex_sympy_score, wif_present, base58_wif_len,
            base58_wif_unique, base58_entropy, addr1_len, addr1_type,
            addr2_present, addr2_len, addr2_type,
            seed_word_count, seed_entropy,
            symmetry, longest_one_run, bin_palindrome, wif_valid_custom,
            is_compressed_custom, addr_entropy_custom,
            addr_type_p2pkh_custom, addr_type_p2sh_custom,
            addr_type_bech32_custom
        };
    }
};

FeatureSet extract_features(const std::string& privkey_hex);
std::vector<std::uint8_t> hex_string_to_bytes(const std::string& hex);

class ScoreTracker {
    float sum   = 0.0f;
    int   count = 0;
public:
    void  add(float v) { sum += v; ++count; }
    float get_avg() const { return count ? sum / static_cast<float>(count) : 0.0f; }
    void reset() { sum = 0.0f; count = 0; }
};

#endif /* ML_HELPERS_H */
