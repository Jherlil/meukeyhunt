#include "ml_helpers.h"
#include "keyutils.h"
#include "bitcoin_utils.hpp"
#include <cmath>
#include <algorithm>
#include <unordered_map>
#include <set>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <iostream> // Para std::cerr (opcional, mas usado nos seus comentários)
#include <cstdlib>  // Para strtoul

float entropy(const std::string& data) {
    if (data.empty()) return 0.0f;
    std::unordered_map<char, int> freq;
    for (char c : data) freq[c]++;
    float ent = 0.0f;
    for (const auto& p : freq) {
        if (p.second > 0) {
            float prob = static_cast<float>(p.second) / data.size();
            ent -= prob * std::log2(prob);
        }
    }
    return ent;
}

float is_palindrome(const std::string& s) {
    if (s.empty()) return 0.0f;
    std::string r = s;
    std::reverse(r.begin(), r.end());
    return s == r ? 1.0f : 0.0f;
}

std::vector<uint8_t> hex_string_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() % 2 != 0) {
        return bytes;
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char* end = nullptr;
        unsigned long byte_val_ul = strtoul(byteString.c_str(), &end, 16);

        if (end != byteString.c_str() + 2 || byteString.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
            bytes.clear();
            return bytes;
        }
        if (byte_val_ul > 255) {
            bytes.clear();
            return bytes;
        }
        bytes.push_back(static_cast<uint8_t>(byte_val_ul));
    }
    return bytes;
}

float is_bin_palindrome(const std::string& hex) {
    if (hex.empty()) return 0.0f;
    std::string bin;
    bin.reserve(hex.length() * 4);
    for (char c : hex) {
        uint8_t val;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') val = 10 + (c - 'A');
        else return 0.0f;

        for (int i = 3; i >= 0; --i)
            bin += ((val >> i) & 1) ? '1' : '0';
    }
    if (bin.empty()) return 0.0f;
    std::string rev = bin;
    std::reverse(rev.begin(), rev.end());
    return bin == rev ? 1.0f : 0.0f;
}

int longest_one_run(const std::string& hex) {
    if (hex.empty()) return 0;
    std::string bin;
    bin.reserve(hex.length() * 4);
    for (char c : hex) {
        uint8_t val;
         if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') val = 10 + (c - 'A');
        else return 0;

        for (int i = 3; i >= 0; --i)
            bin += ((val >> i) & 1) ? '1' : '0';
    }
    if (bin.empty()) return 0;
    int max_run = 0, current_run = 0;
    for (char b : bin) {
        if (b == '1') {
            current_run++;
        } else {
            max_run = std::max(max_run, current_run);
            current_run = 0;
        }
    }
    max_run = std::max(max_run, current_run);
    return max_run;
}

int get_address_type_internal(const std::string& addr) {
    if (addr.empty()) return -1;
    if (addr[0] == '1') return 0;
    if (addr[0] == '3') return 1;
    if (addr.rfind("bc1", 0) == 0) return 2;
    return -1;
}

FeatureSet extract_features(const std::string& privkey_hex) {
    FeatureSet f;

    f.s_priv_hex = privkey_hex;

    f.priv_hex_len = static_cast<float>(privkey_hex.length());
    if (!privkey_hex.empty()) {
        size_t first_digit = privkey_hex.find_first_not_of('0');
        f.priv_hex_zero_prefix = (first_digit == std::string::npos) ? f.priv_hex_len : static_cast<float>(first_digit);

        size_t last_digit = privkey_hex.find_last_not_of('0');
        f.priv_hex_zero_suffix = (last_digit == std::string::npos) ? f.priv_hex_len : static_cast<float>(privkey_hex.length() - 1 - last_digit);

        f.priv_hex_entropy = entropy(privkey_hex);
        f.priv_hex_palindrome = is_palindrome(privkey_hex);
    }


    std::string wif_unc = privkey_hex.empty() ? "" : priv_hex_to_wif(privkey_hex, false);
    std::string wif_comp = privkey_hex.empty() ? "" : priv_hex_to_wif(privkey_hex, true);

    f.wif = wif_unc;
    f.wif_compressed = wif_comp;

    const std::string& wif_principal = wif_comp.empty() ? wif_unc : wif_comp;

    f.wif_present = wif_principal.empty() ? 0.0f : 1.0f;
    f.base58_wif_len = static_cast<float>(wif_principal.length());
    if (!wif_principal.empty()) {
        std::set<char> unique_chars(wif_principal.begin(), wif_principal.end());
        f.base58_wif_unique = static_cast<float>(unique_chars.size());
    }
    f.base58_entropy = entropy(wif_principal);
    f.symmetry = is_palindrome(wif_principal);

    std::string addr1 = privkey_hex.empty() ? "" : private_key_to_address(privkey_hex, true);
    std::string addr2 = privkey_hex.empty() ? "" : private_key_to_address(privkey_hex, false);

    f.addr1_len = static_cast<float>(addr1.length());
    f.addr1_type = static_cast<float>(get_address_type_internal(addr1));

    f.addr2_present = addr2.empty() ? 0.0f : 1.0f;
    f.addr2_len = static_cast<float>(addr2.length());
    f.addr2_type = static_cast<float>(get_address_type_internal(addr2));

    f.longest_one_run = static_cast<float>(longest_one_run(privkey_hex));
    f.bin_palindrome = is_bin_palindrome(privkey_hex);

    f.wif_valid_custom = wif_principal.empty() ? 0.0f : (is_valid_wif(wif_principal) ? 1.0f : 0.0f);
    f.is_compressed_custom = wif_principal.empty() ? 0.0f : (is_compressed_key(wif_principal) ? 1.0f : 0.0f);

    f.addr_entropy_custom = entropy(addr1);
    f.addr_type_p2pkh_custom  = (f.addr1_type == 0.0f) ? 1.0f : 0.0f;
    f.addr_type_p2sh_custom   = (f.addr1_type == 1.0f) ? 1.0f : 0.0f;
    f.addr_type_bech32_custom = (f.addr1_type == 2.0f) ? 1.0f : 0.0f;

    f.seed_word_count = 0.0f;
    f.seed_entropy = 0.0f;
    
    // Lógica de bytes mod 2, 4, 8 (você tinha comentado, pode reativar se necessário)
    // Se reativar, garanta que hex_string_to_bytes é chamado e 'bytes' é preenchido
    std::vector<uint8_t> bytes_for_mod = hex_string_to_bytes(privkey_hex);
    if (!bytes_for_mod.empty()) {
        uint8_t last_byte = bytes_for_mod.back();
        f.is_mod_2 = (last_byte % 2 == 0) ? 1.0f : 0.0f;
        f.is_mod_4 = (last_byte % 4 == 0) ? 1.0f : 0.0f;
        f.is_mod_8 = (last_byte % 8 == 0) ? 1.0f : 0.0f;
    } else {
        f.is_mod_2 = 0.0f;
        f.is_mod_4 = 0.0f;
        f.is_mod_8 = 0.0f;
    }
    f.priv_hex_sympy_score = 0.0f; // Placeholder, como no seu original

    return f;
}