#pragma once
#include <string>
#include <vector>
#include <cstdint> // Para std::uint8_t

#ifndef HELPERS_H
#define HELPERS_H

// Funções de helpers.h que oferecem funcionalidade C++ distinta, renomeadas:
// A versão original de 'trim' em helpers.h retornava std::string.
// A versão em util.h (char *trim(char*, const char*)) será a padrão.
std::string h_trim_string(char *str, const char *whitechars); 
std::string to_hex(uint64_t val);

// A versão original de 'isValidHex' em helpers.h retornava bool.
// A versão em util.h (int isValidHex(char*)) será a padrão.
bool h_isValidHex_bool(char* str);

// A versão original de 'hexs2bin' em helpers.h retornava void.
// A versão em util.h (int hexs2bin(char*, unsigned char*)) será a padrão.
void h_hexs2bin_void(char* hex, unsigned char* bin);

// A função 'indexOf' em helpers.h é similar à de util.h.
// Assumindo que a versão de util.h é a preferida, removemos a declaração de helpers.h.
// Se uma implementação C++ específica de indexOf for necessária, ela pode ser adicionada aqui com um novo nome.

// Outras declarações de helper que não causam conflito direto ou são específicas de C++
std::vector<std::uint8_t> hex_string_to_bytes(const std::string& hex);
std::string to_hex(const std::vector<unsigned char>& data); // Converte vetor de bytes para string hexadecimal (C++)
// std::string to_hex(const std::vector<std::uint8_t>& data); // Alternativa com uint8_t

std::string to_base64(const std::vector<unsigned char>& data);
bool is_hex_string(const std::string& str); // Verifica std::string
bool is_valid_wif(const std::string& wif);
bool is_compressed_key(const std::string& wif);
float calculate_entropy(const std::string& input);
int count_leading_zeros(const std::string& hex);


// === Utility functions for ML ===
#include <cmath>
#include <unordered_map>
#include <algorithm>

static inline float entropy(const std::string& data){
    if(data.empty()) return 0.0f;
    std::unordered_map<char,int> freq;
    for(char c: data) freq[c]++;
    float H=0.0f;
    for(auto &p: freq){
        float prob = static_cast<float>(p.second)/data.size();
        H -= prob * std::log2(prob);
    }
    return H;
}

static inline float is_palindrome(const std::string& s){
    return (!s.empty() && std::equal(s.begin(), s.begin()+s.size()/2, s.rbegin())) ? 1.0f : 0.0f;
}

static inline int get_address_type_internal(const std::string &){ return 0; }

#endif // HELPERS_H
