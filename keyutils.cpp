#include "base58/libbase58.h"
#include "hash/sha256.h"
#include "rmd160/rmd160.h"
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdlib> // Para strtoul, se hex_string_to_bytes estivesse aqui

#include "keyutils.h"
// Se hex_string_to_bytes é definido em ml_helpers.cpp e declarado em ml_helpers.h:
#include "ml_helpers.h" // Para usar hex_string_to_bytes

#include "secp256k1/Int.h"
#include "secp256k1/Point.h"
#include "secp256k1/SECP256K1.h"

#include <unordered_set>
#include <fstream>

#define SHA256_DIGEST_LENGTH 32

// Supondo que b58_sha256_impl é configurado em outro lugar
 //extern bool (*b58_sha256_impl)(void *, const void *, size_t);
// Supondo que RMD160Data é declarado em rmd160.h
// extern void RMD160Data(const unsigned char *data, unsigned int len, char *digest);


bool my_base58_to_sha256(void* hash_out, const void* base58_data, size_t data_len) {
    const char* input = static_cast<const char*>(base58_data);
    uint8_t decoded[64] = {0};
    size_t out_len = sizeof(decoded);

    if (!b58tobin(decoded, &out_len, input, data_len)) {
        return false;
    }
    sha256(decoded, out_len, static_cast<uint8_t*>(hash_out));
    return true;
}


const char* hexmap_keyutils = "0123456789ABCDEF"; // Renomeado para evitar conflito se outro hexmap global existir
static std::unordered_set<std::string> puzzle_keys;

void tohex_keyutils(char* dst_c_str, int len) { // Renomeado para evitar conflito
    unsigned char* u_dst = reinterpret_cast<unsigned char*>(dst_c_str);
    // Esta função precisa de revisão lógica se a intenção é modificar dst_c_str in-place
    // A implementação original era ambígua. Para uma conversão segura para uma nova string,
    // veja tohex_dst_keyutils ou a versão em helpers.cpp que retorna std::string.
    // Por ora, mantendo a estrutura original o máximo possível, mas pode não funcionar como esperado.
    for (int i = 0; i < len; i++) { // Cuidado: esta lógica modifica o byte original
        if (i < strlen(dst_c_str)) { // Segurança extra
             u_dst[i] = hexmap_keyutils[(u_dst[i] >> 4) & 0xF];
        }
    }
}

void tohex_dst_keyutils(const char* src, int len, char* dst_hex_str) { // Renomeado e const char* src
    for (int i = 0; i < len; i++) {
        unsigned char b = static_cast<unsigned char>(src[i]);
        dst_hex_str[i * 2]     = hexmap_keyutils[b >> 4];
        dst_hex_str[i * 2 + 1] = hexmap_keyutils[b & 0xF];
    }
    dst_hex_str[len * 2] = '\0';
}

std::vector<uint8_t> my_base58_to_sha256_str(const std::string& b58str) { // Renomeado para evitar conflito com a versão void*
    std::vector<uint8_t> hash_out(32);
    unsigned char decoded_buffer[256];
    size_t decoded_len = sizeof(decoded_buffer);

    if (b58tobin(decoded_buffer, &decoded_len, b58str.c_str(), b58str.length())) {
        sha256(decoded_buffer, decoded_len, hash_out.data());
    } else {
        return {};
    }
    return hash_out;
}

std::string priv_hex_to_wif(const std::string& private_key_hex, bool compressed_wif) {
    if (private_key_hex.length() != 64) {
        return "";
    }
    std::vector<uint8_t> priv_key_bytes = hex_string_to_bytes(private_key_hex);
    if (priv_key_bytes.empty() && !private_key_hex.empty()) {
        return "";
    }
    if (priv_key_bytes.size() != 32 && !private_key_hex.empty()) {
         return "";
    }

    std::vector<unsigned char> internal_payload; // Usar unsigned char para consistência com b58check_enc
    internal_payload.reserve(33); // 32 para chave + 1 opcional para compressão
    for(uint8_t byte_val : priv_key_bytes) { // Converter de uint8_t para unsigned char se necessário, mas geralmente são compatíveis
        internal_payload.push_back(static_cast<unsigned char>(byte_val));
    }

    if (compressed_wif) {
        internal_payload.push_back(0x01);
    }

    char wif_buffer[128];
    size_t wif_buffer_size = sizeof(wif_buffer);
    uint8_t version_byte = 0x80;

    if (!b58_sha256_impl) {
        std::cerr << "ERRO CRÍTICO em keyutils (priv_hex_to_wif): b58_sha256_impl não foi configurado!" << std::endl;
        return "WIF_SHA256_IMPL_ERROR";
    }

    bool success = b58check_enc(wif_buffer, &wif_buffer_size, version_byte, internal_payload.data(), internal_payload.size());

    if (success && wif_buffer_size > 0) {
        return std::string(wif_buffer, wif_buffer_size - 1);
    }
    return "";
}

std::string private_key_to_address(const std::string& private_key_hex, bool use_compressed_pubkey) {
    if (private_key_hex.length() != 64) {
        return "";
    }
    std::vector<uint8_t> priv_key_bytes_vec = hex_string_to_bytes(private_key_hex);
    if (priv_key_bytes_vec.empty() && !private_key_hex.empty()) {
        return "";
    }
     if (priv_key_bytes_vec.size() != 32 && !private_key_hex.empty()) {
        return "";
    }

    static Secp256K1 secp_k1_instance;
    static bool secp_k1_initialized = false;
    if (!secp_k1_initialized) {
        secp_k1_instance.Init();
        secp_k1_initialized = true;
    }

    Int priv_int;
    priv_int.SetBase16(private_key_hex.c_str());
    Point pub_point = secp_k1_instance.ComputePublicKey(&priv_int);

    unsigned char pub_key_bytes_raw[65];
    int pub_key_len = use_compressed_pubkey ? 33 : 65;
    secp_k1_instance.GetPublicKeyRaw(use_compressed_pubkey, pub_point, reinterpret_cast<char*>(pub_key_bytes_raw));

    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    sha256(pub_key_bytes_raw, pub_key_len, sha256_digest);

    unsigned char pub_key_hash[20];
    RMD160Data(sha256_digest, SHA256_DIGEST_LENGTH, reinterpret_cast<char*>(pub_key_hash));

    char address_buffer[128];
    size_t address_buffer_size = sizeof(address_buffer);
    uint8_t version = 0x00;

    if (!b58_sha256_impl) {
        std::cerr << "ERRO CRÍTICO em keyutils (private_key_to_address): b58_sha256_impl não foi configurado!" << std::endl;
        return "ADDR_SHA256_IMPL_ERROR";
    }

    bool success = b58check_enc(address_buffer, &address_buffer_size, version, pub_key_hash, 20);

    if (success && address_buffer_size > 0) {
        return std::string(address_buffer, address_buffer_size - 1);
    }
    return "";
}

bool check_key(const char* priv_hex_c_str) {
    std::string priv_hex = priv_hex_c_str ? priv_hex_c_str : "";
    if (priv_hex.length() != 64) {
        return false;
    }
    if (puzzle_keys.empty()) {
        return false;
    }
    std::string addr = private_key_to_address(priv_hex, true);
    if (addr.empty()) {
        addr = private_key_to_address(priv_hex, false);
    }
    return puzzle_keys.find(addr) != puzzle_keys.end();
}

bool load_puzzle_keys(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        std::cerr << "[keyutils] Falha ao abrir arquivo de puzzles: " << path << std::endl;
        return false;
    }
    std::string line;
    size_t count = 0;
    while (std::getline(in, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (!line.empty()) {
            puzzle_keys.insert(line);
            ++count;
        }
    }
    std::cout << "[keyutils] " << count << " puzzles carregados de " << path << std::endl;
    return true;
}