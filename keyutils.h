#ifndef KEYUTILS_H
#define KEYUTILS_H

#include <cstddef>

bool my_base58_to_sha256(void* dst, const void* src, size_t len);
bool check_key(const char* privkey_hex);
bool load_puzzle_keys(const std::string& path);


// Funções que serão implementadas em keyutils.cpp
// Certifique-se que estas NÃO estão também definidas em bitcoin_utils.cpp
std::string priv_hex_to_wif(const std::string& private_key_hex, bool compressed_wif);
std::string private_key_to_address(const std::string& private_key_hex, bool use_compressed_pubkey);


// Se você precisar de uma função para converter chave pública para endereço em keyutils:
// std::string public_key_to_address_util(const std::string& public_key_hex);


std::vector<uint8_t> hex_string_to_bytes(const std::string& hex);

#endif // KEYUTILS_H