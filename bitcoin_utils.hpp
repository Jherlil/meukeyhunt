#pragma once

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>
#include <string>
#include <cmath>
#include <map>
#include <set>
#include <cassert>
#include <algorithm>

#include "secp256k1/Int.h"
#include "secp256k1/Point.h"
#include "secp256k1/SECP256K1.h"
#include "secp256k1/IntGroup.h"

std::vector<unsigned char> base58_decode(const std::string& input);
bool is_valid_wif(const std::string& wif);
bool is_compressed_key(const std::string& wif);
std::string priv_to_address(const std::string& priv_hex);
float compute_base58_entropy(const std::string& base58);
std::string classify_address_type(const std::string& addr);
std::string priv_hex_to_wif(const std::string& priv_hex, bool compressed);
std::string private_key_to_address(const std::string& priv_hex, bool compressed);
