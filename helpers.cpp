#include "helpers.h"
#include "ml_helpers.h"

#include <sys/stat.h>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <numeric>
#include <unordered_map>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <cstdio>
#include <cstdlib>

std::string to_hex(uint64_t val) {
    char buffer[17];
    snprintf(buffer, sizeof(buffer), "%016llx", (unsigned long long)val);
    return std::string(buffer);
}

std::string h_trim_string(char *str, const char *whitechars) {
    if (str == nullptr) return "";
    std::string s(str);
    size_t start = s.find_first_not_of(whitechars);
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(whitechars);
    return s.substr(start, end - start + 1);
}

bool h_isValidHex_bool(char* str) {
    if (str == nullptr) return false;
    char* current = str;
    while (*current) {
        if (!isxdigit(static_cast<unsigned char>(*current))) return false;
        current++;
    }
    return true;
}

void h_hexs2bin_void(char* hex, unsigned char* bin) {
    if (hex == nullptr || bin == nullptr) return;
    size_t len = strlen(hex);
    if (len % 2 != 0) return;

    for (size_t i = 0; i < len; i += 2) {
        sscanf(&hex[i], "%2hhx", &bin[i / 2]);
    }
}

std::string to_hex(const std::vector<unsigned char>& data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char byte : data) {
        out.push_back(hex_chars[(byte >> 4) & 0x0F]);
        out.push_back(hex_chars[byte & 0x0F]);
    }
    return out;
}
