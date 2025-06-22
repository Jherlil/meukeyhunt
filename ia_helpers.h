#pragma once
#include <string>
#include <vector>
#include "IA_wrapper.h"  // usa ia::Range

namespace ia {

bool keep_key(const std::string& priv_hex, const Range& r);
std::vector<float> compress_entropy(const std::string& data);
float symmetry_score(const std::string& str);
int leading_zeros(const std::string& hex);

}
