#ifndef BASE58_H
#define BASE58_H

#include <stddef.h> // Para size_t
#pragma once
#include <vector>
#include <string>

std::vector<uint8_t> base58_decode(const std::string& input);


#ifdef __cplusplus
extern "C" {
#endif

// Assinatura que o linker está procurando:
size_t base58_encode_check(const unsigned char* data, size_t data_len, char* output_buffer, size_t output_buffer_len);

#ifdef __cplusplus
} // Fim do extern "C"
#endif

#endif // BASE58_H