#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Tabela base58
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Decodifica base58. Retorna tamanho do output. Simples, limitado.
int base58_decode(const char* input, uint8_t* output, size_t outlen) {
    size_t input_len = strlen(input);
    if (input_len > 52 || outlen < 34) return -1;

    memset(output, 0, outlen);

    for (size_t i = 0; i < input_len; ++i) {
        const char* p = strchr(BASE58_ALPHABET, input[i]);
        if (!p) return -1;
        int carry = p - BASE58_ALPHABET;
        for (int j = outlen - 1; j >= 0; --j) {
            carry += 58 * output[j];
            output[j] = carry % 256;
            carry /= 256;
        }
        if (carry != 0) return -1;
    }

    return outlen;
}

// Verifica se WIF é válido com base na decodificação base58 e tamanho
double is_valid_wif(const char* wif_str) {
    if (!wif_str) return 0.0;
    size_t len = strlen(wif_str);
    if (len < 51 || len > 52) return 0.0;

    uint8_t decoded[38];
    if (base58_decode(wif_str, decoded, sizeof(decoded)) < 0)
        return 0.0;

    // WIF começa com 0x80
    if (decoded[0] != 0x80) return 0.0;

    return 1.0;
}

// Verifica se é uma chave comprimida: byte extra 0x01 antes do checksum
double is_compressed_key(const char* wif_str) {
    if (!wif_str) return 0.0;

    uint8_t decoded[38];
    if (base58_decode(wif_str, decoded, sizeof(decoded)) < 0)
        return 0.0;

    // Checa se penúltimo byte (posição 33) é 0x01
    if (decoded[33] == 0x01) return 1.0;

    return 0.0;
}
