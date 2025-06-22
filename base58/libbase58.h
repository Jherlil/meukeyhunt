// base58/libbase58.h
#ifndef LIBBASE58_H_KEYHUNT
#define LIBBASE58_H_KEYHUNT

#include <stddef.h> // Para size_t
#include <stdbool.h> // Para bool
#include <stdint.h>  // Para uint8_t

#ifdef __cplusplus
extern "C" {
#endif


extern bool (*b58_sha256_impl)(void *, const void *, size_t);

extern bool b58tobin(void *bin, size_t *binsz, const char *b58, size_t b58sz);
extern int b58check(const void *bin, size_t binsz, const char *b58, size_t b58sz);

extern bool b58enc_custom(char *b58, size_t *b58sz, const void *bin, size_t binsz,char* buffer);
extern bool b58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz);
extern bool b58check_enc(char *b58c, size_t *b58c_sz, uint8_t ver, const void *data, size_t datasz);

#ifdef __cplusplus
}
#endif

#endif