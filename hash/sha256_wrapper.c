#include "hash/sha256.h"   /* cabeçalho que declara sha256_Raw */

void sha256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    sha256_Raw(data, len, hash);   /* chama a implementação real */
}
