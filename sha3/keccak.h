// sha3/keccak.h
#ifndef KECCAK_H
#define KECCAK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void	keccakf1600(uint64_t A[25]);

#ifdef __cplusplus
} // Fim do extern "C"
#endif

#endif	/* KECCAK_H */