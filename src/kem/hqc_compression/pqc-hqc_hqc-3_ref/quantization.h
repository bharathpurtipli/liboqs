#ifndef QUANTIZATION_H
#define QUANTIZATION_H

#include "data_structures.h"

#define GET_BIT(arr, idx) (((arr[(idx) >> 6] >> ((idx) & 63)) & 1ULL))
#define SET_BIT(arr, idx, val) \
do { \
if (val) arr[(idx) >> 6] |= (1ULL << ((idx) & 63)); \
else arr[(idx) >> 6] &= ~(1ULL << ((idx) & 63)); \
} while (0)

void apply_dither(uint8_t *msg, int n_rs, int n_rm, product_code_spec_t *specs, int num_specs, uint8_t *dither_salt);
void ciphertext_quantization(ciphertext_pke_t *c_pke);
void ciphertext_dequantization(ciphertext_pke_t *c_pke);

#endif
