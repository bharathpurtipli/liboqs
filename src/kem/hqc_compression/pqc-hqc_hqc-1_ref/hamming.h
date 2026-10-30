#ifndef HAMMING_H
#define HAMMING_H

#include <stdint.h>
#include "quantization.h"
#include "namespace.h"

#define POW2(i) (1 << (i))
#define hamming_encode PQCHQC_NAMESPACE(hamming_encode)
#define hamming_decode PQCHQC_NAMESPACE(hamming_decode)
#define composite_hamming_quantization PQCHQC_NAMESPACE(composite_hamming_quantization)
#define composite_hamming_dequantization PQCHQC_NAMESPACE(composite_hamming_dequantization)

void hamming_encode(const uint8_t *msg, int m, uint8_t *codeword);
void hamming_decode(const uint8_t *Y, int m, uint8_t *msg_hat);
void composite_hamming_quantization(uint8_t *compressed_msg, uint8_t *msg, int n_rs, int n_rm, product_code_spec_t *specs, int num_specs);
void composite_hamming_dequantization(uint8_t *msg_hat, uint8_t *compressed_msg, int n_rs, int n_rm, product_code_spec_t *specs, int num_specs);

#endif // HAMMING_H
