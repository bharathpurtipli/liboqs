/**
* @file hamming.c
 * @brief Implementation of Hamming codes and composite Hamming (de)quantization for the ciphertext compression.
 *
 * This file provides functions for:
 *  - Printing bit arrays for debugging
 *  - Encoding and decoding using standard Hamming codes
 *  - Composite Hamming code quantization/dequantization for product codes
 *  - Hamming distance calculation
 */

#include "hamming.h"
#include <stdlib.h>


/**
 * @brief Encode a message using a Hamming code of parameter m.
 *
 * @param[in] msg Input message bits (length n - m, where n = 2^m - 1)
 * @param[in] m Number of parity bits
 * @param[out] codeword Encoded Hamming codeword of length n
 */
void hamming_encode(const uint8_t *msg, int m, uint8_t *codeword) {
    int n = (1 << m) - 1;

    // Insert data bits into non-parity positions
    for (int i = 0, j = 0; i < n; i++) {
        int pos = i + 1;
        if ((pos & (pos - 1)) == 0) {
            codeword[i] = 0; // parity placeholder
        } else {
            codeword[i] = msg[j++];
        }
    }

    // Compute parity bits
    for (int i = 0; i < m; i++) {
        int p = POW2(i);
        int parity = 0;
        for (int j = 1; j <= n; j++) {
            if (j & p) {
                parity ^= codeword[j - 1];
            }
        }
        codeword[p - 1] = (uint8_t)parity;
    }
}

/**
 * @brief Decode a received Hamming codeword.
 *
 * Performs syndrome computation and single-bit error correction if needed.
 *
 * @param[in] Y Received codeword of length n = 2^m - 1
 * @param[in] m Number of parity bits
 * @param[out] msg_hat Decoded message bits of length n - m
 */
void hamming_decode(const uint8_t *Y, int m, uint8_t *msg_hat) {
    int n = (1 << m) - 1;
    uint8_t *temp = (uint8_t *)malloc(n * sizeof(uint8_t));
    //print_bits(Y, n, "Y");
    for (int i = 0; i < n; i++) temp[i] = Y[i];

    // Compute syndrome
    int syndrome = 0;
    for (int i = 0; i < m; i++) {
        int p = POW2(i);
        int parity = 0;
        for (int j = 1; j <= n; j++) {
            if (j & p) {
                parity ^= temp[j - 1];
            }
        }
        if (parity) syndrome |= p;
    }

    // Correct single-bit error if detected
    if (syndrome > 0 && syndrome <= n) {
        temp[syndrome - 1] ^= 1;
    }

    // Extract information bits
    for (int i = 0, j = 0; i < n; i++) {
        int pos = i + 1;
        if ((pos & (pos - 1)) != 0) {
            msg_hat[j++] = temp[i];
        }
    }

    free(temp);
}

/**
 * @brief Composite Hamming quantization for a product code.
 *
 * Applies multiple Hamming codes (as specified) row by row, and concatenates the decoded
 * information bits with any leftover (uncoded) bits.
 *
 * @param[out] compressed_msg Output compressed bit array
 * @param[in] msg Input encoded message (size n_rs * n_rm)
 * @param[in] n_rs Number of rows (blocks)
 * @param[in] n_rm Length of each row before quantization
 * @param[in] specs Array of product code specifications (Hamming parameters and counts)
 * @param[in] num_specs Number of entries in specs
 */
void composite_hamming_quantization(uint8_t *compressed_msg, uint8_t *msg, int n_rs, int n_rm, product_code_spec_t *specs, int num_specs) {
    // calculates size of hamming product code Q_tilde
    int decoded_row_len = 0;
    for (int s = 0; s < num_specs; s++) {
        int m = specs[s].m;
        int n = (1 << m) - 1;
        int k = n - m;
        decoded_row_len += specs[s].count * k;
    }
    // calculates size of trivial code
    int leftover = n_rm;
    for (int s = 0; s < num_specs; s++) {
        leftover -= specs[s].count * ((1 << specs[s].m) - 1);
    }
    decoded_row_len += leftover;

    // decode
    for (int r = 0; r < n_rs; r++) {
        int src_offset = r * n_rm;  // gives the current n_rm block position in the original msg
        int dst_offset = r * decoded_row_len;  // gives the current block position in the compressed msg
        int pos = 0;  // gives the current position in each n_rm block.

        // Apply each Hamming code
        // iterate over different hamming codes
        for (int s = 0; s < num_specs; s++) {
            int m = specs[s].m;
            int n = (1 << m) - 1;
            int k = n - m;
            // iterate over the number (counts) of hamming codes with the same m
            for (int c = 0; c < specs[s].count; c++) {
                hamming_decode(&msg[src_offset + pos], m,
                               &compressed_msg[dst_offset]);
                dst_offset += k;
                pos += n;
            }
        }

        // Copy leftover bits unchanged
        for (int i = 0; i < leftover; i++) {
            compressed_msg[dst_offset + i] = msg[src_offset + pos + i];
        }
    }
}

/**
 * @brief Composite Hamming dequantization for a product code.
 *
 * Reverses the composite_hamming_quantization by re-encoding with Hamming codes
 * and reinserting parity bits, restoring the full-length message.
 *
 * @param[out] msg_hat Output reconstructed message
 * @param[in] compressed_msg Input compressed bit array
 * @param[in] n_rs Number of rows (blocks)
 * @param[in] n_rm Length of each row after dequantization
 * @param[in] specs Array of product code specifications (Hamming parameters and counts)
 * @param[in] num_specs Number of entries in specs
 */
void composite_hamming_dequantization(uint8_t *msg_hat, uint8_t *compressed_msg, int n_rs, int n_rm, product_code_spec_t *specs,
                                      int num_specs) {
    // calculates size of hamming product code Q_tilde
    int decoded_row_len = 0;
    for (int s = 0; s < num_specs; s++) {
        int m = specs[s].m;
        int n = (1 << m) - 1;
        int k = n - m;
        decoded_row_len += specs[s].count * k;
    }
    // calculates size of trivial code
    int leftover = n_rm;
    for (int s = 0; s < num_specs; s++) {
        leftover -= specs[s].count * ((1 << specs[s].m) - 1);
    }
    decoded_row_len += leftover;

    // encode
    for (int r = 0; r < n_rs; r++) {
        int dst_offset = r * n_rm;
        int src_offset = r * decoded_row_len;
        int pos = 0;

        for (int s = 0; s < num_specs; s++) {
            int m = specs[s].m;
            int n = (1 << m) - 1;
            int k = n - m;

            for (int c = 0; c < specs[s].count; c++) {
                hamming_encode(&compressed_msg[src_offset], m,
                               &msg_hat[dst_offset + pos]);
                src_offset += k;
                pos += n;
            }
        }

        // Copy leftover bits unchanged
        for (int i = 0; i < leftover; i++) {
            msg_hat[dst_offset + pos + i] = compressed_msg[src_offset + i];
        }
    }
}
