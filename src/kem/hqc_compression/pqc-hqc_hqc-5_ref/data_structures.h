/**
 * @file    data_structures.h
 * @brief   HQC-PKE and HQC-KEM ciphertext data structures.
 */

#ifndef HQC_DATA_STRUCTURES_H
#define HQC_DATA_STRUCTURES_H

#include <stdint.h>
#include "parameters.h"

/**
 * @brief Public-key encryption ciphertext.
 *
 * - u: length VEC_N_SIZE_64 words
 * - v: length VEC_N_SIZE_64 words
 */
typedef struct {
    uint64_t u[VEC_N_SIZE_64]; /**< first vector half */
    uint64_t v[VEC_N_SIZE_64]; /**< second vector half */
    uint8_t help[PARAM_SECURITY_BYTES]; /**< helper data for dithering */
} ciphertext_pke_t;

/**
 * @brief Key-encapsulation mechanism ciphertext.
 *
 * Wraps a PKE ciphertext along with the salt used in the KEM:
 * - c_pke: the ciphertext for PKE
 * - salt:  additional randomness (SALT_BYTES bytes)
 */
typedef struct {
    ciphertext_pke_t c_pke;   /**< embedded PKE ciphertext */
    uint8_t salt[SALT_BYTES]; /**< per-encapsulation salt */
} ciphertext_kem_t;

/**
 * @brief 128-bit codeword representation.
 *
 * A Reed-Muller RM(1,7) codeword is 128 bits long. This union allows
 * viewing the same data as an array of bytes or 32-bit words.
 */
typedef union {
    uint8_t u8[16];  /**< Byte-wise access (16 bytes) */
    uint32_t u32[4]; /**< Word-wise access (4 32-bit words) */
} rm_codeword_t;

/**
 * @brief Specification of a Hamming product code component.
 *
 * Describes how many times a particular Hamming code is used
 * in the construction of the composite/quantization code for each Reed-Muller codeword.
 *
 * - m: Hamming code parameter (number of parity bits).
 *      The corresponding code has length n = 2^m - 1 and dimension k = n - m.
 * - count: Number of times this (n, k) Hamming code is applied.
 */
typedef struct {
    int m;      /**< Hamming code parameter */
    int count;  /**< Number of times this code is repeated */
} product_code_spec_t;

#endif  // HQC_DATA_STRUCTURES_H
