#include <stdlib.h>
#include "quantization.h"
#include "hamming.h"
#include "data_structures.h"
#include "parameters.h"
#include "symmetric.h"  // for XOF

#ifdef VERBOSE
#include <stdio.h>

/**
 * @brief Print a bit array as 0/1 sequence.
 *
 * @param arr   Input array of bits (values 0/1).
 * @param len   Number of bits to print.
 * @param label Optional label string (printed before bits).
 */
void print_bits(const uint8_t *arr, int len, const char *label) {
    if (label) {
        printf("%s: ", label);
    }
    for (int i = 0; i < len; i++) {
        printf("%d", arr[i]);
    }
    printf("\n");
}

/**
 * @brief Print a byte array as hexadecimal.
 *
 * @param label Optional label string.
 * @param buf   Input buffer.
 * @param len   Buffer length in bytes.
 */
void print_hex(const char *label, const uint8_t *buf, size_t len) {
    if (label) {
        printf("%s: ", label);
    }
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

#endif


/**
 * @brief Unpack bits from a uint64_t array into a uint8_t array.
 *
 * Each bit of @p in is extracted and stored in @p out as a single 0/1 value.
 *
 * @param in       Input array of 64-bit words.
 * @param out      Output bit array (0/1 values).
 * @param num_bits Number of bits to unpack.
 */
static void unpack_bits(const uint64_t *in, uint8_t *out, int num_bits) {
    for (int i = 0; i < num_bits; i++) {
        out[i] = GET_BIT(in, i);
    }
}

/**
 * @brief Unpack bits from a uint8_t array into a uint8_t array.
 *
 * Each bit of @p in is extracted and stored in @p out as a single 0/1 value.
 * This variant is used when the source buffer is in bytes rather than 64-bit words.
 *
 * @param in       Input byte array.
 * @param out      Output bit array (0/1 values).
 * @param num_bits Number of bits to unpack.
 */
static void unpack_bits_unint8(const uint8_t *in, uint8_t *out, int num_bits) {
    for (int i = 0; i < num_bits; i++) {
        out[i] = GET_BIT(in, i);
    }
}

/**
 * @brief Pack bits from a uint8_t array into a uint64_t array.
 *
 * Each value in @p in (0/1) is written into the corresponding bit of @p out.
 *
 * @param out      Output array of 64-bit words.
 * @param in       Input bit array (0/1 values).
 * @param num_bits Number of bits to pack.
 */
static void pack_bits(uint64_t *out, const uint8_t *in, int num_bits) {
    for (int i = 0; i < num_bits; i++) {
        SET_BIT(out, i, in[i]);
    }
}

/**
 * @brief Apply dither to a Reed-Muller/RS product codeword.
 *
 * The dither bits select positions in the codeword to flip.
 *
 * @param msg         Message/codeword bits to modify (length n_rs * n_rm).
 * @param n_rs        Number of RS blocks.
 * @param n_rm        Block length for Reed-Muller code.
 * @param specs       Product code specification array.
 * @param num_specs   Number of entries in @p specs.
 * @param dither_salt Input randomness (bit array).
 */
void apply_dither(uint8_t *msg, int n_rs, int n_rm, product_code_spec_t *specs, int num_specs, uint8_t *dither_salt) {
    int salt_pos = 0;

    for (int r = 0; r < n_rs; r++) {
        int base = r * n_rm;

        int rm_block_pos = 0;
        for (int s = 0; s < num_specs; s++) {
            int m = specs[s].m;
            int n = (1 << m) - 1;

            for (int c = 0; c < specs[s].count; c++) {
                int index = 0;
                for (int b = 0; b < m; b++) {
                    index = (index << 1) | dither_salt[salt_pos++];
                }
                if (index < n) {
                    msg[base + rm_block_pos + index] ^= 1;
                }
                rm_block_pos += n;
            }
        }

        for (int s = 0; s < num_specs; s++) {
            rm_block_pos += 0;
        }
    }
}

/**
 * @brief Quantize a PKE ciphertext.
 *
 * Performs:
 *  - Convert @p v to bit array.
 *  - Apply dithering using helper data.
 *  - Compress with composite Hamming quantization.
 *  - Store back into ciphertext structure.
 *
 * @param c_pke PKE ciphertext to be quantized.
 */
void ciphertext_quantization(ciphertext_pke_t *c_pke) {

    // convert v to uint8_t bit array
    uint8_t *v_bits = calloc(PARAM_N1N2, sizeof(uint8_t));
    unpack_bits(c_pke->v, v_bits, PARAM_N1N2);
    uint8_t *compressed_v_bits = calloc(COMPRESSED_V, sizeof(uint8_t));

    // specify quantization code
    product_code_spec_t specs[] = PRODUCT_CODE_SPECS;
    int num_specs = sizeof(specs) / sizeof(specs[0]);

    // apply dither
    shake256_xof_ctx help_xof_ctx = {0};
    xof_init(&help_xof_ctx, c_pke->help, PARAM_SECURITY_BYTES);
    uint8_t *dither = (uint8_t *)malloc(DITHER_BYTES * sizeof(uint8_t));
    xof_get_bytes(&help_xof_ctx, dither, DITHER_BYTES);
    uint8_t *dither_bits = (uint8_t *)malloc(DITHER_BITS * sizeof(uint8_t));
    unpack_bits_unint8(dither, dither_bits, DITHER_BITS);
    apply_dither(v_bits, PARAM_N1, PARAM_N2, specs, num_specs, dither_bits);

    // compress
    composite_hamming_quantization(compressed_v_bits,v_bits, PARAM_N1, PARAM_N2, specs, num_specs);

    // safe as uint64_t in c_pke.v
    pack_bits(c_pke->v, compressed_v_bits, COMPRESSED_V);

#ifdef VERBOSE
    print_bits(v_bits, PARAM_N1N2, "\n\nv: ")
    print_hex("\n\nhelp for dither: ",c_pke->help, PARAM_SECURITY_BYTES);
    print_bits(compressed_v_bits, COMPRESSED_V, "\n\ncompressed_v: ")
#endif

    free(v_bits);
    free(compressed_v_bits);
    free(dither);
    free(dither_bits);

}

/**
 * @brief Dequantize a PKE ciphertext.
 *
 * Performs:
 *  - Convert compressed @p v to bit array.
 *  - Decompress with composite Hamming decoding.
 *  - Apply dithering using helper data.
 *  - Store back into ciphertext structure.
 *
 * @param c_pke PKE ciphertext to be dequantized.
 */
void ciphertext_dequantization(ciphertext_pke_t *c_pke) {

    // convert v to uint8_t bit array
    uint8_t *compressed_v_bits = calloc(COMPRESSED_V, sizeof(uint8_t));
    unpack_bits(c_pke->v, compressed_v_bits, COMPRESSED_V);
    uint8_t *decompressed_v_bits = calloc(PARAM_N1N2, sizeof(uint8_t));

    // specify quantization code
    product_code_spec_t specs[] = PRODUCT_CODE_SPECS;
    int num_specs = sizeof(specs) / sizeof(specs[0]);

    // decompress
    composite_hamming_dequantization(decompressed_v_bits, compressed_v_bits, PARAM_N1, PARAM_N2, specs, num_specs);

    // apply dither
    shake256_xof_ctx help_xof_ctx = {0};
    xof_init(&help_xof_ctx, c_pke->help, PARAM_SECURITY_BYTES);
    uint8_t *dither = (uint8_t *)malloc(DITHER_BYTES * sizeof(uint8_t));
    xof_get_bytes(&help_xof_ctx, dither, DITHER_BYTES);
    uint8_t *dither_bits = (uint8_t *)malloc(DITHER_BITS * sizeof(uint8_t));
    unpack_bits_unint8(dither, dither_bits, DITHER_BITS);
    apply_dither(decompressed_v_bits, PARAM_N1, PARAM_N2, specs, num_specs, dither_bits);

    // safe as uint64_t in c_pke.v
    pack_bits(c_pke->v, decompressed_v_bits, PARAM_N1N2);

#ifdef VERBOSE
    print_bits(compressed_v_bits, COMPRESSED_V, "\n\ncompressed_v: ")
    print_hex("\n\nhelp for dither: ",c_pke->help, PARAM_SECURITY_BYTES);
    print_bits(decompressed_v_bits, PARAM_N1N2, "\n\ndecompressed_v: ")
#endif

    free(compressed_v_bits);
    free(decompressed_v_bits);
    free(dither);
    free(dither_bits);
}
