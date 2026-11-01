/*
 * Copyright 2026 ZoeyJF
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <sys/stat.h>
#include <unistd.h>

#include "Secp256k1/sha256.h"
#include "Secp256k1/ripemd160.h"

static const int B58_MAP[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1
};

static const int8_t BECH32_MAP[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    15,-1,10,17,21,20,26,30,  7, 5,-1,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8, 23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14,  6, 4, 2,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8, 23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14,  6, 4, 2,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1
};

static const char HEX_CHARS[] = "0123456789abcdef";

static inline int parse_hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool decode_base58_check(const char *str, size_t len, uint8_t *h160_out) {
    if (len < 25 || len > 35) return false;
    uint8_t bin[64] = {0};
    size_t bin_len = 0;

    for (size_t i = 0; i < len; i++) {
        int v = B58_MAP[(unsigned char)str[i]];
        if (v < 0) return false;
        int carry = v;
        for (size_t j = 0; j < bin_len; j++) {
            carry += (int)bin[j] * 58;
            bin[j] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
        while (carry > 0) {
            bin[bin_len++] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
    }

    size_t leading_zeros = 0;
    while (leading_zeros < len && str[leading_zeros] == '1') {
        leading_zeros++;
    }

    size_t total_len = leading_zeros + bin_len;
    if (total_len != 25) return false;

    uint8_t decoded[25] = {0};
    for (size_t i = 0; i < bin_len; i++) {
        decoded[total_len - 1 - i] = bin[i];
    }

    uint8_t hash1[32], hash2[32];
    sha256(decoded, 21, hash1);
    sha256(hash1, 32, hash2);

    if (memcmp(decoded + 21, hash2, 4) != 0) return false;

    memcpy(h160_out, decoded + 1, 20);
    return true;
}

static uint64_t bech32_polymod(const uint8_t *values, size_t len) {
    uint64_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = chk >> 25;
        chk = ((chk & 0x1FFFFFF) << 5) ^ values[i];
        if (b & 1)  chk ^= 0x3b6a57b2UL;
        if (b & 2)  chk ^= 0x26508e6dUL;
        if (b & 4)  chk ^= 0x1ea119faUL;
        if (b & 8)  chk ^= 0x3d4233ddUL;
        if (b & 16) chk ^= 0x2a1462b3UL;
    }
    return chk;
}

static bool convert_bits_5to8(const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    uint32_t maxv = 255;
    uint32_t max_acc = (1u << (5 + 8 - 1)) - 1;
    for (size_t i = 0; i < inlen; i++) {
        uint8_t value = in[i];
        if (value >> 5) return false;
        acc = ((acc << 5) | value) & max_acc;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((acc >> bits) & maxv);
        }
    }
    if (bits >= 5 || ((acc << (8 - bits)) & maxv)) {
        return false;
    }
    *outlen = o;
    return true;
}

static bool decode_bech32(const char *str, size_t len, uint8_t *h160_out) {
    if (len < 42 || len > 90) return false;
    if (str[0] != 'b' && str[0] != 'B') return false;
    if (str[1] != 'c' && str[1] != 'C') return false;

    size_t pos_one = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '1') pos_one = i;
    }
    if (pos_one != 2) return false;

    uint8_t values[128];
    values[0] = 3; // ('b' | 'B') >> 5
    values[1] = 3; // ('c' | 'C') >> 5
    values[2] = 0;
    values[3] = (uint8_t)(str[0] & 31);
    values[4] = (uint8_t)(str[1] & 31);

    size_t v_count = 5;
    uint8_t data5bit[128];
    size_t count5bit = 0;

    for (size_t i = 3; i < len; i++) {
        int8_t v = BECH32_MAP[(unsigned char)str[i]];
        if (v < 0) return false;
        values[v_count++] = (uint8_t)v;
        data5bit[count5bit++] = (uint8_t)v;
    }

    uint64_t chk = bech32_polymod(values, v_count);
    bool is_bech32  = (chk == 1);
    bool is_bech32m = (chk == 0x2bc830a3UL);

    if (!is_bech32 && !is_bech32m) return false;

    if (count5bit < 6) return false;
    uint8_t witver = data5bit[0];
    if (witver > 16) return false;

    size_t payload_5bit_len = count5bit - 6 - 1;
    uint8_t prog[64];
    size_t prog_len = 0;
    if (!convert_bits_5to8(data5bit + 1, payload_5bit_len, prog, &prog_len)) {
        return false;
    }

    if (prog_len != 20) return false;

    memcpy(h160_out, prog, 20);
    return true;
}

static bool decode_ethereum(const char *str, size_t len, uint8_t *h160_out) {
    if (len == 42 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        str += 2;
        len -= 2;
    }
    if (len != 40) return false;

    for (size_t i = 0; i < 40; i += 2) {
        int hi = parse_hex_digit(str[i]);
        int lo = parse_hex_digit(str[i + 1]);
        if (hi < 0 || lo < 0) return false;
        h160_out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool is_word_delim(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';' || c == ':' || c == '"' || c == '\'' || c == '|';
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX_CHARS[in[i] >> 4];
        out[i * 2 + 1] = HEX_CHARS[in[i] & 15];
    }
    out[len * 2] = '\0';
}

static void print_ui(size_t current_file_idx, size_t total_files, const std::string &current_filename,
                     double file_progress_pct, uint64_t total_converted, double elapsed_sec) {
    printf("\033[H\033[J");
    printf("======================================================================\n");
    printf("                  BTC & ETH Address -> Hash160 Converter              \n");
    printf("======================================================================\n");
    printf(" File Progress  : [%zu/%zu] %s\n", current_file_idx, total_files, current_filename.c_str());
    printf(" Conversion     : %.2f%%\n", file_progress_pct);
    printf(" Total Hashes   : %lu\n", total_converted);
    printf(" Elapsed Time   : %.2f s\n", elapsed_sec);
    printf(" Output Target  : BTC.hex\n");
    printf("======================================================================\n");
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file1> [file2 ...]" << std::endl;
        return 1;
    }

    std::vector<std::string> input_files;
    for (int i = 1; i < argc; i++) {
        input_files.push_back(argv[i]);
    }

    FILE *out_fp = fopen("BTC.hex", "a");
    if (!out_fp) {
        std::cerr << "Error: Cannot open or create BTC.hex for writing." << std::endl;
        return 1;
    }

    auto start_time = std::chrono::steady_clock::now();

    size_t total_files = input_files.size();
    uint64_t total_hashes_converted = 0;

    const size_t READ_BUF_SIZE = 1024 * 1024;
    char *read_buf = (char *)malloc(READ_BUF_SIZE);

    const size_t OUT_BUF_SIZE = 1024 * 1024;
    char *out_buf = (char *)malloc(OUT_BUF_SIZE);
    size_t out_buf_pos = 0;

    if (!read_buf || !out_buf) {
        std::cerr << "Error: Memory allocation failed." << std::endl;
        if (read_buf) free(read_buf);
        if (out_buf) free(out_buf);
        fclose(out_fp);
        return 1;
    }

    for (size_t f_idx = 0; f_idx < total_files; f_idx++) {
        const std::string &fname = input_files[f_idx];
        FILE *in_fp = fopen(fname.c_str(), "rb");
        if (!in_fp) {
            continue;
        }

        struct stat st;
        uint64_t file_size = 0;
        if (fstat(fileno(in_fp), &st) == 0) {
            file_size = st.st_size;
        }

        uint64_t bytes_processed = 0;
        std::string line_remainder = "";

        auto last_ui_update = std::chrono::steady_clock::now();

        while (true) {
            size_t bytes_read = fread(read_buf, 1, READ_BUF_SIZE, in_fp);
            if (bytes_read == 0) break;
            bytes_processed += bytes_read;

            size_t chunk_start = 0;
            for (size_t i = 0; i < bytes_read; i++) {
                if (read_buf[i] == '\n' || read_buf[i] == '\r') {
                    std::string line = line_remainder;
                    if (chunk_start < i) {
                        line.append(read_buf + chunk_start, i - chunk_start);
                    }
                    line_remainder.clear();
                    chunk_start = i + 1;

                    if (!line.empty()) {
                        size_t l_len = line.length();
                        size_t start_pos = 0;
                        while (start_pos < l_len) {
                            while (start_pos < l_len && is_word_delim(line[start_pos])) {
                                start_pos++;
                            }
                            if (start_pos >= l_len) break;

                            size_t end_pos = start_pos;
                            while (end_pos < l_len && !is_word_delim(line[end_pos])) {
                                end_pos++;
                            }

                            size_t token_len = end_pos - start_pos;
                            const char *token = line.c_str() + start_pos;

                            uint8_t h160[20];
                            bool found = false;

                            if (token_len >= 25 && token_len <= 35 && (token[0] == '1' || token[0] == '3')) {
                                if (decode_base58_check(token, token_len, h160)) {
                                    found = true;
                                }
                            } else if (token_len >= 42 && token_len <= 90 && (token[0] == 'b' || token[0] == 'B') && (token[1] == 'c' || token[1] == 'C')) {
                                if (decode_bech32(token, token_len, h160)) {
                                    found = true;
                                }
                            } else if ((token_len == 42 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) || token_len == 40) {
                                if (decode_ethereum(token, token_len, h160)) {
                                    found = true;
                                }
                            }

                            if (found) {
                                char hex_str[41];
                                bytes_to_hex(h160, 20, hex_str);

                                if (out_buf_pos + 41 > OUT_BUF_SIZE) {
                                    fwrite(out_buf, 1, out_buf_pos, out_fp);
                                    out_buf_pos = 0;
                                }
                                memcpy(out_buf + out_buf_pos, hex_str, 40);
                                out_buf_pos += 40;
                                out_buf[out_buf_pos++] = '\n';
                                total_hashes_converted++;
                            }

                            start_pos = end_pos;
                        }
                    }
                }
            }

            if (chunk_start < bytes_read) {
                line_remainder.append(read_buf + chunk_start, bytes_read - chunk_start);
            }

            auto now = std::chrono::steady_clock::now();
            double elapsed_ui = std::chrono::duration<double>(now - last_ui_update).count();
            if (elapsed_ui >= 0.2 || bytes_processed == file_size) {
                double pct = file_size > 0 ? ((double)bytes_processed / (double)file_size) * 100.0 : 100.0;
                double total_elapsed = std::chrono::duration<double>(now - start_time).count();
                print_ui(f_idx + 1, total_files, fname, pct, total_hashes_converted, total_elapsed);
                last_ui_update = now;
            }
        }

        if (!line_remainder.empty()) {
            std::string line = line_remainder;
            size_t l_len = line.length();
            size_t start_pos = 0;
            while (start_pos < l_len) {
                while (start_pos < l_len && is_word_delim(line[start_pos])) {
                    start_pos++;
                }
                if (start_pos >= l_len) break;

                size_t end_pos = start_pos;
                while (end_pos < l_len && !is_word_delim(line[end_pos])) {
                    end_pos++;
                }

                size_t token_len = end_pos - start_pos;
                const char *token = line.c_str() + start_pos;

                uint8_t h160[20];
                bool found = false;

                if (token_len >= 25 && token_len <= 35 && (token[0] == '1' || token[0] == '3')) {
                    if (decode_base58_check(token, token_len, h160)) {
                        found = true;
                    }
                } else if (token_len >= 42 && token_len <= 90 && (token[0] == 'b' || token[0] == 'B') && (token[1] == 'c' || token[1] == 'C')) {
                    if (decode_bech32(token, token_len, h160)) {
                        found = true;
                    }
                } else if ((token_len == 42 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) || token_len == 40) {
                    if (decode_ethereum(token, token_len, h160)) {
                        found = true;
                    }
                }

                if (found) {
                    char hex_str[41];
                    bytes_to_hex(h160, 20, hex_str);

                    if (out_buf_pos + 41 > OUT_BUF_SIZE) {
                        fwrite(out_buf, 1, out_buf_pos, out_fp);
                        out_buf_pos = 0;
                    }
                    memcpy(out_buf + out_buf_pos, hex_str, 40);
                    out_buf_pos += 40;
                    out_buf[out_buf_pos++] = '\n';
                    total_hashes_converted++;
                }

                start_pos = end_pos;
            }
        }

        fclose(in_fp);
    }

    if (out_buf_pos > 0) {
        fwrite(out_buf, 1, out_buf_pos, out_fp);
        out_buf_pos = 0;
    }

    fflush(out_fp);
    fclose(out_fp);

    free(read_buf);
    free(out_buf);

    auto end_time = std::chrono::steady_clock::now();
    double total_duration = std::chrono::duration<double>(end_time - start_time).count();

    struct stat st_out;
    uint64_t btc_hex_size = 0;
    if (stat("BTC.hex", &st_out) == 0) {
        btc_hex_size = st_out.st_size;
    }

    double size_mb = (double)btc_hex_size / (1024.0 * 1024.0);
    double size_gb = (double)btc_hex_size / (1024.0 * 1024.0 * 1024.0);

    printf("\033[H\033[J");
    printf("======================================================================\n");
    printf("                 CONVERSION COMPLETE - SUMMARY                        \n");
    printf("======================================================================\n");
    printf(" Total Files Processed : %zu\n", total_files);
    printf(" Total Hashes Written  : %lu\n", total_hashes_converted);
    printf(" BTC.hex File Size     : %.2f MB (%.4f GB)\n", size_mb, size_gb);
    printf(" Total Execution Time  : %.2f s\n", total_duration);
    printf(" Output Saved To       : BTC.hex\n");
    printf("======================================================================\n");

    return 0;
}
