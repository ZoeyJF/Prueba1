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

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <chrono>
#include <algorithm>
#include <memory>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <queue>
#include "Secp256k1/BTC.h"
#include "Secp256k1/xorfilter.h"
#include "Secp256k1/sha256.h"
#include "Secp256k1/ripemd160.h"

#define IO_BUFFER_SIZE (4 * 1024 * 1024)
#define CHUNK_SIZE (1024 * 1024)

struct hash_entry {
    uint8_t data[HASH160_LEN];
};

static void print_error(const char *msg) {
    fprintf(stderr, "[ERROR] %s\n", msg);
}

static void print_warn(const char *msg) {
    fprintf(stderr, "[WARN] %s\n", msg);
}

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
    values[0] = 3;
    values[1] = 3;
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

static bool parse_hex_or_address(const char *token, size_t token_len, uint8_t *out) {
    if ((token_len == 42 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) || token_len == 40) {
        const char *p = (token_len == 42) ? token + 2 : token;
        for (int i = 0; i < 20; i++) {
            int hi = parse_hex_digit(p[i * 2]);
            int lo = parse_hex_digit(p[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = (uint8_t)((hi << 4) | lo);
        }
        return true;
    }

    if (token_len >= 25 && token_len <= 35 && (token[0] == '1' || token[0] == '3')) {
        return decode_base58_check(token, token_len, out);
    }

    if (token_len >= 42 && token_len <= 90 && (token[0] == 'b' || token[0] == 'B') && (token[1] == 'c' || token[1] == 'C')) {
        return decode_bech32(token, token_len, out);
    }

    return false;
}

static bool is_word_delim(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';' || c == ':' || c == '"' || c == '\'' || c == '|' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}';
}

static int create_temp_chunk(std::vector<hash_entry> &chunk, int chunk_id) {
    if (chunk.empty()) return 0;

    std::sort(chunk.begin(), chunk.end(), [](const hash_entry &a, const hash_entry &b) {
        return memcmp(a.data, b.data, HASH160_LEN) < 0;
    });

    auto last = std::unique(chunk.begin(), chunk.end(), [](const hash_entry &a, const hash_entry &b) {
        return memcmp(a.data, b.data, HASH160_LEN) == 0;
    });
    chunk.erase(last, chunk.end());

    const char *tmp_env = getenv("TMPDIR");
    std::string tdir = (tmp_env && access(tmp_env, W_OK) == 0) ? tmp_env : ((access("/tmp", W_OK) == 0) ? "/tmp" : ".");
    char filename[512];
    snprintf(filename, sizeof(filename), "%s/btc_chunk_%d_%d.tmp", tdir.c_str(), (int)getpid(), chunk_id);

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        print_error("Cannot create temp chunk file");
        return -1;
    }

    uint64_t total_bytes = chunk.size() * HASH160_LEN;
    if ((uint64_t)write(fd, chunk.data(), total_bytes) != total_bytes) {
        close(fd);
        unlink(filename);
        print_error("Cannot write to temp chunk file");
        return -1;
    }

    close(fd);
    chunk.clear();

    return 0;
}

static int merge_chunks_to_bin(std::vector<std::string> &chunk_files, uint64_t *total_unique_hashes) {
    if (chunk_files.empty()) return 0;

    struct CompareHash {
        const std::vector<uint8_t> &hashes;
        CompareHash(const std::vector<uint8_t> &h) : hashes(h) {}
        bool operator()(int a, int b) const {
            return memcmp(hashes.data() + a * HASH160_LEN, hashes.data() + b * HASH160_LEN, HASH160_LEN) > 0;
        }
    };

    std::vector<int> fds(chunk_files.size(), -1);
    std::vector<uint8_t> current_hashes(chunk_files.size() * HASH160_LEN);

    for (size_t i = 0; i < chunk_files.size(); i++) {
        fds[i] = open(chunk_files[i].c_str(), O_RDONLY);
        if (fds[i] < 0) {
            for (size_t j = 0; j < i; j++) if (fds[j] >= 0) close(fds[j]);
            print_error("Cannot open chunk file for merging");
            return -1;
        }
    }

    CompareHash comp(current_hashes);
    std::priority_queue<int, std::vector<int>, CompareHash> pq(comp);

    for (size_t i = 0; i < chunk_files.size(); i++) {
        if (read(fds[i], current_hashes.data() + i * HASH160_LEN, HASH160_LEN) == HASH160_LEN) {
            pq.push((int)i);
        }
    }

    int out_fd = open(BIN_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        for (int fd : fds) if (fd >= 0) close(fd);
        print_error("Cannot create BTC.bin");
        return -1;
    }

    uint8_t *out_buf = (uint8_t*)malloc(IO_BUFFER_SIZE);
    if (!out_buf) {
        close(out_fd);
        for (int fd : fds) if (fd >= 0) close(fd);
        print_error("Memory allocation failed for output buffer");
        return -1;
    }
    size_t out_pos = 0;

    uint8_t prev_hash[HASH160_LEN];
    memset(prev_hash, 0xFF, HASH160_LEN);
    bool has_prev = false;
    uint64_t unique_count = 0;

    while (!pq.empty()) {
        int idx = pq.top();
        pq.pop();

        uint8_t *curr = current_hashes.data() + idx * HASH160_LEN;

        if (!has_prev || memcmp(curr, prev_hash, HASH160_LEN) != 0) {
            if (out_pos + HASH160_LEN > IO_BUFFER_SIZE) {
                if (write(out_fd, out_buf, out_pos) != (ssize_t)out_pos) {
                    print_error("Write error in BTC.bin");
                    free(out_buf);
                    close(out_fd);
                    for (int fd : fds) if (fd >= 0) close(fd);
                    return -1;
                }
                out_pos = 0;
            }
            memcpy(out_buf + out_pos, curr, HASH160_LEN);
            out_pos += HASH160_LEN;

            memcpy(prev_hash, curr, HASH160_LEN);
            has_prev = true;
            unique_count++;
        }

        if (read(fds[idx], curr, HASH160_LEN) == HASH160_LEN) {
            pq.push(idx);
        }
    }

    if (out_pos > 0) {
        if (write(out_fd, out_buf, out_pos) != (ssize_t)out_pos) {
            print_error("Write error flushing BTC.bin");
            free(out_buf);
            close(out_fd);
            for (int fd : fds) if (fd >= 0) close(fd);
            return -1;
        }
        out_pos = 0;
    }

    close(out_fd);
    free(out_buf);

    for (int fd : fds) {
        if (fd >= 0) close(fd);
    }

    for (auto &cf : chunk_files) {
        unlink(cf.c_str());
    }

    *total_unique_hashes = unique_count;
    return 0;
}

static int stage_read_and_sort_external(const std::vector<std::string> &input_files, uint64_t *total_unique_hashes) {
    std::vector<hash_entry> chunk;
    chunk.reserve(CHUNK_SIZE);
    std::vector<std::string> chunk_files;
    int chunk_id = 0;
    uint64_t total_valid = 0;
    uint64_t skipped = 0;

    for (const auto &path : input_files) {
        std::ifstream fin(path);
        if (!fin.is_open()) {
            std::cerr << "[WARN] Cannot open input file: " << path << std::endl;
            continue;
        }

        std::string line;
        while (std::getline(fin, line)) {
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

                hash_entry he;
                if (parse_hex_or_address(token, token_len, he.data)) {
                    chunk.push_back(he);
                    total_valid++;

                    if (chunk.size() >= CHUNK_SIZE) {
                        const char *tmp_env = getenv("TMPDIR");
                        std::string tdir = (tmp_env && access(tmp_env, W_OK) == 0) ? tmp_env : ((access("/tmp", W_OK) == 0) ? "/tmp" : ".");
                        char fname[512];
                        snprintf(fname, sizeof(fname), "%s/btc_chunk_%d_%d.tmp", tdir.c_str(), (int)getpid(), chunk_id);

                        if (create_temp_chunk(chunk, chunk_id) != 0) {
                            fin.close();
                            return -1;
                        }

                        chunk_files.push_back(fname);
                        chunk_id++;
                    }
                } else {
                    skipped++;
                }

                start_pos = end_pos;
            }
        }
        fin.close();
    }

    if (total_valid == 0) {
        print_error("No valid hashes found in input");
        return -1;
    }

    if (!chunk.empty()) {
        const char *tmp_env = getenv("TMPDIR");
        std::string tdir = (tmp_env && access(tmp_env, W_OK) == 0) ? tmp_env : ((access("/tmp", W_OK) == 0) ? "/tmp" : ".");
        char fname[512];
        snprintf(fname, sizeof(fname), "%s/btc_chunk_%d_%d.tmp", tdir.c_str(), (int)getpid(), chunk_id);

        if (create_temp_chunk(chunk, chunk_id) != 0) {
            for (auto &cf : chunk_files) unlink(cf.c_str());
            return -1;
        }

        chunk_files.push_back(fname);
    }

    if (merge_chunks_to_bin(chunk_files, total_unique_hashes) != 0) {
        for (auto &cf : chunk_files) unlink(cf.c_str());
        return -1;
    }

    return 0;
}

static int stage_write_idx(bool is_sparse, uint64_t n_hashes) {
    int bin_fd = open(BIN_FILE, O_RDONLY);
    if (bin_fd < 0) {
        print_error("Cannot open BTC.bin for IDX generation");
        return -1;
    }

    int idx_fd = open(IDX_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (idx_fd < 0) {
        close(bin_fd);
        print_error("Cannot create BTC.idx");
        return -1;
    }

    uint64_t record_count = is_sparse ? ((n_hashes + IDX_SPARSE_STRIDE - 1) / IDX_SPARSE_STRIDE) : n_hashes;

    idx_header_t hdr;
    hdr.magic = IDX_MAGIC;
    hdr.format_type = is_sparse ? IDX_FORMAT_SPARSE : IDX_FORMAT_FULL;
    hdr.total_hashes = n_hashes;
    hdr.record_count = record_count;
    hdr.stride = is_sparse ? IDX_SPARSE_STRIDE : 1;
    hdr.entry_size = is_sparse ? sizeof(idx_record_sparse_t) : sizeof(idx_record_t);

    if (write(idx_fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(bin_fd);
        close(idx_fd);
        print_error("Cannot write IDX header");
        return -1;
    }

    uint8_t *out_buf = (uint8_t*)malloc(IO_BUFFER_SIZE);
    if (!out_buf) {
        close(bin_fd);
        close(idx_fd);
        print_error("Memory allocation failed for IDX buffer");
        return -1;
    }
    size_t out_pos = 0;

    uint8_t hash_buf[HASH160_LEN];

    if (!is_sparse) {
        for (uint64_t i = 0; i < n_hashes; i++) {
            off64_t offset = (off64_t)i * (off64_t)HASH160_LEN;
            if (pread64(bin_fd, hash_buf, HASH160_LEN, offset) != HASH160_LEN) {
                free(out_buf);
                close(bin_fd);
                close(idx_fd);
                print_error("Read error from BTC.bin");
                return -1;
            }

            idx_record_t rec;
            memcpy(rec.hash, hash_buf, HASH160_LEN);
            rec.record_index = i;

            if (out_pos + sizeof(idx_record_t) > IO_BUFFER_SIZE) {
                if (write(idx_fd, out_buf, out_pos) != (ssize_t)out_pos) {
                    free(out_buf);
                    close(bin_fd);
                    close(idx_fd);
                    print_error("Write error to BTC.idx");
                    return -1;
                }
                out_pos = 0;
            }
            memcpy(out_buf + out_pos, &rec, sizeof(idx_record_t));
            out_pos += sizeof(idx_record_t);
        }
    } else {
        for (uint64_t b = 0; b < record_count; b++) {
            uint64_t start_rec = b * IDX_SPARSE_STRIDE;
            off64_t offset = (off64_t)start_rec * (off64_t)HASH160_LEN;

            if (pread64(bin_fd, hash_buf, HASH160_LEN, offset) != HASH160_LEN) {
                free(out_buf);
                close(bin_fd);
                close(idx_fd);
                print_error("Read error from BTC.bin");
                return -1;
            }

            idx_record_sparse_t rec;
            memcpy(rec.hash, hash_buf, HASH160_LEN);
            rec.record_index = (uint32_t)start_rec;

            if (out_pos + sizeof(idx_record_sparse_t) > IO_BUFFER_SIZE) {
                if (write(idx_fd, out_buf, out_pos) != (ssize_t)out_pos) {
                    free(out_buf);
                    close(bin_fd);
                    close(idx_fd);
                    print_error("Write error to BTC.idx");
                    return -1;
                }
                out_pos = 0;
            }
            memcpy(out_buf + out_pos, &rec, sizeof(idx_record_sparse_t));
            out_pos += sizeof(idx_record_sparse_t);
        }
    }

    if (out_pos > 0) {
        if (write(idx_fd, out_buf, out_pos) != (ssize_t)out_pos) {
            free(out_buf);
            close(bin_fd);
            close(idx_fd);
            print_error("Write error flushing BTC.idx");
            return -1;
        }
    }

    free(out_buf);
    close(bin_fd);
    close(idx_fd);

    return 0;
}

static int stage_write_xor(uint64_t n_hashes) {
    int fd = open(BIN_FILE, O_RDONLY);
    if (fd < 0) {
        print_error("Cannot open BTC.bin for XOR generation");
        return -1;
    }

    struct stat st;
    fstat(fd, &st);
    size_t sz = st.st_size;

    if (sz == 0 || (sz % HASH160_LEN) != 0) {
        close(fd);
        print_error("Invalid BTC.bin size");
        return -1;
    }

    uint8_t *map = static_cast<uint8_t*>(mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0));
    if (map == MAP_FAILED) {
        close(fd);
        print_error("mmap failed for BTC.bin");
        return -1;
    }

    xorfilter_t xf;
    memset(&xf, 0, sizeof(xf));

    int r = xorfilter_build(&xf, map, n_hashes, 16);
    if (r != 0) {
        munmap(map, sz);
        close(fd);
        print_error("XOR filter build failed");
        return -1;
    }

    int out_fd = open(XOR_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        xorfilter_free(&xf);
        munmap(map, sz);
        close(fd);
        print_error("Cannot create BTC.xor");
        return -1;
    }

    xor_header_t hdr;
    hdr.magic = XOR_MAGIC;
    hdr.version = XOR_VERSION;
    hdr.seed = xf.seed;
    hdr.block_length = xf.block_length;
    hdr.fingerprint_bits = xf.fingerprint_bits;
    hdr.entry_count = xf.entry_count;
    hdr.array_length = xf.array_length;

    if (write(out_fd, &hdr, sizeof(xor_header_t)) != sizeof(xor_header_t)) {
        close(out_fd);
        xorfilter_free(&xf);
        munmap(map, sz);
        close(fd);
        print_error("Cannot write XOR header");
        return -1;
    }

    if (write(out_fd, xf.fingerprints, xf.array_length) != (ssize_t)xf.array_length) {
        close(out_fd);
        xorfilter_free(&xf);
        munmap(map, sz);
        close(fd);
        print_error("Cannot write XOR fingerprints");
        return -1;
    }

    close(out_fd);
    xorfilter_free(&xf);

    munmap(map, sz);
    close(fd);

    return 0;
}

int main(int argc, char **argv) {
    std::vector<std::string> input_files;
    bool is_sparse = false;
    bool format_selected = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sparse") == 0 || strcmp(argv[i], "-sparse") == 0) {
            is_sparse = true;
            format_selected = true;
        } else if (strcmp(argv[i], "--full") == 0 || strcmp(argv[i], "-full") == 0) {
            is_sparse = false;
            format_selected = true;
        } else if (argv[i][0] != '-') {
            input_files.push_back(argv[i]);
        }
    }

    // Default to BTC.hex if no files specified
    if (input_files.empty()) {
        if (access("BTC.hex", R_OK) == 0) {
            input_files.push_back("BTC.hex");
        } else {
            std::cerr << "Usage: " << argv[0] << " [input_file_1 ... input_file_N] [--sparse | --full]\n";
            std::cerr << "[ERROR] No input files specified and default BTC.hex was not found.\n";
            return 1;
        }
    }

    if (!format_selected) {
        std::cout << "\n============================================================\n";
        std::cout << "CREATE-BIX Index Format Selection\n";
        std::cout << "============================================================\n";
        std::cout << "Option [1]: Full Index (28 bytes/entry + header)\n";
        std::cout << "Option [2]: Sparse Index (24 bytes/block + header)\n";
        std::cout << "Choice [1/2]: ";
        std::cout.flush();

        char choice = '1';
        if (std::cin >> choice) {
            if (choice == '2' || choice == 'B' || choice == 'b') {
                is_sparse = true;
            }
        }
    }

    auto start_time = std::chrono::steady_clock::now();

    std::cout << "\n[INFO] Starting database generation for " << input_files.size() << " input file(s).\n";
    std::cout << "[INFO] Selected Index Format: " << (is_sparse ? "Sparse Index" : "Full Index") << "\n";

    uint64_t n_hashes = 0;
    if (stage_read_and_sort_external(input_files, &n_hashes) != 0) {
        return 1;
    }

    std::cout << "[INFO] BTC.bin created with " << n_hashes << " unique 20-byte hashes.\n";

    if (stage_write_idx(is_sparse, n_hashes) != 0) {
        return 1;
    }
    std::cout << "[INFO] BTC.idx created successfully with IDX_MAGIC (0x49445831) header.\n";

    if (stage_write_xor(n_hashes) != 0) {
        return 1;
    }
    std::cout << "[INFO] BTC.xor filter generated successfully.\n";

    auto end_time = std::chrono::steady_clock::now();
    double total_duration = std::chrono::duration<double>(end_time - start_time).count();

    struct stat st_bin, st_idx, st_xor;
    stat(BIN_FILE, &st_bin);
    stat(IDX_FILE, &st_idx);
    stat(XOR_FILE, &st_xor);

    double bin_mb = (double)st_bin.st_size / (1024.0 * 1024.0);
    double idx_mb = (double)st_idx.st_size / (1024.0 * 1024.0);
    double xor_mb = (double)st_xor.st_size / (1024.0 * 1024.0);
    double total_gb = (double)(st_bin.st_size + st_idx.st_size + st_xor.st_size) / (1024.0 * 1024.0 * 1024.0);

    std::cout << "\n============================================================\n";
    std::cout << "                 DATABASE GENERATION SUMMARY                \n";
    std::cout << "============================================================\n";
    std::cout << " Total Unique Hashes : " << n_hashes << "\n";
    std::cout << " Index Type          : " << (is_sparse ? "SPARSE" : "FULL") << "\n";
    printf(" BTC.bin Size        : %.2f MB\n", bin_mb);
    printf(" BTC.idx Size        : %.2f MB\n", idx_mb);
    printf(" BTC.xor Size        : %.2f MB\n", xor_mb);
    printf(" Total DB Footprint  : %.6f GB\n", total_gb);
    printf(" Total Build Time    : %.2f s\n", total_duration);
    std::cout << "============================================================\n";
    std::cout << "[OK] Creation completed successfully.\n";

    return 0;
}
