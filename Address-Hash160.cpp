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
#include <array>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <algorithm>
#include <queue>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "Secp256k1/sha256.h"
#include "Secp256k1/ripemd160.h"

// Chunk threshold: 2,000,000 hashes * 20 bytes = 40 MB RAM per chunk.
// Keeps peak memory usage strictly bounded under 100 MB regardless of file sizes (6 GB to 60+ GB).
static const size_t CHUNK_HASH_LIMIT = 2000000;
static const size_t OUT_BUFFER_SIZE = 1024 * 1024;
static const size_t STREAM_BUFFER_SIZE = 64 * 1024; // 64 KB per stream to prevent OOM with hundreds of chunks

static std::string get_temp_dir() {
    const char *tmp = getenv("TMPDIR");
    if (tmp && access(tmp, W_OK) == 0) return std::string(tmp);
    if (access("/tmp", W_OK) == 0) return "/tmp";
    return ".";
}

using Hash20 = std::array<uint8_t, 20>;

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
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ';' || c == ':' || c == '"' || c == '\'' || c == '|' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}';
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX_CHARS[in[i] >> 4];
        out[i * 2 + 1] = HEX_CHARS[in[i] & 15];
    }
    out[len * 2] = '\0';
}

static int flush_chunk_to_temp_file(std::vector<Hash20> &chunk, int chunk_id, std::vector<std::string> &temp_files) {
    if (chunk.empty()) return 0;

    // Sort chunk lexicographically
    std::sort(chunk.begin(), chunk.end(), [](const Hash20 &a, const Hash20 &b) {
        return memcmp(a.data(), b.data(), 20) < 0;
    });

    // Deduplicate in chunk
    auto last_it = std::unique(chunk.begin(), chunk.end(), [](const Hash20 &a, const Hash20 &b) {
        return memcmp(a.data(), b.data(), 20) == 0;
    });
    chunk.erase(last_it, chunk.end());

    std::string tdir = get_temp_dir();
    char path[512];
    snprintf(path, sizeof(path), "%s/addr_chunk_%d_%d.tmp", tdir.c_str(), (int)getpid(), chunk_id);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        std::cerr << "\n[ERROR] Cannot open temp chunk file: " << path << std::endl;
        return -1;
    }

    uint64_t bytes_to_write = chunk.size() * 20;
    if ((uint64_t)write(fd, chunk.data(), bytes_to_write) != bytes_to_write) {
        std::cerr << "\n[ERROR] Cannot write to temp chunk file: " << path << std::endl;
        close(fd);
        unlink(path);
        return -1;
    }

    close(fd);
    temp_files.push_back(path);
    chunk.clear();
    return 0;
}

static uint64_t merge_temp_chunks_to_btc_hex(const std::vector<std::string> &temp_files) {
    if (temp_files.empty()) return 0;

    FILE *out_fp = fopen("BTC.hex", "wb");
    if (!out_fp) {
        std::cerr << "[ERROR] Cannot open BTC.hex for writing." << std::endl;
        return 0;
    }

    struct ChunkStream {
        int fd;
        std::vector<uint8_t> buffer;
        size_t buf_pos;
        size_t buf_end;
        uint8_t current_hash[20];
        bool has_data;

        ChunkStream() : fd(-1), buffer(STREAM_BUFFER_SIZE), buf_pos(0), buf_end(0), has_data(false) {}

        bool read_next() {
            if (fd < 0) return false;
            if (buf_pos + 20 > buf_end) {
                size_t rem = buf_end - buf_pos;
                if (rem > 0) {
                    memmove(buffer.data(), buffer.data() + buf_pos, rem);
                }
                ssize_t n = read(fd, buffer.data() + rem, STREAM_BUFFER_SIZE - rem);
                if (n <= 0) {
                    if (rem < 20) {
                        has_data = false;
                        return false;
                    }
                    buf_end = rem;
                } else {
                    buf_end = rem + n;
                }
                buf_pos = 0;
            }
            if (buf_pos + 20 <= buf_end) {
                memcpy(current_hash, buffer.data() + buf_pos, 20);
                buf_pos += 20;
                has_data = true;
                return true;
            }
            has_data = false;
            return false;
        }
    };

    std::vector<ChunkStream> streams(temp_files.size());
    for (size_t i = 0; i < temp_files.size(); i++) {
        streams[i].fd = open(temp_files[i].c_str(), O_RDONLY);
        streams[i].buf_pos = 0;
        streams[i].buf_end = 0;
        streams[i].has_data = false;
        if (streams[i].fd >= 0) {
            streams[i].read_next();
        }
    }

    struct StreamComparator {
        std::vector<ChunkStream> &s;
        StreamComparator(std::vector<ChunkStream> &streams_ref) : s(streams_ref) {}
        bool operator()(int a, int b) const {
            return memcmp(s[a].current_hash, s[b].current_hash, 20) > 0;
        }
    };

    StreamComparator comp(streams);
    std::priority_queue<int, std::vector<int>, StreamComparator> pq(comp);

    for (size_t i = 0; i < streams.size(); i++) {
        if (streams[i].has_data) {
            pq.push((int)i);
        }
    }

    char *out_buf = (char *)malloc(OUT_BUFFER_SIZE);
    if (!out_buf) {
        std::cerr << "[ERROR] Memory allocation failed for output buffer." << std::endl;
        fclose(out_fp);
        return 0;
    }
    size_t out_buf_pos = 0;

    uint8_t prev_hash[20];
    memset(prev_hash, 0xFF, 20);
    bool has_prev = false;
    uint64_t unique_count = 0;

    while (!pq.empty()) {
        int stream_idx = pq.top();
        pq.pop();

        uint8_t *curr = streams[stream_idx].current_hash;

        if (!has_prev || memcmp(curr, prev_hash, 20) != 0) {
            char hex_str[41];
            bytes_to_hex(curr, 20, hex_str);

            if (out_buf_pos + 41 > OUT_BUFFER_SIZE) {
                fwrite(out_buf, 1, out_buf_pos, out_fp);
                out_buf_pos = 0;
            }
            memcpy(out_buf + out_buf_pos, hex_str, 40);
            out_buf_pos += 40;
            out_buf[out_buf_pos++] = '\n';

            memcpy(prev_hash, curr, 20);
            has_prev = true;
            unique_count++;
        }

        if (streams[stream_idx].read_next()) {
            pq.push(stream_idx);
        }
    }

    if (out_buf_pos > 0) {
        fwrite(out_buf, 1, out_buf_pos, out_fp);
    }

    fflush(out_fp);
    fclose(out_fp);
    free(out_buf);

    for (auto &st : streams) {
        if (st.fd >= 0) close(st.fd);
    }

    for (const auto &path : temp_files) {
        unlink(path.c_str());
    }

    return unique_count;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file_1> [input_file_2 ... input_file_N]" << std::endl;
        return 1;
    }

    std::vector<std::string> input_files;
    for (int i = 1; i < argc; i++) {
        input_files.push_back(argv[i]);
    }

    auto start_time = std::chrono::steady_clock::now();
    size_t total_files = input_files.size();

    std::vector<Hash20> chunk;
    chunk.reserve(CHUNK_HASH_LIMIT);
    std::vector<std::string> temp_chunk_files;
    int chunk_id = 0;

    const size_t READ_BUF_SIZE = 4 * 1024 * 1024;
    char *read_buf = (char *)malloc(READ_BUF_SIZE);
    if (!read_buf) {
        std::cerr << "Error: Memory allocation failed for read buffer." << std::endl;
        return 1;
    }

    std::cout << "======================================================================\n";
    std::cout << "        Universal Address & Hash160 Extractor and Sorter              \n";
    std::cout << "======================================================================\n";

    uint64_t total_extracted = 0;

    for (size_t f_idx = 0; f_idx < total_files; f_idx++) {
        const std::string &fname = input_files[f_idx];
        FILE *in_fp = fopen(fname.c_str(), "rb");
        if (!in_fp) {
            std::cerr << "[WARN] Could not open file: " << fname << std::endl;
            continue;
        }

        struct stat st;
        uint64_t file_size = 0;
        if (fstat(fileno(in_fp), &st) == 0) {
            file_size = st.st_size;
        }

        uint64_t bytes_processed = 0;
        uint64_t lines_processed = 0;
        uint64_t valid_addresses_in_file = 0;
        std::string line_remainder = "";

        auto last_ui_update = std::chrono::steady_clock::now();

        auto process_line = [&](const std::string &line) {
            lines_processed++;
            if (line.empty()) return;

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

                Hash20 h;
                bool found = false;

                // 1. Bitcoin P2PKH / P2SH (Base58Check)
                if (token_len >= 25 && token_len <= 35 && (token[0] == '1' || token[0] == '3')) {
                    if (decode_base58_check(token, token_len, h.data())) {
                        found = true;
                    }
                }
                // 2. Bitcoin SegWit Bech32/Bech32m (bc1q / bc1p)
                else if (token_len >= 42 && token_len <= 90 &&
                         (token[0] == 'b' || token[0] == 'B') &&
                         (token[1] == 'c' || token[1] == 'C')) {
                    if (decode_bech32(token, token_len, h.data())) {
                        found = true;
                    }
                }
                // 3. Ethereum or Raw Hash160 (0x prefix or raw 40 hex chars)
                else if ((token_len == 42 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) || token_len == 40) {
                    if (decode_ethereum(token, token_len, h.data())) {
                        found = true;
                    }
                }

                if (found) {
                    chunk.push_back(h);
                    valid_addresses_in_file++;
                    total_extracted++;

                    if (chunk.size() >= CHUNK_HASH_LIMIT) {
                        flush_chunk_to_temp_file(chunk, chunk_id++, temp_chunk_files);
                    }
                }

                start_pos = end_pos;
            }
        };

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

                    process_line(line);
                }
            }

            if (chunk_start < bytes_read) {
                line_remainder.append(read_buf + chunk_start, bytes_read - chunk_start);
            }

            auto now = std::chrono::steady_clock::now();
            double elapsed_ui = std::chrono::duration<double>(now - last_ui_update).count();
            if (elapsed_ui >= 0.25 || bytes_processed == file_size) {
                double pct = file_size > 0 ? ((double)bytes_processed / (double)file_size) * 100.0 : 100.0;
                printf("\r[Processing %zu/%zu] %s: %.1f%% | Lines: %lu | Extracted: %lu | Total: %lu | Chunks: %zu",
                       f_idx + 1, total_files, fname.c_str(), pct,
                       (unsigned long)lines_processed,
                       (unsigned long)valid_addresses_in_file,
                       (unsigned long)total_extracted,
                       temp_chunk_files.size());
                fflush(stdout);
                last_ui_update = now;
            }
        }

        if (!line_remainder.empty()) {
            process_line(line_remainder);
        }

        fclose(in_fp);

        printf("\r[Completed %zu/%zu] %s: 100.0%% | Lines: %lu | Extracted: %lu | Total: %lu | Chunks: %zu\n",
               f_idx + 1, total_files, fname.c_str(),
               (unsigned long)lines_processed,
               (unsigned long)valid_addresses_in_file,
               (unsigned long)total_extracted,
               temp_chunk_files.size());
        fflush(stdout);
    }

    free(read_buf);

    if (!chunk.empty()) {
        flush_chunk_to_temp_file(chunk, chunk_id++, temp_chunk_files);
    }

    std::cout << "\nMerging and deduplicating " << temp_chunk_files.size() << " temporary chunk(s) to BTC.hex..." << std::endl;
    auto merge_start = std::chrono::steady_clock::now();

    uint64_t total_unique = merge_temp_chunks_to_btc_hex(temp_chunk_files);

    auto merge_end = std::chrono::steady_clock::now();
    double merge_duration = std::chrono::duration<double>(merge_end - merge_start).count();
    std::cout << "Merging completed in " << merge_duration << " s. Unique hashes: " << total_unique << std::endl;

    auto end_time = std::chrono::steady_clock::now();
    double total_duration = std::chrono::duration<double>(end_time - start_time).count();

    struct stat st_out;
    uint64_t btc_hex_size = 0;
    if (stat("BTC.hex", &st_out) == 0) {
        btc_hex_size = st_out.st_size;
    }

    double size_mb = (double)btc_hex_size / (1024.0 * 1024.0);
    double size_gb = (double)btc_hex_size / (1024.0 * 1024.0 * 1024.0);

    std::cout << "\n======================================================================\n";
    std::cout << "                 CONVERSION COMPLETE - SUMMARY                        \n";
    std::cout << "======================================================================\n";
    std::cout << " Total Files Processed : " << total_files << "\n";
    std::cout << " Total Addresses Read  : " << total_extracted << "\n";
    std::cout << " Total Unique Hashes   : " << total_unique << "\n";
    printf(" BTC.hex File Size     : %.2f MB (%.6f GB)\n", size_mb, size_gb);
    printf(" Total Execution Time  : %.2f s (%.2f min)\n", total_duration, total_duration / 60.0);
    std::cout << " Output Saved To       : BTC.hex\n";
    std::cout << "======================================================================\n";

    return 0;
}
