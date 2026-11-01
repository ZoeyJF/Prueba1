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

static int parse_hex_hash(const std::string &line, uint8_t *out) {
    if (line.length() < 40) return -1;

    for (int i = 0; i < 20; i++) {
        char hi = line[i * 2];
        char lo = line[i * 2 + 1];

        int val_hi = -1, val_lo = -1;

        if (hi >= '0' && hi <= '9') val_hi = hi - '0';
        else if (hi >= 'a' && hi <= 'f') val_hi = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') val_hi = hi - 'A' + 10;

        if (lo >= '0' && lo <= '9') val_lo = lo - '0';
        else if (lo >= 'a' && lo <= 'f') val_lo = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') val_lo = lo - 'A' + 10;

        if (val_hi == -1 || val_lo == -1) return -1;

        out[i] = (uint8_t)((val_hi << 4) | val_lo);
    }
    return 0;
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

static int stage_read_and_sort_external(const char *hex_path, uint64_t *total_unique_hashes) {
    std::ifstream fin(hex_path);
    if (!fin.is_open()) {
        print_error("Cannot open input file");
        return -1;
    }

    std::vector<hash_entry> chunk;
    chunk.reserve(CHUNK_SIZE);
    std::vector<std::string> chunk_files;
    int chunk_id = 0;
    uint64_t total_valid = 0;
    uint64_t skipped = 0;

    std::string line;
    while (std::getline(fin, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ' || line.back() == '\t')) {
            line.pop_back();
        }
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
            line.erase(line.begin());
        }

        if (line.empty()) continue;

        hash_entry he;
        if (parse_hex_hash(line, he.data) != 0) {
            skipped++;
            continue;
        }

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
    }

    fin.close();

    if (skipped > 0) {
        print_warn("Skipped invalid lines during parsing");
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
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_hex_file> [--sparse | --full]\n";
        return 1;
    }

    bool is_sparse = false;
    bool format_selected = false;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--sparse") == 0 || strcmp(argv[i], "-sparse") == 0) {
            is_sparse = true;
            format_selected = true;
        } else if (strcmp(argv[i], "--full") == 0 || strcmp(argv[i], "-full") == 0) {
            is_sparse = false;
            format_selected = true;
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

    std::cout << "\n[INFO] Starting database generation for: " << argv[1] << "\n";
    std::cout << "[INFO] Selected Index Format: " << (is_sparse ? "Sparse Index" : "Full Index") << "\n";

    uint64_t n_hashes = 0;
    if (stage_read_and_sort_external(argv[1], &n_hashes) != 0) {
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
