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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>
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
#define MAX_OPEN_FILES 64

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
    
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/btc_chunk_%d.tmp", chunk_id);
    
    FILE *f = fopen(filename, "wb");
    if (!f) {
        print_error("Cannot create temp chunk file");
        return -1;
    }
    
    for (auto &he : chunk) {
        fwrite(he.data, 1, HASH160_LEN, f);
    }
    
    fclose(f);
    chunk.clear();
    
    return 0;
}

static int merge_chunks_to_bin(std::vector<std::string> &chunk_files) {
    if (chunk_files.empty()) return 0;
    
    std::priority_queue<
        std::pair<int, int>, 
        std::vector<std::pair<int, int>>, 
        std::greater<std::pair<int, int>>
    > pq;
    
    std::vector<FILE*> fds(chunk_files.size(), nullptr);
    std::vector<uint8_t> current_hashes(chunk_files.size() * HASH160_LEN);
    
    for (size_t i = 0; i < chunk_files.size(); i++) {
        fds[i] = fopen(chunk_files[i].c_str(), "rb");
        if (!fds[i]) {
            for (size_t j = 0; j < i; j++) {
                if (fds[j]) fclose(fds[j]);
            }
            print_error("Cannot open chunk file for merging");
            return -1;
        }
        
        if (fread(current_hashes.data() + i * HASH160_LEN, 1, HASH160_LEN, fds[i]) == HASH160_LEN) {
            pq.push({0, (int)i});
        }
    }
    
    FILE *fout = fopen(BIN_FILE, "wb");
    if (!fout) {
        for (auto fd : fds) if (fd) fclose(fd);
        print_error("Cannot create BTC.bin");
        return -1;
    }
    
    char *buf = (char*)malloc(IO_BUFFER_SIZE);
    if (!buf) {
        fclose(fout);
        for (auto fd : fds) if (fd) fclose(fd);
        print_error("Memory allocation failed");
        return -1;
    }
    setvbuf(fout, buf, _IOFBF, IO_BUFFER_SIZE);
    
    uint8_t prev_hash[HASH160_LEN];
    memset(prev_hash, 0xFF, HASH160_LEN);
    bool has_prev = false;
    
    while (!pq.empty()) {
        auto top = pq.top();
        pq.pop();
        int idx = top.second;
        
        uint8_t *curr = current_hashes.data() + idx * HASH160_LEN;
        
        if (!has_prev || memcmp(curr, prev_hash, HASH160_LEN) != 0) {
            fwrite(curr, 1, HASH160_LEN, fout);
            memcpy(prev_hash, curr, HASH160_LEN);
            has_prev = true;
        }
        
        if (fread(curr, 1, HASH160_LEN, fds[idx]) == HASH160_LEN) {
            pq.push({0, idx});
        }
    }
    
    fclose(fout);
    free(buf);
    
    for (auto fd : fds) {
        if (fd) fclose(fd);
    }
    
    for (auto &cf : chunk_files) {
        unlink(cf.c_str());
    }
    
    return 0;
}

static int stage_read_and_sort_external(const char *hex_path) {
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
            char fname[256];
            snprintf(fname, sizeof(fname), "/tmp/btc_chunk_%d.tmp", chunk_id);
            
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
        char fname[256];
        snprintf(fname, sizeof(fname), "/tmp/btc_chunk_%d.tmp", chunk_id);
        
        if (create_temp_chunk(chunk, chunk_id) != 0) {
            for (auto &cf : chunk_files) unlink(cf.c_str());
            return -1;
        }
        
        chunk_files.push_back(fname);
    }
    
    if (merge_chunks_to_bin(chunk_files) != 0) {
        for (auto &cf : chunk_files) unlink(cf.c_str());
        return -1;
    }
    
    return 0;
}

static int stage_write_idx_full() {
    FILE *fin = fopen(BIN_FILE, "rb");
    if (!fin) {
        print_error("Cannot open BTC.bin for IDX generation");
        return -1;
    }
    
    fseek(fin, 0, SEEK_END);
    long bin_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    if (bin_size <= 0 || bin_size % HASH160_LEN != 0) {
        fclose(fin);
        print_error("Invalid BTC.bin size");
        return -1;
    }
    
    uint64_t n = bin_size / HASH160_LEN;
    
    FILE *fout = fopen(IDX_FILE, "wb");
    if (!fout) {
        fclose(fin);
        print_error("Cannot create BTC.idx");
        return -1;
    }
    
    char *buf = (char*)malloc(IO_BUFFER_SIZE);
    if (!buf) {
        fclose(fin);
        fclose(fout);
        print_error("Memory allocation failed");
        return -1;
    }
    setvbuf(fout, buf, _IOFBF, IO_BUFFER_SIZE);
    
    uint8_t hash_buf[HASH160_LEN];
    for (uint64_t i = 0; i < n; i++) {
        if (fread(hash_buf, 1, HASH160_LEN, fin) != HASH160_LEN) {
            free(buf);
            fclose(fin);
            fclose(fout);
            print_error("Read error from BTC.bin");
            return -1;
        }
        
        idx_record_t rec;
        memcpy(rec.hash, hash_buf, HASH160_LEN);
        rec.record_index = i;
        fwrite(&rec, 1, sizeof(idx_record_t), fout);
    }
    
    fclose(fin);
    fclose(fout);
    free(buf);
    
    return 0;
}

static int stage_write_idx_sparse() {
    FILE *fin = fopen(BIN_FILE, "rb");
    if (!fin) {
        print_error("Cannot open BTC.bin for IDX generation");
        return -1;
    }
    
    fseek(fin, 0, SEEK_END);
    long bin_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    if (bin_size <= 0 || bin_size % HASH160_LEN != 0) {
        fclose(fin);
        print_error("Invalid BTC.bin size");
        return -1;
    }
    
    uint64_t n = bin_size / HASH160_LEN;
    uint64_t blocks = (n + IDX_SPARSE_STRIDE - 1) / IDX_SPARSE_STRIDE;
    
    FILE *fout = fopen(IDX_FILE, "wb");
    if (!fout) {
        fclose(fin);
        print_error("Cannot create BTC.idx");
        return -1;
    }
    
    char *buf = (char*)malloc(IO_BUFFER_SIZE);
    if (!buf) {
        fclose(fin);
        fclose(fout);
        print_error("Memory allocation failed");
        return -1;
    }
    setvbuf(fout, buf, _IOFBF, IO_BUFFER_SIZE);
    
    uint8_t hash_buf[HASH160_LEN];
    for (uint64_t b = 0; b < blocks; b++) {
        uint64_t start_rec = b * IDX_SPARSE_STRIDE;
        
        fseek(fin, start_rec * HASH160_LEN, SEEK_SET);
        if (fread(hash_buf, 1, HASH160_LEN, fin) != HASH160_LEN) {
            free(buf);
            fclose(fin);
            fclose(fout);
            print_error("Read error from BTC.bin");
            return -1;
        }
        
        idx_record_sparse_t rec;
        memcpy(rec.hash, hash_buf, HASH160_LEN);
        rec.record_index = (uint32_t)start_rec;
        fwrite(&rec, 1, sizeof(idx_record_sparse_t), fout);
    }
    
    fclose(fin);
    fclose(fout);
    free(buf);
    
    return 0;
}

static int stage_write_xor() {
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
    
    uint64_t n = sz / HASH160_LEN;
    
    uint8_t *map = static_cast<uint8_t*>(mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0));
    if(map == MAP_FAILED) {
        close(fd);
        print_error("mmap failed for BTC.bin");
        return -1;
    }
    
    xorfilter_t xf;
    memset(&xf, 0, sizeof(xf));
    
    int r = xorfilter_build(&xf, map, n, 16);
    if (r != 0) {
        munmap(map, sz);
        close(fd);
        print_error("Xor filter build failed");
        return -1;
    }
    
    FILE *fout = fopen(XOR_FILE, "wb");
    if (!fout) {
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
    
    fwrite(&hdr, 1, sizeof(xor_header_t), fout);
    fwrite(xf.fingerprints, 1, xf.array_length, fout);
    
    fclose(fout);
    xorfilter_free(&xf);
    
    munmap(map, sz);
    close(fd);
    
    return 0;
}

static int verify_outputs(size_t expected_bin_size, size_t expected_idx_size) {
    struct stat st;
    
    if (stat(BIN_FILE, &st) != 0) {
        print_error("BTC.bin missing after generation");
        return -1;
    }
    if ((size_t)st.st_size != expected_bin_size) {
        print_error("BTC.bin size mismatch");
        return -1;
    }
    
    if (stat(IDX_FILE, &st) != 0) {
        print_error("BTC.idx missing after generation");
        return -1;
    }
    if ((size_t)st.st_size != expected_idx_size) {
        print_error("BTC.idx size mismatch");
        return -1;
    }
    
    if (stat(XOR_FILE, &st) != 0) {
        print_error("BTC.xor missing after generation");
        return -1;
    }
    if (st.st_size < (off_t)sizeof(xor_header_t)) {
        print_error("BTC.xor too small");
        return -1;
    }
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./CREATE-BIX <input_hex_file>\n");
        return 1;
    }

    fprintf(stderr, "\n============================================================\n");
    fprintf(stderr, "CREATE-BIX index format selection\n");
    fprintf(stderr, "============================================================\n");
    fprintf(stderr, "Option A: Full Index (28 bytes/entry)\n");
    fprintf(stderr, "Option B: Sparse Index (24 bytes/block)\n");
    fprintf(stderr, "Choice [A/B]: ");
    
    char choice;
    if (scanf(" %c", &choice) != 1) {
        print_error("Invalid input for choice");
        return 1;
    }
    
    bool is_sparse = (choice == 'B' || choice == 'b');
    
    if (stage_read_and_sort_external(argv[1]) != 0) return 1;
    
    FILE *fb = fopen(BIN_FILE, "rb");
    if (!fb) {
        print_error("Cannot verify BTC.bin");
        return 1;
    }
    fseek(fb, 0, SEEK_END);
    long bin_size = ftell(fb);
    fclose(fb);
    
    if (bin_size <= 0 || bin_size % HASH160_LEN != 0) {
        print_error("Invalid BTC.bin state");
        return 1;
    }
    
    uint64_t n = bin_size / HASH160_LEN;
    size_t expected_bin_size = n * HASH160_LEN;
    size_t expected_idx_size = 0;
    
    if (is_sparse) {
        if (stage_write_idx_sparse() != 0) return 1;
        uint64_t blocks = (n + IDX_SPARSE_STRIDE - 1) / IDX_SPARSE_STRIDE;
        expected_idx_size = blocks * IDX_SPARSE_ENTRY_SIZE;
    } else {
        if (stage_write_idx_full() != 0) return 1;
        expected_idx_size = n * IDX_RECORD_SIZE;
    }
    
    if (stage_write_xor() != 0) return 1;
    
    if (verify_outputs(expected_bin_size, expected_idx_size) != 0) return 1;
    
    fprintf(stderr, "[DEBUG] BTC.bin: %llu hashes, %ld bytes\n", (unsigned long long)n, bin_size);
    fprintf(stderr, "[DEBUG] BTC.idx: %llu entries, %zu bytes, format %s\n", 
            is_sparse ? (n + IDX_SPARSE_STRIDE - 1) / IDX_SPARSE_STRIDE : n, 
            expected_idx_size, 
            is_sparse ? "SPARSE" : "FULL");
            
    fb = fopen(BIN_FILE, "rb");
    if (fb) {
        uint8_t first_hash[HASH160_LEN];
        if (fread(first_hash, 1, HASH160_LEN, fb) == HASH160_LEN) {
            char hex_buf[41];
            for(int i=0;i<20;i++) sprintf(hex_buf+i*2,"%02x",first_hash[i]);
            hex_buf[40]=0;
            fprintf(stderr, "[DEBUG] First hash in BTC.bin: %s\n", hex_buf);
        }
        fclose(fb);
    }
    
    fprintf(stderr, "[OK] Creation completed successfully.\n");
    return 0;
}
