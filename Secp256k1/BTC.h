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

#ifndef BTC_H
#define BTC_H

#include <cstdint>
#include <cstdio>
#include <pthread.h>
#include <atomic>
#include <cstddef>

#define HASH160_LEN 20
#define IDX_RECORD_SIZE 28
#define IDX_SPARSE_ENTRY_SIZE 24
#define IDX_SPARSE_STRIDE 64

#define IDX_MAGIC 0x49445831u   // "IDX1"
#define IDX_FORMAT_FULL 1u
#define IDX_FORMAT_SPARSE 2u

#define XOR_MAGIC 0x584F5246u   // "XORF"
#define XOR_VERSION 2u

#define FOUND_FILE "FOUND.txt"
#define BIN_FILE "BTC.bin"
#define IDX_FILE "BTC.idx"
#define XOR_FILE "BTC.xor"
#define HEX_LINE_LEN 40

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;         // IDX_MAGIC (0x49445831)
    uint32_t format_type;   // IDX_FORMAT_FULL (1) or IDX_FORMAT_SPARSE (2)
    uint64_t total_hashes;  // Total number of 20-byte hashes in BTC.bin
    uint64_t record_count;  // Total index entries in BTC.idx
    uint32_t stride;        // Stride for sparse index (e.g. 64), 1 for full
    uint32_t entry_size;    // 28 for full, 24 for sparse
} idx_header_t;

typedef struct {
    uint8_t hash[HASH160_LEN];
    uint64_t record_index;
} idx_record_t;

typedef struct {
    uint8_t hash[HASH160_LEN];
    uint32_t record_index;
} idx_record_sparse_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t seed;
    uint32_t block_length;
    uint8_t fingerprint_bits;
    uint64_t entry_count;
    uint64_t array_length;
} xor_header_t;

#pragma pack(pop)

typedef enum {
    SEARCH_MODE_SEQ = 0,
    SEARCH_MODE_RND = 1
} search_mode_t;

typedef struct {
    uint8_t *fingerprints;
    uint64_t array_length;
    uint64_t block_length;
    uint8_t fingerprint_bits;
    uint64_t seed;
    uint64_t entry_count;
    bool is_mmap;
    size_t mmap_size;
} xor_table_t;

typedef struct {
    void *records;          // Pointer to idx_record_t or idx_record_sparse_t (after header if present)
    uint64_t count;
    uint32_t format_type;   // IDX_FORMAT_FULL or IDX_FORMAT_SPARSE
    uint32_t stride;        // e.g. 64 or 1
    bool has_header;
    bool is_mmap;
    size_t mmap_size;
} idx_table_t;

typedef struct {
    search_mode_t mode;
    int range_bits;
    int subranges;
    int threads;
    int seconds_slot;
    int seconds_pure_switch;
    int pure_cycles_before_range_change;
    uint64_t range_start[4];
    uint64_t range_end[4];
} config_t;

int btc_load_idx(const char *idx_path, idx_table_t *table);
void btc_free_idx(idx_table_t *table);
int btc_load_xor(const char *xor_path, xor_table_t *table);
void btc_free_xor(xor_table_t *table);
bool btc_xor_contains(const xor_table_t *table, const uint8_t *hash, int len);
int btc_binary_search_idx(const idx_table_t *table, const uint8_t *hash, uint64_t *record_index_out);
int btc_confirm_bin(int bin_fd, uint64_t record_index, const uint8_t *hash);
int btc_write_found(const char *priv_hex, const char *hash160_hex, int range_bits, int subrange_id, const char *timestamp_utc);
int btc_detect_cores(int *cores, int *big_cluster, int *little_cluster);
int btc_get_big_core_id(int index);
int btc_pin_thread(int core_id);
int btc_run_engine(config_t *cfg);

#endif
