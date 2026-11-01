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

#include "BTC.h"
#include "xorfilter.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

int btc_load_idx(const char *idx_path, idx_table_t *table) {
    FILE *f = fopen(idx_path, "rb");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size <= 0 || (size % IDX_RECORD_SIZE != 0 && size % IDX_SPARSE_ENTRY_SIZE != 0)) {
        fclose(f);
        return -1;
    }
    
    table->records = (idx_record_t*)malloc(size);
    if (!table->records) {
        fclose(f);
        return -1;
    }
    
    if (fread(table->records, 1, size, f) != (size_t)size) {
        free(table->records);
        table->records = nullptr;
        fclose(f);
        return -1;
    }
    
    fclose(f);
    
    if (size % IDX_RECORD_SIZE == 0) {
        table->count = size / IDX_RECORD_SIZE;
    } else {
        table->count = size / IDX_SPARSE_ENTRY_SIZE;
    }
    
    table->is_mmap = false;
    table->mmap_size = 0;
    
    return 0;
}

void btc_free_idx(idx_table_t *table) {
    if (table) {
        if (table->is_mmap) {
            if (table->records) munmap(table->records, table->mmap_size);
        } else {
            if (table->records) free(table->records);
        }
        table->records = nullptr;
        table->count = 0;
        table->is_mmap = false;
        table->mmap_size = 0;
    }
}

int btc_load_xor(const char *xor_path, xor_table_t *table) {
    FILE *f = fopen(xor_path, "rb");
    if (!f) return -1;
    
    xor_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f);
        return -1;
    }
    
    if (hdr.magic != XOR_MAGIC || hdr.version != XOR_VERSION) {
        fclose(f);
        return -1;
    }
    
    uint64_t fp_bytes = hdr.array_length;
    
    table->fingerprints = (uint8_t*)malloc(fp_bytes);
    if (!table->fingerprints) {
        fclose(f);
        return -1;
    }
    
    if (fread(table->fingerprints, 1, fp_bytes, f) != fp_bytes) {
        free(table->fingerprints);
        table->fingerprints = nullptr;
        fclose(f);
        return -1;
    }
    
    fclose(f);
    
    table->seed = hdr.seed;
    table->block_length = hdr.block_length;
    table->fingerprint_bits = hdr.fingerprint_bits;
    table->entry_count = hdr.entry_count;
    table->array_length = fp_bytes;
    table->is_mmap = false;
    table->mmap_size = 0;
    
    return 0;
}

void btc_free_xor(xor_table_t *table) {
    if (table) {
        if (table->is_mmap) {
            if (table->fingerprints) munmap(table->fingerprints, table->mmap_size);
        } else {
            if (table->fingerprints) free(table->fingerprints);
        }
        table->fingerprints = nullptr;
        table->array_length = 0;
        table->block_length = 0;
        table->fingerprint_bits = 0;
        table->seed = 0;
        table->entry_count = 0;
        table->is_mmap = false;
        table->mmap_size = 0;
    }
}

bool btc_xor_contains(const xor_table_t *table, const uint8_t *key, int len) {
    if (!table || !table->fingerprints || len != HASH160_LEN) return false;
    
    xorfilter_t xf;
    memset(&xf, 0, sizeof(xf));
    xf.fingerprints = table->fingerprints;
    xf.array_length = (uint32_t)table->array_length;
    xf.block_length = (uint32_t)table->block_length;
    xf.fingerprint_bits = table->fingerprint_bits;
    xf.seed = table->seed;
    xf.entry_count = table->entry_count;
    
    return xorfilter_contains(&xf, key, (uint64_t)len) != 0;
}

int btc_binary_search_idx(const idx_table_t *table, const uint8_t *hash, uint64_t *record_index_out) {
    if (!table || !table->records || table->count == 0) return -1;
    
    uint64_t low = 0;
    uint64_t high = table->count - 1;
    
    while (low <= high) {
        uint64_t mid = low + (high - low) / 2;
        int cmp = memcmp(table->records[mid].hash, hash, HASH160_LEN);
        
        if (cmp == 0) {
            *record_index_out = table->records[mid].record_index;
            return 0;
        } else if (cmp < 0) {
            if (mid == UINT64_MAX) break;
            low = mid + 1;
        } else {
            if (mid == 0) break;
            high = mid - 1;
        }
    }
    
    return -1;
}

int btc_confirm_bin(FILE *bin_file, uint64_t record_index, const uint8_t *hash) {
    if (!bin_file || !hash) return -1;
    
    uint8_t stored_hash[HASH160_LEN];
    fseek(bin_file, record_index * HASH160_LEN, SEEK_SET);
    
    if (fread(stored_hash, 1, HASH160_LEN, bin_file) != HASH160_LEN) {
        return -1;
    }
    
    if (memcmp(stored_hash, hash, HASH160_LEN) == 0) {
        return 0;
    }
    
    return -1;
}

int btc_write_found(const char *priv_hex, const char *hash160_hex, int range_bits, int subrange_id, const char *timestamp_utc) {
    FILE *f = fopen(FOUND_FILE, "a");
    if (!f) return -1;
    
    fprintf(f, "%s|%s|%d|%d|%s\n", priv_hex, hash160_hex, range_bits, subrange_id, timestamp_utc);
    fclose(f);
    
    return 0;
}

int btc_detect_cores(int *total, int *big, int *little) {
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    *total = (int)cores;
    *big = (int)(cores / 2);
    if (*big < 1) *big = 1;
    *little = *total - *big;
    return 0;
}

int btc_pin_thread(int cpu_id) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu_id, &set);
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

int btc_run_engine(config_t *cfg) {
    if (!cfg) return -1;
    return 0;
}
