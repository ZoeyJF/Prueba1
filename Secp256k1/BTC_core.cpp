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
#include <vector>
#include <algorithm>

static std::vector<int> g_big_cores_list;

int btc_load_idx(const char *idx_path, idx_table_t *table) {
    if (!table) return -1;
    memset(table, 0, sizeof(idx_table_t));

    int fd = open(idx_path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    uint64_t size = st.st_size;

    idx_header_t hdr;
    bool has_header = false;
    uint64_t data_offset = 0;
    uint32_t format_type = IDX_FORMAT_FULL;
    uint32_t stride = 1;
    uint64_t count = 0;

    if (size >= sizeof(idx_header_t)) {
        if (pread64(fd, &hdr, sizeof(hdr), 0) == sizeof(hdr)) {
            if (hdr.magic == IDX_MAGIC) {
                has_header = true;
                data_offset = sizeof(idx_header_t);
                format_type = hdr.format_type;
                stride = hdr.stride ? hdr.stride : (format_type == IDX_FORMAT_SPARSE ? IDX_SPARSE_STRIDE : 1);
                count = hdr.record_count;
            }
        }
    }

    if (!has_header) {
        if (size % IDX_RECORD_SIZE == 0 && (size % IDX_SPARSE_ENTRY_SIZE != 0 || size == 0)) {
            format_type = IDX_FORMAT_FULL;
            stride = 1;
            count = size / IDX_RECORD_SIZE;
        } else if (size % IDX_SPARSE_ENTRY_SIZE == 0) {
            format_type = IDX_FORMAT_SPARSE;
            stride = IDX_SPARSE_STRIDE;
            count = size / IDX_SPARSE_ENTRY_SIZE;
        } else if (size % IDX_RECORD_SIZE == 0) {
            format_type = IDX_FORMAT_FULL;
            stride = 1;
            count = size / IDX_RECORD_SIZE;
        } else {
            close(fd);
            return -1;
        }
    }

    uint64_t payload_bytes = size - data_offset;
    void *records = malloc(payload_bytes > 0 ? payload_bytes : 1);
    if (!records) {
        close(fd);
        return -1;
    }

    if (payload_bytes > 0) {
        if ((uint64_t)pread64(fd, records, payload_bytes, data_offset) != payload_bytes) {
            free(records);
            close(fd);
            return -1;
        }
    }

    close(fd);

    table->records = records;
    table->count = count;
    table->format_type = format_type;
    table->stride = stride;
    table->has_header = has_header;
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
    if (!table) return -1;
    memset(table, 0, sizeof(xor_table_t));

    int fd = open(xor_path, O_RDONLY);
    if (fd < 0) return -1;

    xor_header_t hdr;
    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        close(fd);
        return -1;
    }

    if (hdr.magic != XOR_MAGIC || hdr.version != XOR_VERSION) {
        close(fd);
        return -1;
    }

    uint64_t fp_bytes = hdr.array_length;

    table->fingerprints = (uint8_t*)malloc(fp_bytes > 0 ? fp_bytes : 1);
    if (!table->fingerprints) {
        close(fd);
        return -1;
    }

    if (fp_bytes > 0 && (uint64_t)read(fd, table->fingerprints, fp_bytes) != fp_bytes) {
        free(table->fingerprints);
        table->fingerprints = nullptr;
        close(fd);
        return -1;
    }

    close(fd);

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

    if (table->format_type == IDX_FORMAT_FULL) {
        const idx_record_t *recs = (const idx_record_t*)table->records;
        uint64_t low = 0;
        uint64_t high = table->count - 1;

        while (low <= high) {
            uint64_t mid = low + (high - low) / 2;
            int cmp = memcmp(recs[mid].hash, hash, HASH160_LEN);

            if (cmp == 0) {
                *record_index_out = recs[mid].record_index;
                return 0;
            } else if (cmp < 0) {
                if (mid == UINT64_MAX) break;
                low = mid + 1;
            } else {
                if (mid == 0) break;
                high = mid - 1;
            }
        }
    } else {
        // Sparse index binary search for block
        const idx_record_sparse_t *recs = (const idx_record_sparse_t*)table->records;
        uint64_t low = 0;
        uint64_t high = table->count;
        uint64_t best_block = UINT64_MAX;

        while (low < high) {
            uint64_t mid = low + (high - low) / 2;
            int cmp = memcmp(recs[mid].hash, hash, HASH160_LEN);
            if (cmp <= 0) {
                best_block = mid;
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        if (best_block != UINT64_MAX) {
            *record_index_out = recs[best_block].record_index;
            return 0;
        }
    }

    return -1;
}

int btc_confirm_bin(int bin_fd, uint64_t record_index, const uint8_t *hash) {
    if (bin_fd < 0 || !hash) return -1;

    uint8_t stored_hash[HASH160_LEN];
    off64_t offset = (off64_t)record_index * (off64_t)HASH160_LEN;

    if (pread64(bin_fd, stored_hash, HASH160_LEN, offset) != HASH160_LEN) {
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

struct CoreFreq {
    int core_id;
    uint64_t max_freq;
};

int btc_detect_cores(int *total, int *big, int *little) {
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    *total = (int)cores;

    std::vector<CoreFreq> core_freqs;
    core_freqs.reserve(cores);

    bool found_freqs = false;
    for (int i = 0; i < cores; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", i);
        FILE *f = fopen(path, "r");
        uint64_t freq = 0;
        if (f) {
            if (fscanf(f, "%lu", &freq) == 1 && freq > 0) {
                found_freqs = true;
            }
            fclose(f);
        }
        core_freqs.push_back({i, freq});
    }

    g_big_cores_list.clear();

    if (found_freqs) {
        // Sort descending by max frequency
        std::sort(core_freqs.begin(), core_freqs.end(), [](const CoreFreq &a, const CoreFreq &b) {
            if (a.max_freq != b.max_freq) return a.max_freq > b.max_freq;
            return a.core_id < b.core_id;
        });

        uint64_t top_freq = core_freqs[0].max_freq;
        // Big cores are defined as cores within 15% of maximum frequency or at least top half
        int big_count = 0;
        for (const auto &cf : core_freqs) {
            if (cf.max_freq >= (top_freq * 85 / 100) && cf.max_freq > 0) {
                g_big_cores_list.push_back(cf.core_id);
                big_count++;
            }
        }
        if (big_count < 1) {
            big_count = (int)(cores / 2);
            if (big_count < 1) big_count = 1;
            for (int i = 0; i < big_count; i++) g_big_cores_list.push_back(core_freqs[i].core_id);
        }
        *big = big_count;
        *little = *total - *big;
    } else {
        // Fallback when sysfs cpufreq is not accessible
        int big_count = (int)(cores / 2);
        if (big_count < 1) big_count = (int)cores;
        for (int i = 0; i < (int)cores; i++) {
            g_big_cores_list.push_back(i);
        }
        *big = big_count;
        *little = *total - *big;
    }

    return 0;
}

int btc_get_big_core_id(int index) {
    if (g_big_cores_list.empty()) return index;
    return g_big_cores_list[index % g_big_cores_list.size()];
}

int btc_pin_thread(int core_id) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(core_id, &set);
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}

int btc_run_engine(config_t *cfg) {
    if (!cfg) return -1;
    return 0;
}
