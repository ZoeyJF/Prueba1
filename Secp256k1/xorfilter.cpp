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

#include "xorfilter.h"
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdio>

static inline uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

static inline uint64_t hash_key(const uint8_t *key, uint64_t len, uint64_t seed) {
    uint64_t h = seed;
    for (uint64_t i = 0; i < len; i++) {
        h = splitmix64(h ^ (uint64_t)key[i]);
    }
    return splitmix64(h ^ (uint64_t)len);
}

#define BLOOM_K 10

int xorfilter_build(xorfilter_t *f, const uint8_t *keys, uint64_t n, uint8_t bits) {
    if (!f || !keys || n == 0) return -1;
    (void)bits;

    uint64_t m_bits = (uint64_t)n * 15ULL + 128ULL;
    m_bits = (m_bits + 63ULL) & ~63ULL;
    uint64_t m_bytes = m_bits / 8ULL;

    uint8_t *filter = (uint8_t*)calloc(m_bytes, 1);
    if (!filter) return -1;

    uint64_t seed = 0x9E3779B97F4A7C15ULL;

    for (uint64_t i = 0; i < n; i++) {
        const uint8_t *k = keys + i * 20;
        uint64_t h1 = hash_key(k, 20, seed);
        uint64_t h2 = hash_key(k, 20, seed ^ 0xDEADBEEFCAFEBABEULL);
        if (h2 == 0) h2 = 1;
        for (int j = 0; j < BLOOM_K; j++) {
            uint64_t pos = (h1 + (uint64_t)j * h2) % m_bits;
            filter[pos >> 3] |= (uint8_t)(1u << (pos & 7));
        }
    }

    f->fingerprints = filter;
    f->array_length = m_bytes;
    f->block_length = m_bits;
    f->fingerprint_bits = 8;
    f->seed = seed;
    f->entry_count = n;
    return 0;
}

int xorfilter_contains(const xorfilter_t *f, const uint8_t *key, uint64_t key_len) {
    if (!f || !f->fingerprints) return 0;
    uint64_t m_bits = (uint64_t)f->array_length * 8ULL;
    uint64_t seed = f->seed;
    const uint8_t *filter = f->fingerprints;
    uint64_t h1 = hash_key(key, key_len, seed);
    uint64_t h2 = hash_key(key, key_len, seed ^ 0xDEADBEEFCAFEBABEULL);
    if (h2 == 0) h2 = 1;
    for (int j = 0; j < BLOOM_K; j++) {
        uint64_t pos = (h1 + (uint64_t)j * h2) % m_bits;
        if ((filter[pos >> 3] & (uint8_t)(1u << (pos & 7))) == 0) return 0;
    }
    return 1;
}

void xorfilter_free(xorfilter_t *f) {
    if (!f) return;
    free(f->fingerprints);
    f->fingerprints = nullptr;
    f->array_length = 0;
    f->block_length = 0;
    f->entry_count = 0;
}

