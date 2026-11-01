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

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <ctime>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <csignal>
#include <unistd.h>
#include <strings.h>
#include <random>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sstream>
#include <cmath>

#include "Secp256k1/Secp256k1.h"
#include "Secp256k1/BTC.h"
#include "Secp256k1/xorfilter.h"
#include "Secp256k1/AddressHelper.h"
#include "Secp256k1/rmd160.h"
#include "Secp256k1/sha256.h"
#include "Secp256k1/ripemd160.h"
#include "Secp256k1/sha3.h"
#include "Secp256k1/keccak.h"
#include "Secp256k1/IntGroup.h"
#include "Secp256k1/Point.h"
#include "Secp256k1/Int.h"
#include "Secp256k1/util.h"
#include "Secp256k1/Random.h"

enum IdxFormat {
    IDX_UNKNOWN = 0,
    IDX_FULL = 1,
    IDX_SPARSE = 2
};

struct FoundLogEntry {
    std::string message;
    int remaining_cycles;
};

static std::atomic<bool> g_stop{false};
static std::atomic<unsigned long long> g_total_keys{0};
static std::atomic<unsigned long long> g_xor_hits{0};
static std::atomic<unsigned long long> g_found_count{0};
static std::atomic<int> g_threads_done{0};

static std::mutex g_io_mutex;
static std::mutex g_found_mutex;
static std::vector<FoundLogEntry> g_found_logs;
static int g_display_lines = 0;
static std::unique_ptr<std::atomic<unsigned long long>[]> g_thread_counters;

static Secp256K1 *g_secp = nullptr;
static idx_table_t g_idx;
static xor_table_t g_xorf;
static FILE *g_bin_file = nullptr;
static uint8_t *g_bin_map = nullptr;
static size_t g_bin_size = 0;
static int g_mem_mode_bin = 1;
static int g_mem_mode_idx = 1;
static int g_mem_mode_xor = 1;
static IdxFormat g_idx_format = IDX_UNKNOWN;

static int g_range_bits = 71;
static bool g_random_mode = false;
static int g_num_threads = 0;
static int g_cpu_cores = 1;
static int g_big_cores = 0;
static bool g_all_ranges = false;

static uint8_t g_start_key[32];
static uint8_t g_end_key[32];
static Point g_inc_point;

static const char *ORDER_HEX = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
static const char *BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char *BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int BATCH_SIZE = 256;
static const int BATCH_STEPS = BATCH_SIZE - 1;

static void sig_handler(int) {
    g_stop.store(true, std::memory_order_relaxed);
}

static void print_usage(const char *prog_name) {
    printf("BTCMobile Engine Usage:\n");
    printf("  %s -R [1-256] [-S|-Random] [-t threads]\n\n", prog_name);
    printf("Options:\n");
    printf("  -R <bits|all>   Range in bits (1-256) or 'all' for full scan\n");
    printf("  -S              Sequential search mode (default)\n");
    printf("  -Random         Random bidirectional position jump mode\n");
    printf("  -t <threads>    Number of worker threads (capped to Big cores)\n");
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void hex_to_bytes(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((hex_val(h[i * 2]) << 4) | hex_val(h[i * 2 + 1]));
    }
}

static void zero_256(uint8_t *a) { memset(a, 0, 32); }
static void copy_256(uint8_t *d, const uint8_t *s) { memcpy(d, s, 32); }
static int cmp_256(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 32); }

static void set_power_of_two(uint8_t *a, int bits) {
    zero_256(a);
    if (bits <= 0) { a[31] = 1; return; }
    if (bits >= 256) return;
    int byte_idx = 31 - (bits / 8);
    int bit_idx = bits % 8;
    a[byte_idx] |= (uint8_t)(1u << bit_idx);
}

static void set_order_value(uint8_t *a) {
    hex_to_bytes(ORDER_HEX, a, 32);
}

static void initialize_range(int bits) {
    if (bits <= 0) bits = 1;
    if (bits > 256) bits = 256;
    
    if (bits == 256) {
        set_power_of_two(g_start_key, 255);
        set_order_value(g_end_key);
    } else {
        set_power_of_two(g_start_key, bits - 1);
        set_power_of_two(g_end_key, bits);
    }
}

static void add_small_uint(uint8_t *a, uint64_t v) {
    uint64_t carry = v;
    for (int i = 31; i >= 0 && carry; i--) {
        uint64_t sum = (uint64_t)a[i] + carry;
        a[i] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

static void sub_small_uint(uint8_t *a, uint64_t v) {
    uint64_t borrow = v;
    for (int i = 31; i >= 0 && borrow; i--) {
        uint64_t val = a[i];
        if (val >= (borrow & 0xFF)) {
            a[i] = (uint8_t)(val - (borrow & 0xFF));
            borrow >>= 8;
        } else {
            a[i] = (uint8_t)((val + 256) - (borrow & 0xFF));
            borrow = (borrow >> 8) + 1;
        }
    }
}

static void generate_random_key(uint8_t *priv_bytes, std::mt19937_64 &rng) {
    if (g_range_bits < 256) {
        int offset_bits = g_range_bits - 1;
        uint8_t off[32];
        zero_256(off);
        if (offset_bits > 0) {
            int bytes_needed = (offset_bits + 7) / 8;
            for (int i = 0; i < bytes_needed; i++) {
                off[31 - i] = (uint8_t)(rng() & 0xFF);
            }
            int rem = offset_bits % 8;
            if (rem) off[31 - bytes_needed + 1] &= (uint8_t)((1 << rem) - 1);
        }
        uint8_t temp[32];
        copy_256(temp, g_start_key);
        uint16_t carry = 0;
        for (int i = 31; i >= 0; i--) {
            uint16_t sum = (uint16_t)temp[i] + (uint16_t)off[i] + carry;
            temp[i] = (uint8_t)sum;
            carry = sum >> 8;
        }
        copy_256(priv_bytes, temp);
    } else {
        do {
            for (int i = 0; i < 32; i++) priv_bytes[i] = (uint8_t)(rng() & 0xFF);
        } while (cmp_256(priv_bytes, g_start_key) < 0 || cmp_256(priv_bytes, g_end_key) >= 0);
    }
}

static long double u256_to_ld(const uint8_t *a) {
    long double val = 0.0L;
    for (int i = 0; i < 32; i++) {
        val = val * 256.0L + (long double)a[i];
    }
    return val;
}

static std::string format_comma(unsigned long long x) {
    std::string s = std::to_string(x);
    std::string res;
    int cnt = 0;
    for (auto it = s.rbegin(); it != s.rend(); ++it) {
        res.push_back(*it);
        if (++cnt % 3 == 0 && it + 1 != s.rend()) res.push_back(',');
    }
    std::reverse(res.begin(), res.end());
    return res;
}

static void utc_timestamp(char *buf, size_t len) {
    time_t t = time(nullptr);
    struct tm tm_info;
    gmtime_r(&t, &tm_info);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S UTC", &tm_info);
}

static void sha256_double(const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t temp[32];
    sha256((unsigned char*)in, (unsigned int)len, temp);
    sha256(temp, 32, out);
}

static void base58_encode_raw(const uint8_t *in, size_t len, char *out, size_t outsize) {
    size_t zeros = 0;
    while (zeros < len && in[zeros] == 0) zeros++;
    size_t raw_len = len - zeros;
    size_t size = raw_len * 138 / 100 + 1;
    uint8_t buf[128];
    char tmp[128];
    size_t psz = 0;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, in + zeros, raw_len);
    while (true) {
        uint32_t carry = 0;
        bool nonzero = false;
        for (size_t i = 0; i < size; i++) {
            uint32_t acc = carry * 256u + buf[i];
            buf[i] = (uint8_t)(acc / 58u);
            carry = acc % 58u;
            if (buf[i]) nonzero = true;
        }
        tmp[psz++] = BASE58_ALPHABET[carry];
        if (!nonzero) break;
    }
    size_t k = 0;
    for (size_t i = 0; i < zeros && k + 1 < outsize; i++) out[k++] = '1';
    for (size_t i = psz; i > 0 && k + 1 < outsize; i--) out[k++] = tmp[i - 1];
    out[k] = 0;
}

static void generate_base58_check(const uint8_t *h160, uint8_t prefix, char *out, size_t outsize) {
    uint8_t payload[21];
    uint8_t full[25];
    uint8_t checksum[32];
    payload[0] = prefix;
    memcpy(payload + 1, h160, 20);
    sha256_double(payload, 21, checksum);
    memcpy(full, payload, 21);
    memcpy(full + 21, checksum, 4);
    base58_encode_raw(full, 25, out, outsize);
}

static uint64_t bech32_polymod_step(uint64_t pre, uint8_t v) {
    uint64_t b = pre >> 25;
    pre = ((pre & 0x1ffffffULL) << 5) ^ v;
    if (b & 1) pre ^= 0x3b6a57b2ULL;
    if (b & 2) pre ^= 0x26508e6dULL;
    if (b & 4) pre ^= 0x1ea119faULL;
    if (b & 8) pre ^= 0x3d4233ddULL;
    if (b & 16) pre ^= 0x2a1462b3ULL;
    return pre & 0x3fffffffULL;
}

static void generate_bech32_p2wpkh(const uint8_t *h160, char *out, size_t outsize) {
    uint8_t data5[32];
    size_t data5len = 0;
    uint8_t values[64];
    size_t vlen = 0;
    uint64_t chk = 1;
    size_t k = 0;

    uint32_t acc = 0;
    int bits = 0;
    for (int i = 0; i < 20; i++) {
        acc = (acc << 8) | h160[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            data5[data5len++] = (uint8_t)((acc >> bits) & 31);
        }
    }
    if (bits > 0) {
        data5[data5len++] = (uint8_t)((acc << (5 - bits)) & 31);
    }

    values[0] = 0;
    memcpy(values + 1, data5, data5len);
    vlen = data5len + 1;

    for (const char *p = "bc"; *p; p++) chk = bech32_polymod_step(chk, (uint8_t)(*p) >> 5);
    chk = bech32_polymod_step(chk, 0);
    for (const char *p = "bc"; *p; p++) chk = bech32_polymod_step(chk, (uint8_t)(*p) & 31);
    for (size_t i = 0; i < vlen; i++) chk = bech32_polymod_step(chk, values[i]);
    for (int i = 0; i < 6; i++) chk = bech32_polymod_step(chk, 0);
    chk ^= 1;
    for (int i = 0; i < 5; i++) values[vlen + i] = (uint8_t)((chk >> (5 * (4 - i))) & 31);

    for (const char *p = "bc"; *p && k + 1 < outsize; p++) out[k++] = *p;
    if (k + 1 < outsize) out[k++] = '1';
    for (size_t i = 0; i < vlen + 5 && k + 1 < outsize; i++) out[k++] = BECH32_CHARSET[values[i]];
    out[k] = 0;
}

static void generate_eth_address(const uint8_t *pub_uncompressed_xy, char *out, size_t outsize) {
    SHA3_256_CTX ctx;
    uint8_t hash[32];
    KECCAK_256_Init(&ctx);
    KECCAK_256_Update(&ctx, pub_uncompressed_xy, 64);
    KECCAK_256_Final(hash, &ctx);
    
    if (outsize < 43) { out[0] = 0; return; }
    size_t pos = 0;
    out[pos++] = '0';
    out[pos++] = 'x';
    for (int i = 12; i < 32; i++) {
        sprintf(out + pos, "%02x", hash[i]);
        pos += 2;
    }
    out[pos] = 0;
}

static void bytes_to_int_obj(const uint8_t *bytes, Int &obj) {
    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i*2, "%02x", bytes[i]);
    obj.SetBase16(hex);
}

static int ask_storage_choice(const char *filename) {
    printf("[INFO] Select storage for %s : [1] RAM  [2] Disk MMAP\n", filename);
    printf("Choice [1-2]: ");
    int choice = 0;
    if (scanf("%d", &choice) != 1) choice = 1;
    if (choice < 1 || choice > 2) choice = 1;
    return choice;
}

static void init_memory_loading() {
    g_mem_mode_bin = ask_storage_choice(BIN_FILE);
    g_mem_mode_idx = ask_storage_choice(IDX_FILE);
    g_mem_mode_xor = ask_storage_choice(XOR_FILE);
    
    printf("\n[INFO] Storage modes selected:\n");
    printf("[INFO] BTC.bin : %s\n", g_mem_mode_bin == 1 ? "RAM" : "MMAP");
    printf("[INFO] BTC.idx : %s\n", g_mem_mode_idx == 1 ? "RAM" : "MMAP");
    printf("[INFO] BTC.xor : %s\n", g_mem_mode_xor == 1 ? "RAM" : "MMAP");
}

static int load_database_files() {
    struct stat st;
    if (stat(IDX_FILE, &st) != 0) {
        fprintf(stderr, "[ERROR] Cannot find %s\n", IDX_FILE);
        return -1;
    }
    
    size_t size_idx = st.st_size;
    bool div_28 = (size_idx % 28 == 0);
    bool div_24 = (size_idx % 24 == 0);
    
    if (div_28 && !div_24) {
        g_idx_format = IDX_FULL;
    } else if (div_24 && !div_28) {
        g_idx_format = IDX_SPARSE;
    } else if (div_28 && div_24) {
        g_idx_format = IDX_FULL;
        fprintf(stderr, "[WARN] Formato ambiguo, asumiendo FULL\n");
    } else {
        fprintf(stderr, "[ERROR] BTC.idx tiene tamaño inválido: %zu\n", size_idx);
        return -1;
    }

    if (g_mem_mode_idx == 1) {
        if (size_idx > 2147483648ULL) {
            fprintf(stderr, "[WARN] BTC.idx es grande (%zu bytes). Se recomienda usar MMAP.\n", size_idx);
        }
        if (btc_load_idx(IDX_FILE, &g_idx) != 0) {
             fprintf(stderr, "[WARN] Cannot load %s into RAM. Falling back to MMAP...\n", IDX_FILE);
             g_mem_mode_idx = 2;
        }
    }

    if (g_mem_mode_idx == 2) {
        int fd = open(IDX_FILE, O_RDONLY);
        if (fd < 0) {
             fprintf(stderr, "[ERROR] Cannot open %s for mmap\n", IDX_FILE);
             return -1;
        }
        g_idx.records = (idx_record_t*)mmap(NULL, size_idx, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (g_idx.records == MAP_FAILED) {
             fprintf(stderr, "[ERROR] mmap failed for IDX\n");
             return -1;
        }
        g_idx.count = size_idx / (g_idx_format == IDX_FULL ? 28 : 24);
        g_idx.is_mmap = true;
        g_idx.mmap_size = size_idx;
    }

    if (g_mem_mode_xor == 1) {
        if (btc_load_xor(XOR_FILE, &g_xorf) != 0) {
            fprintf(stderr, "[WARN] Cannot load %s into RAM. Falling back to MMAP...\n", XOR_FILE);
            g_mem_mode_xor = 2;
        }
    }

    if (g_mem_mode_xor == 2) {
        struct stat xst;
        if (stat(XOR_FILE, &xst) != 0) {
            fprintf(stderr, "[ERROR] Cannot find %s\n", XOR_FILE);
            btc_free_idx(&g_idx);
            return -1;
        }
        int fd = open(XOR_FILE, O_RDONLY);
        if (fd < 0) {
             fprintf(stderr, "[ERROR] Cannot open %s for mmap\n", XOR_FILE);
             btc_free_idx(&g_idx);
             return -1;
        }
        xor_header_t hdr;
        if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
            close(fd);
            fprintf(stderr, "[ERROR] Failed to read XOR header\n");
            btc_free_idx(&g_idx);
            return -1;
        }
        
        uint64_t fp_bytes = hdr.array_length;
        size_t total_size = sizeof(xor_header_t) + fp_bytes;
        
        uint8_t *full_map = (uint8_t*)mmap(NULL, total_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (full_map == MAP_FAILED) {
             fprintf(stderr, "[ERROR] mmap failed for XOR\n");
             btc_free_idx(&g_idx);
             return -1;
        }
        
        g_xorf.fingerprints = full_map + sizeof(xor_header_t);
        g_xorf.seed = hdr.seed;
        g_xorf.block_length = hdr.block_length;
        g_xorf.fingerprint_bits = hdr.fingerprint_bits;
        g_xorf.entry_count = hdr.entry_count;
        g_xorf.array_length = fp_bytes;
        g_xorf.is_mmap = true;
        g_xorf.mmap_size = total_size;
    }

    if (g_mem_mode_bin == 1) {
        g_bin_file = fopen(BIN_FILE, "rb");
        if (!g_bin_file) {
            fprintf(stderr, "[ERROR] Cannot open %s\n", BIN_FILE);
            btc_free_xor(&g_xorf);
            btc_free_idx(&g_idx);
            return -1;
        }
        
        fseek(g_bin_file, 0, SEEK_END);
        g_bin_size = ftell(g_bin_file);
        fseek(g_bin_file, 0, SEEK_SET);
    } else {
        int fd = open(BIN_FILE, O_RDONLY);
        if (fd < 0) {
             fprintf(stderr, "[ERROR] Cannot open %s for mmap\n", BIN_FILE);
             btc_free_xor(&g_xorf);
             btc_free_idx(&g_idx);
             return -1;
        }
        struct stat bst;
        fstat(fd, &bst);
        g_bin_size = bst.st_size;
        g_bin_map = (uint8_t*)mmap(NULL, g_bin_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (g_bin_map == MAP_FAILED) {
             fprintf(stderr, "[ERROR] mmap failed for BIN\n");
             btc_free_xor(&g_xorf);
             btc_free_idx(&g_idx);
             return -1;
        }
    }
    
    if (g_idx.count == 0) {
         fprintf(stderr, "[ERROR] Empty index\n");
         return -1;
    }
    
    uint8_t test_hash[HASH160_LEN];
    uint64_t test_rec_idx = 0;
    
    if (g_idx_format == IDX_FULL) {
        memcpy(test_hash, g_idx.records[0].hash, HASH160_LEN);
        test_rec_idx = g_idx.records[0].record_index;
    } else {
        idx_record_sparse_t *sparse_recs = (idx_record_sparse_t*)g_idx.records;
        memcpy(test_hash, sparse_recs[0].hash, HASH160_LEN);
        test_rec_idx = sparse_recs[0].record_index;
    }
    
    uint8_t stored_hash[HASH160_LEN];
    bool confirmed = false;
    
    if (g_mem_mode_bin == 2) {
        if (test_rec_idx * HASH160_LEN < g_bin_size) {
            memcpy(stored_hash, g_bin_map + (test_rec_idx * HASH160_LEN), HASH160_LEN);
            confirmed = (memcmp(stored_hash, test_hash, HASH160_LEN) == 0);
        }
    } else {
        std::lock_guard<std::mutex> lock(g_io_mutex);
        fseek(g_bin_file, test_rec_idx * HASH160_LEN, SEEK_SET);
        if (fread(stored_hash, 1, HASH160_LEN, g_bin_file) == HASH160_LEN) {
            confirmed = (memcmp(stored_hash, test_hash, HASH160_LEN) == 0);
        }
    }
    
    if (!confirmed) {
        char hex_test[41], hex_stored[41];
        for(int i=0;i<20;i++) sprintf(hex_test+i*2,"%02x",test_hash[i]);
        for(int i=0;i<20;i++) sprintf(hex_stored+i*2,"%02x",stored_hash[i]);
        fprintf(stderr, "[ERROR] Self-test fallido: BTC.idx[0] no está en BTC.bin[%llu]\n", test_rec_idx);
        fprintf(stderr, "Expected: %s\nFound:    %s\n", hex_test, hex_stored);
        return -1;
    }
    
    fprintf(stderr, "[INFO] Formato %s verificado: %llu entradas, %zu bytes bin\n", 
            g_idx_format == IDX_FULL ? "FULL" : "SPARSE", 
            g_idx.count, g_bin_size);
            
    return 0;
}

static void build_increment_points() {
    Int k_inc((uint64_t)g_num_threads);
    g_inc_point = g_secp->ComputePublicKey(&k_inc);
}

static void run_diagnostic_k1() {
    fprintf(stderr, "[DIAG] Testing privkey 1:\n");
    
    uint8_t priv_bytes[32];
    zero_256(priv_bytes);
    priv_bytes[31] = 1;
    
    Int k_int;
    bytes_to_int_obj(priv_bytes, k_int);
    
    Point pub = g_secp->ComputePublicKey(&k_int);
    
    uint8_t h160_comp[20];
    uint8_t h160_unc[20];
    
    g_secp->GetHash160(P2PKH, true, pub, h160_comp);
    g_secp->GetHash160(P2PKH, false, pub, h160_unc);
    
    char hex_comp[41];
    char hex_unc[41];
    for(int i=0;i<20;i++) sprintf(hex_comp+i*2,"%02x",h160_comp[i]);
    for(int i=0;i<20;i++) sprintf(hex_unc+i*2,"%02x",h160_unc[i]);
    hex_comp[40]=0;
    hex_unc[40]=0;
    
    fprintf(stderr, "[DIAG]   hash160 compressed  : %s\n", hex_comp);
    fprintf(stderr, "[DIAG]   hash160 uncompressed: %s\n", hex_unc);
    fprintf(stderr, "[DIAG]   expected compressed : 751e76e8199196d454941c45d1b3a323f1433bd6\n");
    fprintf(stderr, "[DIAG]   expected uncompressed: 91b24bf9f5288532960ac687abb035127b1d28a5\n");
    
    bool match_comp = (strcmp(hex_comp, "751e76e8199196d454941c45d1b3a323f1433bd6") == 0);
    bool match_unc = (strcmp(hex_unc, "91b24bf9f5288532960ac687abb035127b1d28a5") == 0);
    
    fprintf(stderr, "[DIAG]   match compressed    : %s\n", match_comp ? "yes" : "no");
    fprintf(stderr, "[DIAG]   match uncompressed  : %s\n", match_unc ? "yes" : "no");
    
    if (!match_comp && !match_unc) {
        fprintf(stderr, "[FATAL] BTC.cpp hash160 incorrecto para privkey 1. Abortando.\n");
        exit(1);
    }
    
    bool xor_comp = btc_xor_contains(&g_xorf, h160_comp, HASH160_LEN);
    bool xor_unc = btc_xor_contains(&g_xorf, h160_unc, HASH160_LEN);
    
    fprintf(stderr, "[DIAG]   xor_contains(comp)  : %s\n", xor_comp ? "yes" : "no");
    fprintf(stderr, "[DIAG]   xor_contains(uncomp): %s\n", xor_unc ? "yes" : "no");
    
    uint64_t rec_idx = 0;
    int idx_comp = btc_binary_search_idx(&g_idx, h160_comp, &rec_idx);
    fprintf(stderr, "[DIAG]   idx_lookup(comp)    : %s=%llu / not_found\n", idx_comp==0?"found":"not_found", rec_idx);
    
    idx_comp = btc_binary_search_idx(&g_idx, h160_unc, &rec_idx);
    fprintf(stderr, "[DIAG]   idx_lookup(uncomp)  : %s=%llu / not_found\n", idx_comp==0?"found":"not_found", rec_idx);
}

static void process_hit(const uint8_t priv_bytes[32], Point &current_pub, const uint8_t h160_comp[20], const uint8_t h160_unc[20], int thread_id) {
    char ts[64];
    utc_timestamp(ts, sizeof(ts));
    
    std::lock_guard<std::mutex> lock(g_found_mutex);
    g_found_count.fetch_add(1, std::memory_order_relaxed);
    
    char priv_hex[65];
    for(int i=0;i<32;i++) sprintf(priv_hex+i*2,"%02x",priv_bytes[i]);
    priv_hex[64]=0;
    
    char h160_comp_hex[41];
    for(int i=0;i<20;i++) sprintf(h160_comp_hex+i*2,"%02x",h160_comp[i]);
    h160_comp_hex[40]=0;
    
    char h160_unc_hex[41];
    for(int i=0;i<20;i++) sprintf(h160_unc_hex+i*2,"%02x",h160_unc[i]);
    h160_unc_hex[40]=0;

    char addr_c[64], addr_u[64], addr_sh[64], addr_be[128], addr_eth[64];
    generate_base58_check(h160_comp, 0x00, addr_c, sizeof(addr_c));
    generate_base58_check(h160_unc, 0x00, addr_u, sizeof(addr_u));
    
    uint8_t redeem[22];
    redeem[0]=0x00; redeem[1]=0x14; memcpy(redeem+2,h160_comp,20);
    uint8_t sh32[32], sh20[20];
    sha256(redeem, 22, sh32);
    ripemd160(sh32, 32, sh20);
    generate_base58_check(sh20, 0x05, addr_sh, sizeof(addr_sh));
    
    generate_bech32_p2wpkh(h160_comp, addr_be, sizeof(addr_be));
    
    unsigned char raw_pub[65];
    g_secp->GetPublicKeyRaw(false, current_pub, (char*)raw_pub);
    generate_eth_address(raw_pub+1, addr_eth, sizeof(addr_eth));

    std::ostringstream oss;
    oss << "-|<.>" << std::string(75,'.') << "\n";
    oss << "-|<.>.FOUND KEY >\n";
    oss << "-|<.>" << std::string(75,'.') << "\n";
    oss << "-|<.>.Private Key : " << priv_hex << " >\n";
    oss << "-|<.>.Hash160 Comp : " << h160_comp_hex << " >\n";
    oss << "-|<.>.Hash160 Uncomp : " << h160_unc_hex << " >\n";
    oss << "-|<.>.BTC P2PKH Comp : " << addr_c << " >\n";
    oss << "-|<.>.BTC P2PKH Uncomp : " << addr_u << " >\n";
    oss << "-|<.>.BTC P2SH-P2WPKH : " << addr_sh << " >\n";
    oss << "-|<.>.BTC Bech32 P2WPKH : " << addr_be << " >\n";
    oss << "-|<.>.ETH Address : " << addr_eth << " >\n";
    oss << "-|<.>.Range : " << g_range_bits << "/256 >\n";
    oss << "-|<.>.Subrange : " << thread_id << " >\n";
    oss << "-|<.>.Timestamp : " << ts << " >\n";
    oss << "-|<.>" << std::string(75,'.') << "\n";
    
    FoundLogEntry entry;
    entry.message = oss.str();
    entry.remaining_cycles = 3;
    g_found_logs.push_back(entry);

    btc_write_found(priv_hex, h160_comp_hex, g_range_bits, thread_id, ts);
}

static bool check_and_verify(const uint8_t h160[20], uint64_t *rec_idx_out) {
    if (!btc_xor_contains(&g_xorf, h160, HASH160_LEN)) {
        return false;
    }
    
    g_xor_hits.fetch_add(1, std::memory_order_relaxed);
    
    uint64_t record_index = 0;
    int found_in_idx = 0;

    if (g_idx_format == IDX_FULL) {
       if (btc_binary_search_idx(&g_idx, h160, &record_index) == 0) {
        found_in_idx = 1;
       }
    } else {
        idx_record_sparse_t *sparse_recs = (idx_record_sparse_t*)g_idx.records;
        uint64_t low = 0;
        uint64_t high = g_idx.count;
        uint64_t best_block = UINT64_MAX;
        
        while (low < high) {
            uint64_t mid = low + (high - low) / 2;
            int cmp = memcmp(sparse_recs[mid].hash, h160, HASH160_LEN);
            if (cmp <= 0) {
                best_block = mid;
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        
        if (best_block != UINT64_MAX) {
            uint32_t start_rec = sparse_recs[best_block].record_index;
            uint32_t end_rec = start_rec + IDX_SPARSE_STRIDE;
            if (end_rec > (uint32_t)(g_bin_size / HASH160_LEN)) {
                end_rec = (uint32_t)(g_bin_size / HASH160_LEN);
            }
            
            for (uint32_t r = start_rec; r < end_rec; r++) {
                uint8_t stored_hash[HASH160_LEN];
                bool match = false;
                
                if (g_mem_mode_bin == 2) {
                     if (r * HASH160_LEN < g_bin_size) {
                         memcpy(stored_hash, g_bin_map + (r * HASH160_LEN), HASH160_LEN);
                         match = (memcmp(stored_hash, h160, HASH160_LEN) == 0);
                     }
                } else {
                     std::lock_guard<std::mutex> lock(g_io_mutex);
                     fseek(g_bin_file, r * HASH160_LEN, SEEK_SET);
                     if (fread(stored_hash, 1, HASH160_LEN, g_bin_file) == HASH160_LEN) {
                         match = (memcmp(stored_hash, h160, HASH160_LEN) == 0);
                     }
                }
                
                if (match) {
                    record_index = r;
                    found_in_idx = 1;
                    break;
                }
            }
        }
    }
    
    if (found_in_idx > 0) {
        *rec_idx_out = record_index;
        return true;
    }
    
    return false;
}

/*
 * High-performance Montgomery Batch Inversion function for Secp256k1 curves.
 * Computes 256 affine points from a base point and precalculated step table
 * using IntGroup::ModInv(), ModMulK1, and ModSquareK1 reductions.
 */
static inline void compute_batch_points(
    Point base_pub,
    Point step_table[BATCH_STEPS],
    IntGroup &modGroup,
    Int deltaX[BATCH_STEPS],
    bool zero_flag[BATCH_STEPS],
    Point pts[BATCH_SIZE]
) {
    for (int i = 0; i < BATCH_STEPS; i++) {
        deltaX[i].ModSub(&base_pub.x, &step_table[i].x);
        if (deltaX[i].IsZero()) {
            zero_flag[i] = true;
            deltaX[i].SetInt32(1);
        } else {
            zero_flag[i] = false;
        }
    }

    modGroup.Set(deltaX);
    modGroup.ModInv();

    pts[0] = base_pub;
    for (int i = 0; i < BATCH_STEPS; i++) {
        if (zero_flag[i]) {
            pts[i + 1] = g_secp->AddDirect(base_pub, step_table[i]);
        } else {
            Int dy;
            dy.ModSub(&base_pub.y, &step_table[i].y);
            Int lambda;
            lambda.ModMulK1(&dy, &deltaX[i]);
            Int lambda2;
            lambda2.ModSquareK1(&lambda);
            pts[i + 1].z.SetInt32(1);
            pts[i + 1].x.ModSub(&lambda2, &base_pub.x);
            pts[i + 1].x.ModSub(&step_table[i].x);
            Int dx;
            dx.ModSub(&base_pub.x, &pts[i + 1].x);
            pts[i + 1].y.ModMulK1(&lambda, &dx);
            pts[i + 1].y.ModSub(&base_pub.y);
        }
    }
}

static void worker_function(int thread_id) {
    if (g_big_cores > 0) {
        btc_pin_thread(thread_id % g_big_cores);
    } else if (g_cpu_cores > 0) {
        btc_pin_thread(thread_id % g_cpu_cores);
    }

    uint8_t priv_bytes[32];
    Int k_int;
    Point current_pub;
    unsigned long long local_count = 0;
    
    std::mt19937_64 rng((uint64_t)std::chrono::steady_clock::now().time_since_epoch().count() ^ (uint64_t)thread_id);

    if (!g_random_mode) {
        copy_256(priv_bytes, g_start_key);
        add_small_uint(priv_bytes, (uint64_t)thread_id);
        if (cmp_256(priv_bytes, g_end_key) >= 0) {
            g_threads_done.fetch_add(1, std::memory_order_release);
            return;
        }
        
        bytes_to_int_obj(priv_bytes, k_int);
        current_pub = g_secp->ComputePublicKey(&k_int);

        Point step_table[BATCH_STEPS];
        Int deltaX[BATCH_STEPS];
        Point pts[BATCH_SIZE];
        bool zero_flag[BATCH_STEPS];
        IntGroup modGroup(BATCH_STEPS);

        for (int i = 0; i < BATCH_STEPS; i++) {
            Int k_step((uint64_t)(i + 1) * (uint64_t)g_num_threads);
            step_table[i] = g_secp->ComputePublicKey(&k_step);
        }

        while (!g_stop.load(std::memory_order_relaxed)) {
            compute_batch_points(current_pub, step_table, modGroup, deltaX, zero_flag, pts);

            uint8_t batch_start_priv[32];
            copy_256(batch_start_priv, priv_bytes);

            bool range_reached = false;
            for (int i = 0; i < BATCH_SIZE; i++) {
                uint8_t cur_priv[32];
                copy_256(cur_priv, batch_start_priv);
                add_small_uint(cur_priv, (uint64_t)i * (uint64_t)g_num_threads);

                if (cmp_256(cur_priv, g_end_key) >= 0) {
                    range_reached = true;
                    break;
                }

                uint8_t h160_comp[20];
                uint8_t h160_unc[20];
                g_secp->GetHash160(P2PKH, true, pts[i], h160_comp);
                g_secp->GetHash160(P2PKH, false, pts[i], h160_unc);
                uint64_t rec_idx = 0;
                if (check_and_verify(h160_comp, &rec_idx) || check_and_verify(h160_unc, &rec_idx)) {
                    process_hit(cur_priv, pts[i], h160_comp, h160_unc, thread_id);
                }
            }

            local_count += BATCH_SIZE;
            if (local_count >= 1024) {
                g_total_keys.fetch_add(local_count, std::memory_order_relaxed);
                g_thread_counters[thread_id].fetch_add(local_count, std::memory_order_relaxed);
                local_count = 0;
            }

            if (range_reached) break;

            add_small_uint(priv_bytes, (uint64_t)BATCH_SIZE * (uint64_t)g_num_threads);
            bytes_to_int_obj(priv_bytes, k_int);
            current_pub = g_secp->ComputePublicKey(&k_int);

            if (g_stop.load(std::memory_order_relaxed)) break;
        }

    } else { // g_random_mode == true
        Point step_table_fwd[BATCH_STEPS];
        Point step_table_bwd[BATCH_STEPS];
        Int deltaX[BATCH_STEPS];
        Point pts[BATCH_SIZE];
        bool zero_flag[BATCH_STEPS];
        IntGroup modGroup(BATCH_STEPS);

        for (int i = 0; i < BATCH_STEPS; i++) {
            Int k_step((uint64_t)(i + 1));
            step_table_fwd[i] = g_secp->ComputePublicKey(&k_step);
            step_table_bwd[i] = g_secp->Negation(step_table_fwd[i]);
        }

        Int k_256((uint64_t)BATCH_SIZE);
        Point step_table_fwd_256 = g_secp->ComputePublicKey(&k_256);
        Point step_table_bwd_256 = g_secp->Negation(step_table_fwd_256);

        Int k_1((uint64_t)1);
        Point G_1 = g_secp->ComputePublicKey(&k_1);
        Point NegG_1 = g_secp->Negation(G_1);

        uint8_t fwd_priv[32];
        uint8_t bwd_priv[32];
        Point fwd_pub;
        Point bwd_pub;

        auto gen_anchor = [&]() {
            uint8_t rnd_priv[32];
            generate_random_key(rnd_priv, rng);

            Int k_rnd;
            bytes_to_int_obj(rnd_priv, k_rnd);
            Point P_rnd = g_secp->ComputePublicKey(&k_rnd);

            copy_256(fwd_priv, rnd_priv);
            fwd_pub = P_rnd;

            copy_256(bwd_priv, rnd_priv);
            sub_small_uint(bwd_priv, 1);
            bwd_pub = g_secp->AddDirect(P_rnd, NegG_1);
        };

        gen_anchor();
        auto anchor_start = std::chrono::steady_clock::now();

        while (!g_stop.load(std::memory_order_relaxed)) {
            // --- 1. Forward Batch Sweep (256 keys via IntGroup Montgomery Batch Inversion) ---
            compute_batch_points(fwd_pub, step_table_fwd, modGroup, deltaX, zero_flag, pts);

            for (int i = 0; i < BATCH_SIZE; i++) {
                uint8_t cur_priv[32];
                copy_256(cur_priv, fwd_priv);
                add_small_uint(cur_priv, (uint64_t)i);

                if (cmp_256(cur_priv, g_start_key) >= 0 && cmp_256(cur_priv, g_end_key) < 0) {
                    uint8_t h160_comp[20];
                    uint8_t h160_unc[20];
                    g_secp->GetHash160(P2PKH, true, pts[i], h160_comp);
                    g_secp->GetHash160(P2PKH, false, pts[i], h160_unc);
                    uint64_t rec_idx = 0;
                    if (check_and_verify(h160_comp, &rec_idx) || check_and_verify(h160_unc, &rec_idx)) {
                        process_hit(cur_priv, pts[i], h160_comp, h160_unc, thread_id);
                    }
                }
            }

            add_small_uint(fwd_priv, (uint64_t)BATCH_SIZE);
            fwd_pub = g_secp->AddDirect(fwd_pub, step_table_fwd_256);
            local_count += BATCH_SIZE;

            if (g_stop.load(std::memory_order_relaxed)) break;

            // --- 2. Backward Batch Sweep (256 keys via IntGroup Montgomery Batch Inversion) ---
            compute_batch_points(bwd_pub, step_table_bwd, modGroup, deltaX, zero_flag, pts);

            for (int i = 0; i < BATCH_SIZE; i++) {
                uint8_t cur_priv[32];
                copy_256(cur_priv, bwd_priv);
                sub_small_uint(cur_priv, (uint64_t)i);

                if (cmp_256(cur_priv, g_start_key) >= 0 && cmp_256(cur_priv, g_end_key) < 0) {
                    uint8_t h160_comp[20];
                    uint8_t h160_unc[20];
                    g_secp->GetHash160(P2PKH, true, pts[i], h160_comp);
                    g_secp->GetHash160(P2PKH, false, pts[i], h160_unc);
                    uint64_t rec_idx = 0;
                    if (check_and_verify(h160_comp, &rec_idx) || check_and_verify(h160_unc, &rec_idx)) {
                        process_hit(cur_priv, pts[i], h160_comp, h160_unc, thread_id);
                    }
                }
            }

            sub_small_uint(bwd_priv, (uint64_t)BATCH_SIZE);
            bwd_pub = g_secp->AddDirect(bwd_pub, step_table_bwd_256);
            local_count += BATCH_SIZE;

            if (local_count >= 1024) {
                g_total_keys.fetch_add(local_count, std::memory_order_relaxed);
                g_thread_counters[thread_id].fetch_add(local_count, std::memory_order_relaxed);
                local_count = 0;
            }

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - anchor_start).count() >= 5) {
                gen_anchor();
                anchor_start = now;
            }
        }
    }

    if (local_count) {
        g_total_keys.fetch_add(local_count, std::memory_order_relaxed);
        g_thread_counters[thread_id].fetch_add(local_count, std::memory_order_relaxed);
    }
    
    g_threads_done.fetch_add(1, std::memory_order_release);
}

static void render_display(std::vector<unsigned long long> &prev_counts, double elapsed_sec, int current_range_bit, int render_cycle) {
    std::ostringstream b;
    char lb[160];

    b << "-|<.>BTCMobile Zoey Alejandroo JF >\n";
    b << "-|<.>\\_____________________________________/\n";
    b << "-|<.>.................................................................\n";

    if (!g_random_mode) {
        b << "-|<.>.Mode : SEQUENTIAL FORWARD >\n";
    } else {
        b << "-|<.>.Mode : RANDOM >\n";
    }
    b << "-|<.>\\_____________________________________/\n";
    b << "-|<.>.................................................................\n";

    snprintf(lb, sizeof(lb), "-|<.>.Range : %d/256 >\n", current_range_bit);
    b << lb;
    b << "-|<.>\\_____________________________________/\n";
    b << "-|<.>..................................................................\n";
    b << "-|<.>.Bits >\n";
    b << "-|<.>\\_____________________________________/\n";
    b << "-|<.>..................................................................\n";

    auto min_hex = [](const uint8_t *a) -> std::string {
        int first = 0;
        while (first < 32 && a[first] == 0) first++;
        if (first == 32) return "0x0";
        std::string s = "0x";
        char t[3];
        for (int i = first; i < 32; i++) { snprintf(t, 3, "%02x", a[i]); s += t; }
        return s;
    };

    b << "-|<.>." << min_hex(g_start_key) << " >\n";
    b << "-|<.>\\________________________________________________________________/\n";
    b << "-|<.>..................................................................\n";
    b << "-|<.>." << min_hex(g_end_key) << " >\n";
    b << "-|<.>\\________________________________________________________________/\n";
    b << "-|<.>..................................................................\n";

    if (!g_random_mode) {
        unsigned long long total = g_total_keys.load(std::memory_order_relaxed);
        long double size_ld = u256_to_ld(g_end_key) - u256_to_ld(g_start_key);
        if (size_ld <= 0) size_ld = 1;
        double pct = (double)((long double)total / size_ld * 100.0L);
        if (pct > 100.0) pct = 100.0;

        b << "-|<.>.Range Progrese/s >\n";
        b << "-|<.>\\_____________________________________/\n";
        b << "-|<.>..................................................................\n";
        b << "-|<.>.[";
        int bars = (int)(pct * 33.0 / 100.0 + 0.5);
        if (bars < 0) bars = 0;
        if (bars > 33) bars = 33;
        for (int i = 0; i < bars; i++) b << '=';
        if (bars < 33) b << '>';
        for (int i = bars + 1; i < 33; i++) b << '-';
        snprintf(lb, sizeof(lb), "] %.2f%% >\n", pct);
        b << lb;
        b << "-|<.>\\________________________________________________________________/\n";
        b << "-|<.>..................................................................\n";
    } else {
        b << "-|<.>.Search Type:Bidireccional-Random-Posittions >\n";
        b << "-|<.>\\_____________________________________/\n";
        int seed_shift = render_cycle * 13;
        for (int r = 0; r < 6; r++) {
            for (int c = 0; c < 67; c++) {
                int x = (r * 67 + c * 7 + seed_shift) % 100;
                if (x < 45) b << ' ';
                else if (x < 75) b << '.';
                else if (x < 90) b << "•";
                else b << "●";
            }
            b << "\n";
        }
        b << "-|<.>\\________________________________________________________________/\n";
        b << "-|<.>..................................................................\n";
    }

    std::vector<unsigned long long> rates(g_num_threads, 0);
    for (int i = 0; i < g_num_threads; i++) {
        unsigned long long cur = g_thread_counters[i].load(std::memory_order_relaxed);
        unsigned long long delta = (cur >= prev_counts[i]) ? (cur - prev_counts[i]) : 0;
        rates[i] = (elapsed_sec > 0.0) ? (unsigned long long)(delta / elapsed_sec) : 0;
        prev_counts[i] = cur;
    }

    for (int i = 0; i < g_num_threads; i += 2) {
        b << "-|<.>.[Thread " << (i + 1) << ": " << format_comma(rates[i]) << " keys/s ]";
        if (i + 1 < g_num_threads) {
            b << ".-|<.>|-.[Thread " << (i + 2) << ": " << format_comma(rates[i + 1]) << " keys/s ] >\n";
        } else {
            b << " >\n";
        }
        b << "-|<.>\\________________________________________________________________/\n";
    }

    b << "-|<.>..................................................................\n";
    unsigned long long total_all = g_total_keys.load(std::memory_order_relaxed);
    snprintf(lb, sizeof(lb), "-|<.>.In 15/s [Total %llu Key/s ] >\n", total_all);
    b << lb;
    b << "-|<.>\\_____________________________________/\n";
    b << "-|<.>..................................................................\n";

    double xor_rate = 0.0;
    if (total_all > 0) xor_rate = (double)g_xor_hits.load(std::memory_order_relaxed) * 100.0 / (double)total_all;
    snprintf(lb, sizeof(lb), "-|<.>.[Xor-Filter : %.2f] >\n", xor_rate);
    b << lb;
    b << "-|<.>\\_____________________________________/\n";
    b << "-|<.>..................................................................\n";

    snprintf(lb, sizeof(lb), "-|<.>.[Found : %llu ] >\n", (unsigned long long)g_found_count.load(std::memory_order_relaxed));
    b << lb;
    b << "-|<.>\\_____________________________________/\n";
    b << "-|<.>..................................................................\n";

    {
        std::lock_guard<std::mutex> lk(g_found_mutex);
        for (auto it = g_found_logs.begin(); it != g_found_logs.end(); ) {
            if (it->remaining_cycles > 0) {
                b << it->message;
                it->remaining_cycles--;
                ++it;
            } else {
                it = g_found_logs.erase(it);
            }
        }
    }

    std::string out = b.str();
    int new_lines = 0;
    for (size_t i = 0; i < out.size(); i++) {
        if (out[i] == '\n') new_lines++;
    }

    if (g_display_lines > 0) {
        char esc[32];
        snprintf(esc, sizeof(esc), "\033[%dF\033[J", g_display_lines);
        fputs(esc, stdout);
    }
    fputs(out.c_str(), stdout);
    fflush(stdout);
    g_display_lines = new_lines;
}

int run_single_range(int bits) {
    g_range_bits = bits;
    initialize_range(bits);
    
    g_threads_done.store(0, std::memory_order_relaxed);
    g_thread_counters.reset(new std::atomic<unsigned long long>[g_num_threads]);
    for(int i=0;i<g_num_threads;i++) g_thread_counters[i].store(0);
    
    std::vector<std::thread> workers;
    for(int i=0;i<g_num_threads;i++){
        workers.emplace_back(worker_function, i);
    }
    
    std::vector<unsigned long long> prev_counts(g_num_threads, 0);
    g_display_lines = 0;
    int render_cycle = 0;
    auto last_time = std::chrono::steady_clock::now();
    auto next_render = last_time + std::chrono::seconds(15);
    
    while(!g_stop.load(std::memory_order_relaxed)){
        if (g_threads_done.load(std::memory_order_acquire) == g_num_threads) {
            break;
        }
        
        auto now = std::chrono::steady_clock::now();
        if(now < next_render){
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        double elapsed = std::chrono::duration<double>(now - last_time).count();
        if(elapsed <= 0.0) elapsed = 15.0;
        
        render_cycle++;
        render_display(prev_counts, elapsed, bits, render_cycle);
        
        last_time = now;
        next_render = now + std::chrono::seconds(15);
    }
    
    for(auto &t : workers){
        if(t.joinable()) t.join();
    }
    
    fprintf(stderr, "[OK] Rango %d completado: %llu match(es)\n", bits, (unsigned long long)g_found_count.load());
    
    return 0;
}

int main(int argc, char **argv) {
    int bits_arg = 0;
    bool mode_specified = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-R") == 0 && i + 1 < argc) {
            if (strcasecmp(argv[i+1], "all") == 0) {
                g_all_ranges = true;
                i++;
            } else {
                bits_arg = atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "-S") == 0) {
            g_random_mode = false;
            mode_specified = true;
        } else if (strcasecmp(argv[i], "-Random") == 0) {
            g_random_mode = true;
            mode_specified = true;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            g_num_threads = atoi(argv[++i]);
        } else if (argv[i][0] == '-' && argv[i][1] >= '0' && argv[i][1] <= '9') {
            g_num_threads = atoi(argv[i] + 1);
        } else {
            fprintf(stderr, "[ERROR] Unrecognized flag: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    if (!mode_specified) {
        g_random_mode = false;
    }
    
    int little;
    btc_detect_cores(&g_cpu_cores, &g_big_cores, &little);
    if (g_cpu_cores < 1) g_cpu_cores = 1;
    if (g_big_cores < 1) g_big_cores = g_cpu_cores;

    if (g_num_threads <= 0) {
        g_num_threads = g_big_cores;
    } else if (g_num_threads > g_big_cores) {
        g_num_threads = g_big_cores;
    }
    if (g_num_threads > 32) g_num_threads = 32;
    
    g_secp = new Secp256K1();
    g_secp->Init();
    build_increment_points();
    
    init_memory_loading();
    
    if (load_database_files() != 0) {
        delete g_secp;
        return 1;
    }
    
    run_diagnostic_k1();
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    if (g_all_ranges || bits_arg == 0) {
        for (int b = 1; b <= 256; b++) {
            if (g_stop.load(std::memory_order_relaxed)) break;
            run_single_range(b);
        }
        fprintf(stderr, "[OK] Todos los rangos completados\n");
    } else {
        if (bits_arg <= 0) bits_arg = 71;
        if (bits_arg > 256) bits_arg = 256;
        run_single_range(bits_arg);
    }
    
    if(g_bin_file) fclose(g_bin_file);
    if(g_bin_map) munmap(g_bin_map, g_bin_size);
    btc_free_xor(&g_xorf);
    btc_free_idx(&g_idx);

    delete g_secp;
    return 0;
}
