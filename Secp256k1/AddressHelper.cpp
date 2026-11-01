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

#include "AddressHelper.h"
#include "sha256.h"
#include "ripemd160.h"
#include "sha3.h"
#include "keccak.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

static const char *B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char *BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static void base58_encode(const unsigned char *in, size_t inlen, char *out, size_t outsize) {
    size_t zeros = 0;
    while (zeros < inlen && in[zeros] == 0) zeros++;
    size_t size = (inlen - zeros) * 138 / 100 + 1;
    unsigned char *buf = (unsigned char*)calloc(size, 1);
    size_t high = size - 1;
    for (size_t i = zeros; i < inlen; i++) {
        int carry = in[i];
        size_t j = size - 1;
        for (; j > high || carry != 0; j--) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
            if (j == 0) break;
        }
        high = j;
    }
    size_t j = 0;
    while (j < size && buf[j] == 0) j++;
    size_t k = 0;
    for (size_t i = 0; i < zeros && k + 1 < outsize; i++) out[k++] = '1';
    for (; j < size && k + 1 < outsize; j++) out[k++] = B58[buf[j]];
    out[k] = 0;
    free(buf);
}

static void btc_p2pkh(const unsigned char *h160, unsigned char prefix, char *out, size_t outsize) {
    unsigned char payload[21];
    payload[0] = prefix;
    memcpy(payload + 1, h160, 20);
    unsigned char s1[32], s2[32];
    sha256(payload, 21, s1);
    sha256(s1, 32, s2);
    unsigned char full[25];
    memcpy(full, payload, 21);
    memcpy(full + 21, s2, 4);
    base58_encode(full, 25, out, outsize);
}

static void btc_p2sh_p2wpkh(const unsigned char *h160, char *out, size_t outsize) {
    unsigned char redeem[22];
    redeem[0] = 0x00;
    redeem[1] = 0x14;
    memcpy(redeem + 2, h160, 20);
    unsigned char h[32];
    sha256(redeem, 22, h);
    btc_p2pkh(h, 0x05, out, outsize);
}

static uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static void bech32_encode(const char *hrp, const uint8_t *data, size_t data_len, char *out, size_t outsize) {
    uint32_t chk_val = 1;
    size_t hrp_len = strlen(hrp);
    for (size_t i = 0; i < hrp_len; i++) chk_val = bech32_polymod_step(chk_val) ^ (hrp[i] >> 5);
    chk_val = bech32_polymod_step(chk_val);
    for (size_t i = 0; i < hrp_len; i++) chk_val = bech32_polymod_step(chk_val) ^ (hrp[i] & 31);
    for (size_t i = 0; i < data_len; i++) chk_val = bech32_polymod_step(chk_val) ^ data[i];
    for (int i = 0; i < 6; i++) chk_val = bech32_polymod_step(chk_val);
    chk_val ^= 1;
    size_t k = 0;
    for (size_t i = 0; i < hrp_len && k + 1 < outsize; i++) out[k++] = hrp[i];
    if (k + 1 < outsize) out[k++] = '1';
    for (size_t i = 0; i < data_len && k + 1 < outsize; i++) out[k++] = BECH32_CHARSET[data[i]];
    for (int i = 0; i < 6 && k + 1 < outsize; i++) {
        int shift = 5 * (5 - i);
        out[k++] = BECH32_CHARSET[(chk_val >> shift) & 31];
    }
    out[k] = 0;
}

static void convert_bits(const uint8_t *in, size_t inlen, int inbits, int outbits, uint8_t *out, size_t *outlen) {
    uint32_t acc = 0;
    int bits = 0;
    size_t k = 0;
    uint32_t maxv = (1u << outbits) - 1;
    for (size_t i = 0; i < inlen; i++) {
        acc = (acc << inbits) | in[i];
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[k++] = (acc >> bits) & maxv;
        }
    }
    if (bits) out[k++] = (acc << (outbits - bits)) & maxv;
    *outlen = k;
}

static void btc_p2wpkh_bech32(const uint8_t *h160, char *out, size_t outsize) {
    uint8_t data5[64];
    size_t data5len = 0;
    convert_bits(h160, 20, 8, 5, data5, &data5len);
    uint8_t final_data[64];
    final_data[0] = 0;
    memcpy(final_data + 1, data5, data5len);
    bech32_encode("bc", final_data, data5len + 1, out, outsize);
}

static void eth_address_from_pub(const unsigned char *pub64, char *out, size_t outsize) {
    SHA3_256_CTX ctx;
    KECCAK_256_Init(&ctx);
    KECCAK_256_Update(&ctx, pub64, 64);
    unsigned char k[32];
    KECCAK_256_Final(k, &ctx);
    snprintf(out, outsize,
             "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
               "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             k[12], k[13], k[14], k[15], k[16], k[17], k[18], k[19], k[20], k[21],
             k[22], k[23], k[24], k[25], k[26], k[27], k[28], k[29], k[30], k[31]);
}

static void hexify(const unsigned char *in, size_t n, char *out) {
    static const char *hx = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = hx[in[i] >> 4];
        out[i * 2 + 1] = hx[in[i] & 15];
    }
    out[n * 2] = 0;
}

int derive_all_info(Int &priv, Point &pub, DerivedInfo &out) {
    unsigned char pubc[33];
    pubc[0] = pub.y.IsEven() ? 0x02 : 0x03;
    pub.x.Get32Bytes(pubc + 1);

    unsigned char pubu[65];
    pubu[0] = 0x04;
    pub.x.Get32Bytes(pubu + 1);
    pub.y.Get32Bytes(pubu + 33);

    unsigned char sha[32], h160c[20], h160u[20];
    sha256(pubc, 33, sha);
    ripemd160(sha, 32, h160c);
    sha256(pubu, 65, sha);
    ripemd160(sha, 32, h160u);

    char priv_hex[80];
    memset(priv_hex, '0', 64);
    priv_hex[64] = 0;
    char *p = priv.GetBase16();
    if (p) {
        int len = (int)strlen(p);
        if (len > 0 && len <= 64) memcpy(priv_hex + (64 - len), p, (size_t)len);
        free(p);
    }

    char pubc_hex[80];
    char pubu_hex[140];
    char h160c_hex[48];
    hexify(pubc, 33, pubc_hex);
    hexify(pubu, 65, pubu_hex);
    hexify(h160c, 20, h160c_hex);

    char addr_c[80];
    char addr_u[80];
    char addr_p2sh[80];
    char addr_bech[80];
    btc_p2pkh(h160c, 0x00, addr_c, sizeof(addr_c));
    btc_p2pkh(h160u, 0x00, addr_u, sizeof(addr_u));
    btc_p2sh_p2wpkh(h160c, addr_p2sh, sizeof(addr_p2sh));
    btc_p2wpkh_bech32(h160c, addr_bech, sizeof(addr_bech));

    char eth[80];
    eth_address_from_pub(pubu + 1, eth, sizeof(eth));

    out.privkey_hex = priv_hex;
    out.pubkey_compressed_hex = pubc_hex;
    out.pubkey_uncompressed_hex = pubu_hex;
    out.hash160_hex = h160c_hex;
    out.btc_p2pkh_compressed = addr_c;
    out.btc_p2pkh_uncompressed = addr_u;
    out.btc_p2sh_p2wpkh = addr_p2sh;
    out.btc_p2wpkh_bech32 = addr_bech;
    out.eth_address = eth;
    return 0;
}

void format_extended_entry(const DerivedInfo &info,
                           int range_bits,
                           int subrange_id,
                           int thread_id,
                           const char *timestamp_utc,
                           char *out,
                           size_t out_size) {
    snprintf(out, out_size,
        "Private Key       : %s\n"
        "Public Key Comp   : %s\n"
        "Public Key Uncomp : %s\n"
        "Hash160 Comp      : %s\n"
        "BTC P2PKH Comp    : %s\n"
        "BTC P2PKH Uncomp  : %s\n"
        "BTC P2SH-P2WPKH   : %s\n"
        "BTC Bech32 P2WPKH : %s\n"
        "ETH Address       : %s\n"
        "Range bits        : %d\n"
        "Subrange          : %d\n"
        "Thread            : %d\n"
        "Timestamp         : %s\n"
        "\n",
        info.privkey_hex.c_str(),
        info.pubkey_compressed_hex.c_str(),
        info.pubkey_uncompressed_hex.c_str(),
        info.hash160_hex.c_str(),
        info.btc_p2pkh_compressed.c_str(),
        info.btc_p2pkh_uncompressed.c_str(),
        info.btc_p2sh_p2wpkh.c_str(),
        info.btc_p2wpkh_bech32.c_str(),
        info.eth_address.c_str(),
        range_bits,
        subrange_id,
        thread_id,
        timestamp_utc);
}

