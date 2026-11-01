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

#ifndef ADDRESSHELPER_H
#define ADDRESSHELPER_H

#include <string>
#include <cstddef>
#include "Int.h"
#include "Point.h"

struct DerivedInfo {
    std::string privkey_hex;
    std::string pubkey_compressed_hex;
    std::string pubkey_uncompressed_hex;
    std::string hash160_hex;
    std::string btc_p2pkh_compressed;
    std::string btc_p2pkh_uncompressed;
    std::string btc_p2sh_p2wpkh;
    std::string btc_p2wpkh_bech32;
    std::string eth_address;
};

int derive_all_info(Int &priv, Point &pub, DerivedInfo &out);

void format_extended_entry(const DerivedInfo &info,
                           int range_bits,
                           int subrange_id,
                           int thread_id,
                           const char *timestamp_utc,
                           char *out,
                           size_t out_size);

#endif

