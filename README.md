# BTCMobile - High-Performance Cryptography & Dual-Search Suite

High-performance cryptographic search engine and database generation suite written in **C++17**, optimized for **ARM64 / Android Termux / Linux** mobile devices and high-end workstations.

The suite provides a complete, end-to-end pipeline: from universal address parsing and deduplication to database indexing and multi-threaded dual-network key search across **Ethereum** and **Bitcoin**.

---

## 1. End-to-End Pipeline & Architecture Overview

The system consists of three modular, highly decoupled engines that communicate via standardized 64-bit binary artifacts:

```text
+---------------------------------------------------------------------------------------------+
| MODULE 1: Address-Hash160 (Universal Address Extractor, Sorter & Deduplicator)             |
|   - Inputs: Any file format, layout, or extension (from 1 MB to 60+ GB)                     |
|   - Parses: ETH (0x...), BTC P2PKH (1...), BTC P2SH (3...), SegWit (bc1...), Raw 40 hex     |
|   - External k-way merge sort (< 100 MB RAM strictly bounded)                               |
|   - Output: BTC.hex (Lexicographically sorted, unique 40-char lowercase hex strings)        |
+----------------------------------------------+----------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------+
| MODULE 2: CREATE-BIX (Database & Index Generator)                                           |
|   - Input: BTC.hex (or mixed text files directly)                                           |
|   - Outputs:                                                                                |
|       * BTC.bin: Contiguous binary file of sorted 20-byte Hash160 payloads                  |
|       * BTC.idx: Index file with magic header (0x49445831) supporting:                       |
|                  Option 1: Full Index (28 bytes per record: hash[20] + offset[8])           |
|                  Option 2: Sparse Index (24 bytes per record: hash[20] + offset[4], stride) |
|       * BTC.xor: 3-hash XOR filter for ultra-fast O(1) probabilistic set membership queries |
+----------------------------------------------+----------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------+
| MODULE 3: BTC (Dual-Network Ethereum & Bitcoin High-Performance Search Engine)              |
|   - Inputs: BTC.bin, BTC.idx, BTC.xor                                                       |
|   - Storage Modes: Interactive selection at startup ([1] RAM or [2] Disk MMAP via mmap64)   |
|   - Mathematical Engine:                                                                    |
|       * Solinas pseudo-Mersenne fast field reduction (p = 2^256 - 2^32 - 977)               |
|       * 1024-key Montgomery batch inversion (1 single modular inversion per 1024 points)    |
|       * Precomputed step table (+/- iG, i in [1, 1023])                                      |
|       * Big/Prime CPU core pinning via sysfs cpufreq detection                              |
|   - Dual Verification Pipeline:                                                             |
|       * Step 1: Ethereum (Keccak-256 over 64-byte uncompressed X, Y coordinates)            |
|       * Step 2: Bitcoin (Hash160 over compressed 02/03+X and uncompressed 04+X+Y)           |
|   - Precision Match Reporting:                                                              |
|       * Exact percentage position within range ([2^(R-1), 2^R - 1])                         |
|       * Subrange calculation (Range segmented into 100 exact subranges: 1 to 100)           |
|   - Output: FOUND.txt (Permanent log of private keys, addresses, ranges, and subranges)      |
+---------------------------------------------------------------------------------------------+
```

---

## 2. Detailed Technical Breakdown of Each Module

### Module 1: `Address-Hash160.cpp` (Universal Address Extractor & Sorter)
* **Input Flexibility:**
  - Syntax: `./Address-Hash160 <input_1> [input_2 ... input_N]`
  - Parses mixed inputs regardless of delimiters (spaces, commas, tabs, colons, quotes).
  - Decodes and extracts:
    - **Ethereum Addresses:** Hex strings with or without `0x` prefix (40 hex chars / 20 bytes).
    - **Bitcoin P2PKH (`1...`) & P2SH (`3...`):** Base58Check decoding, verifying SHA-256 double checksum and extracting the raw 20-byte Hash160.
    - **Bitcoin SegWit Bech32 / Bech32m (`bc1q...` / `bc1p...`):** BIP173 / BIP350 decoding, extracting the 20-byte witness program.
    - **Raw Hash160:** 40-character hexadecimal strings.
* **External Chunked Merge Sort (OOM Elimination):**
  - Chunks hashes into blocks of 2,000,000 hashes (~40 MB) sorted lexicographically in memory and flushed to temporary storage in `$TMPDIR`.
  - Merges all temporary chunks using a min-heap priority queue (`std::priority_queue`) with 64 KB per-stream read buffers.
  - Keeps peak RAM usage strictly **below 100 MB**, allowing multi-gigabyte files (6 GB to 60+ GB) to be parsed without crashing mobile or Termux environments.
* **Terminal UI:**
  - Non-destructive ANSI updates (`\r\033[K`) preserving scrollback history.
  - Real-time progress percentage, processed lines, valid addresses, and duplicates found.
  - Final summary with execution time (seconds and minutes), total unique hashes written, and `BTC.hex` size in MB and GB.

---

### Module 2: `CREATE-BIX.cpp` (Database Engine)
* **Input:**
  - Defaults to `BTC.hex` when invoked without arguments, or accepts direct files (`./CREATE-BIX input.txt`).
* **Outputs Generated:**
  1. `BTC.bin`: Contiguous binary file storing unique 20-byte hashes in strict lexicographical order.
  2. `BTC.idx`: Binary index file with standard magic header (`IDX_MAGIC = 0x49445831`):
     - **Full Index (`--full`):** 28 bytes per record (`hash[20]` + `record_index[8]`). Enables binary search directly on the index to obtain exact 64-bit offsets in `BTC.bin`.
     - **Sparse Index (`--sparse`):** 24 bytes per record (`hash[20]` + `record_index[4]`), indexing every 256th hash (`stride = 256`) to drastically reduce index footprint while keeping disk reads minimal.
  3. `BTC.xor`: 3-hash XOR filter constructed over the 20-byte hashes for ultra-fast $O(1)$ probabilistic membership testing with a 16-bit fingerprint.
* **64-Bit Scalability:**
  - All file pointers, counters, and offsets strictly use `uint64_t` and POSIX 64-bit I/O (`pread64`/`pwrite64`) to seamlessly support massive databases up to 60+ GB.

---

### Module 3: `BTC.cpp` (Dual-Search Engine)
* **Interactive Storage Configuration:**
  - Prompts at startup for `BTC.bin`, `BTC.idx`, and `BTC.xor`:
    ```text
    [INFO] Select storage for BTC.bin : [1] RAM [2] Disk MMAP
    [INFO] Select storage for BTC.idx : [1] RAM [2] Disk MMAP
    [INFO] Select storage for BTC.xor : [1] RAM [2] Disk MMAP
    ```
  - **RAM:** Fast in-memory buffer.
  - **Disk MMAP:** 64-bit memory mapping (`mmap64`) with `MAP_PRIVATE`, allowing multi-gigabyte databases to be searched without exhausting RAM.
* **Command-Line Parameters:**
  - `-R <1-256>`: Selects bit range bound $[2^{R-1}, 2^R - 1]$ (or curve order $N$ for $R=256$).
  - `-S`: Sequential forward search starting from $2^{R-1}$ to $2^R - 1$, advancing contiguously by $1024 \times T$ keys per iteration.
  - `-Random`: Bidirectional random search anchoring threads at random points in the range, sweeping forward ($+1024$) and backward ($-1024$) around anchor points for 5 seconds, then re-anchoring to new random positions without exceeding range bounds.
  - `-t <threads>`: Thread count (up to 32). Inspects `/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq` and binds threads exclusively to Big/Prime cores via `pthread_setaffinity_np` to prevent thermal throttling.
* **Mathematical & Cryptographic Optimizations:**
  - **Solinas Special Reduction:** Fast reduction modulo $p = 2^{256} - 2^{32} - 977$ replacing expensive divisions with short multiplications by `0x1000003D1`.
  - **1024-Key Montgomery Batch Inversion:** Computes 1 single modular inversion ($a^{p-2} \pmod p$) with `IntGroup::ModInv()` for each block of 1024 points, resolving affine additions in $Z=1$ coordinates.
  - **Thread-Isolated Scratch Allocation:** All batch tables (`WorkerScratch`) are allocated once on the heap via `std::unique_ptr` at thread startup, keeping thread stack frames minimal (**< 4 KB**) and preventing stack overflows on Android Termux.
  - **Exact 1-to-1 Key Correspondence:** Every generated point in both `-S` and `-Random` modes is strictly mapped to its 32-byte scalar private key.
* **Dual Verification Pipeline:**
  1. **Ethereum Verification:**
     - Computes Keccak-256 over uncompressed coordinates $(X, Y)$ (64 bytes).
     - Extracts last 20 bytes and queries `BTC.xor` -> `BTC.idx` -> `BTC.bin`.
     - On match: derives checksummed address (`0x...`), logs to `FOUND.txt`, displays on screen, and increments `FOUND` counter without stopping.
  2. **Bitcoin Verification:**
     - Computes compressed (`02/03 + X`) and uncompressed (`04 + X + Y`) Hash160 (SHA-256 + RIPEMD-160).
     - Queries `BTC.xor` -> `BTC.idx` -> `BTC.bin`.
     - On match: derives P2PKH Compressed, P2PKH Uncompressed, P2SH-P2WPKH, and Bech32 P2WPKH, logs to `FOUND.txt`, displays on screen, and increments `FOUND` counter without stopping.
* **Precision Subrange Tracking:**
  - The bit range is segmented into **100 exact subranges** (Subranges 1 to 100).
  - Matches report their exact subrange and percentage position within the range:
    ```text
    -|<.>.Range         : 71/256 >
    -|<.>.Subrange      : 51/100 (50.0000%) >
    ```
* **Real-Time Terminal Dashboard:**
  - Renders immediately upon launch and refreshes every 15 seconds without wiping terminal history.
  - Displays mode, range, bit boundaries, progress bar, per-thread key rates, cumulative monotonic rate, XOR filter false positive rate, and found matches.

---

## 3. Building and Installation

### Prerequisites
- Modern C++17 compiler (`g++` or `clang++`).
- POSIX-compliant system: Linux, Android Termux, macOS, or WSL.
- Zlib development headers (`zlib1g-dev` on Debian/Ubuntu, `zlib` on Termux).

### Compilation
Build the complete suite using the optimized Makefile:

```bash
make clean && make -j$(nproc)
```

Target architecture flags (`armv8-a+crypto`, SSSE3, `-DNO_SSE`) are detected automatically.

---

## 4. Usage Examples & Workflow

### Step 1: Extract and Sort Addresses into `BTC.hex`
```bash
./Address-Hash160 input_addresses.txt another_list.csv
```

### Step 2: Generate Database (`BTC.bin`, `BTC.idx`, `BTC.xor`)
Generate full index database (recommended for maximum speed):
```bash
./CREATE-BIX --full
```
Or generate sparse index database (recommended for compact disk storage):
```bash
./CREATE-BIX --sparse
```

### Step 3: Run Dual-Search Engine (`BTC`)
Run sequential forward search in bit range 71 with 4 threads:
```bash
./BTC -R 71 -S -t 4
```

Run random bidirectional search in bit range 66:
```bash
./BTC -R 66 -Random -t 4
```

---

## 5. License & Attribution

This project is licensed under the **Apache License, Version 2.0**.

Third-party cryptographic implementations retain their original licenses:
- `Secp256k1/keccak.c` & `keccak.h`: Copyright (c) 2015 Taylor R. Campbell (BSD 2-Clause License).
- `Secp256k1/xxhash.c` & `xxhash.h`: Copyright (C) 2012-2020 Yann Collet (BSD 2-Clause License).
- `Secp256k1/sse2neon.h`: Copyright (c) 2015-2026 SSE2NEON Contributors (MIT License).
