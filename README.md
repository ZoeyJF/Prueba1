# BTCMobile - High-Performance Mobile Bitcoin Engine


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
=======
**Author & Developer:** ZoeyJF
**Target Architectures:** ARM Mobile (Qualcomm Snapdragon Big Cores) / x86_64 / i686

---

## Overview

**BTCMobile** is an ultra-fast, C++17 multithreaded Bitcoin private key search engine designed specifically for high-performance execution on mobile Snapdragon processor Big-cluster cores. It unifies **Montgomery Batch Inversion** (`IntGroup::ModInv`), **Solinas / Pseudo-Mersenne Fast Reduction** (`ModMulK1`, `ModSquareK1`), **Precalculated Elliptic Curve Step Tables**, and **Constructive XOR Filtering** into both **Sequential (`-S`)** and **Bidirectional Random (`-Random`)** search modes.

---

## 🔬 Mathematical & Cryptographic Architecture

### 1. Elliptic Curve Arithmetic (Secp256k1)
- **Curve Equation:** $y^2 = x^3 + 7 \pmod P$
- **Prime Finite Field:** $P = 2^{256} - 2^{32} - 977$ (`0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`)
- **Solinas / Pseudo-Mersenne Reduction (`ModMulK1`, `ModSquareK1`):** Exploits the special form of $P$ to replace 512-bit multi-precision modulo division with register-level additions and bit shifts on ARMv8-A vector hardware.

### 2. Montgomery Batch Inversion (`IntGroup::ModInv`)
- Converts 256 individual, computationally expensive modular inversions into **1 single inversion** per batch:
  $$\text{Batch Cost} = 1 \text{ ModInv} + 3 \times 256 \text{ ModMulK1}$$
- Reduces per-key computational overhead by **>95%**, boosting speed on Snapdragon processors from thousands to millions of keys per second per core.

### 3. Bidirectional Random Sweeping (`-Random`)
- **Impredecible Anchor Generation:** Every 5 seconds, worker threads generate a 256-bit random private key scalar $K_{rnd}$ in the requested range ($1-256$ bits) and calculate $P_{rnd} = \text{ComputePublicKey}(K_{rnd})$ **once**.
- **Bidirectional Montgomery Batches:** Sweeps forward ($+256$) and backward ($-256$) simultaneously from $P_{rnd}$ using precalculated forward (`step_table_fwd`) and backward (`step_table_bwd`) step tables.

---

## 🛠️ Components & Tools

### 1. `Address-Hash160` (Address Converter Utility)
Converts raw Bitcoin address text files (P2PKH, P2SH, Bech32) into 20-byte raw Hash160 hex strings stored in `BTC.hex`.

- **Input File:** Any plain text file containing Bitcoin addresses (e.g., `Test.txt`).
- **Output File:** `BTC.hex` (containing 40-character hex Hash160 strings).
- **Command Usage:**
  ```bash
  ./Address-Hash160 <input_address_file>
  ```

### 2. `CREATE-BIX` (Database Generator Utility)
Sorts, deduplicates, and compiles `BTC.hex` into high-speed binary database structures required by the engine.

- **Required Inputs:** `BTC.hex` (generated by `Address-Hash160`).
- **Generated Output Files:**
  - `BTC.bin`: Raw sorted 20-byte Hash160 binary table.
  - `BTC.idx`: Full (28 bytes/entry) or Sparse (24 bytes/block) index table.
  - `BTC.xor`: 3-hash non-block Constructive XOR Filter (~0.15% false-positive rejection).
- **Command Usage:**
  ```bash
  ./CREATE-BIX BTC.hex
  ```

### 3. `BTC` (Main Key Search Engine)
Performs high-speed multithreaded private key scanning against the compiled database files (`BTC.bin`, `BTC.idx`, `BTC.xor`).

- **Required Database Files:** `BTC.bin`, `BTC.idx`, `BTC.xor` in the current working directory.
- **Output Log:** Appends all found private keys, public keys, and derived address types to `FOUND.txt`. Search never stops on hit.
- **Command Flags:**
  - `-R <bits|all>`: Specifies search bit range ($1-256$) or `all` for full scan.
  - `-S`: Enables Sequential search mode.
  - `-Random`: Enables Bidirectional Random position jump mode (anchors every 5s).
  - `-t <threads>`: Number of worker threads (automatically pinned to Snapdragon Big-cores).
- **Command Usage:**
  ```bash
  ./BTC -R <bits> [-S|-Random] -t <threads>
  ```

---

## 📋 Execution & Console Log Examples

### 1. Converting Address File to `BTC.hex`
```text
root@localhost:~/BTCMobile# ./Address-Hash160 Test.txt
======================================================================
                 CONVERSION COMPLETE - SUMMARY
======================================================================
 Total Files Processed : 1
 Total Hashes Written  : 32
 BTC.hex File Size     : 0.00 MB (0.0000 GB)
 Total Execution Time  : 0.01 s
 Output Saved To       : BTC.hex
======================================================================
root@localhost:~/BTCMobile# ls -las
total 837
  3 drwxr-xr-x+                4 root root   3488 Oct 29 01:56 .
  4 drwx------+                3 root root  20480 Oct 29 01:15 ..
  3 drwxr-xr-x+                7 root root   3488 Oct 29 01:15 .git
 64 -rwxr-xr-x+                1 root root  74840 Oct 29 01:17 Address-Hash160
 20 -rw-r--r--+                1 root root  16998 Oct 29 01:15 Address-Hash160.cpp
324 -rwxr-xr-x+                1 root root 363888 Oct 29 01:17 BTC
 44 -rw-r--r--+                1 root root  44433 Oct 29 01:15 BTC.cpp
  4 -rw-r--r--+                1 root root   1312 Oct 29 01:56 BTC.hex
288 -rwxr-xr-x+                1 root root 292912 Oct 29 01:17 CREATE-BIX
 16 -rw-r--r--+                1 root root  14703 Oct 29 01:15 CREATE-BIX.cpp
  4 -rw-r--r--+                1 root root   1948 Oct 29 01:15 Makefile
  4 -rw-r--r--+                1 root root     11 Oct 29 01:15 README.md
  3 drwxr-xr-x+                3 root root   3488 Oct 29 01:15 Secp256k1
 48 -rw-r--r--+                1 root root  48544 Oct 29 01:15 Test.hex
  4 -rw-r--r--+                1 root root   2684 Oct 29 01:15 VERIFICATION.txt
root@localhost:~/BTCMobile#
```

---

### 2. Creating Full Index Database (`CREATE-BIX Option A`)
```text
root@localhost:~/BTCMobile# ./CREATE-BIX BTC.hex

============================================================
CREATE-BIX index format selection
============================================================
Option A: Full Index (28 bytes/entry)
Option B: Sparse Index (24 bytes/block)
Choice [A/B]: a
[DEBUG] BTC.bin: 32 hashes, 640 bytes
[DEBUG] BTC.idx: 32 entries, 896 bytes, format FULL
[DEBUG] First hash in BTC.bin: 0959e80121f36aea13b3bad361c15dac26189e2f
[OK] Creation completed successfully.
root@localhost:~/BTCMobile#
```

---

### 3. Creating Sparse Index Database (`CREATE-BIX Option B`)
```text
root@localhost:~/BTCMobile# ./CREATE-BIX BTC.hex

============================================================
CREATE-BIX index format selection
============================================================
Option A: Full Index (28 bytes/entry)
Option B: Sparse Index (24 bytes/block)
Choice [A/B]: b
[DEBUG] BTC.bin: 32 hashes, 640 bytes
[DEBUG] BTC.idx: 1 entries, 24 bytes, format SPARSE
[DEBUG] First hash in BTC.bin: 0959e80121f36aea13b3bad361c15dac26189e2f
[OK] Creation completed successfully.
root@localhost:~/BTCMobile#
```

---

### 4. Running Sequential Search Mode (`./BTC -R 25 -S -t 4`)
```text
root@localhost:~/BTCMobile# ./BTC -R 25 -S -t 4
[INFO] Select storage for BTC.bin : [1] RAM  [2] Disk MMAP
Choice [1-2]: 1
[INFO] Select storage for BTC.idx : [1] RAM  [2] Disk MMAP
Choice [1-2]: 1
[INFO] Select storage for BTC.xor : [1] RAM  [2] Disk MMAP
Choice [1-2]: 1

[INFO] Storage modes selected:
[INFO] BTC.bin : RAM
[INFO] BTC.idx : RAM
[INFO] BTC.xor : RAM
[INFO] Formato FULL verificado: 1174 entradas, 23480 bytes bin
[DIAG] Testing privkey 1:
[DIAG]   hash160 compressed  : 751e76e8199196d454941c45d1b3a323f1433bd6
[DIAG]   hash160 uncompressed: 91b24bf9f5288532960ac687abb035127b1d28a5
[DIAG]   expected compressed : 751e76e8199196d454941c45d1b3a323f1433bd6
[DIAG]   expected uncompressed: 91b24bf9f5288532960ac687abb035127b1d28a5
[DIAG]   match compressed    : yes
[DIAG]   match uncompressed  : yes
[DIAG]   xor_contains(comp)  : yes
[DIAG]   xor_contains(uncomp): no
[DIAG]   idx_lookup(comp)    : found=520 / not_found
[DIAG]   idx_lookup(uncomp)  : not_found=520 / not_found
-|<.>BTCMobile Zoey Alejandroo JF >
-|<.>\_____________________________________/
-|<.>.................................................................
-|<.>.Mode : SEQUENTIAL FORWARD >
-|<.>\_____________________________________/
-|<.>.................................................................
-|<.>.Range : 25/256 >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.Bits >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.0x01000000 >
-|<.>\________________________________________________________________/
-|<.>..................................................................
-|<.>.0x02000000 >
-|<.>\________________________________________________________________/
-|<.>..................................................................
-|<.>.Range Progrese/s >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.[==========================>------] 77.55% >
-|<.>\________________________________________________________________/
-|<.>..................................................................
-|<.>.[Thread 1: 96,832 keys/s ].-|<.>|-.[Thread 2: 106,174 keys/s ] >
-|<.>\________________________________________________________________/
-|<.>.[Thread 3: 112,653 keys/s ].-|<.>|-.[Thread 4: 112,516 keys/s ] >
-|<.>\________________________________________________________________/
-|<.>..................................................................
-|<.>.In 15/s [Total 13009920 Key/s ] >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.[Xor-Filter : 0.15] >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.[Found : 3 ] >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>...........................................................................
-|<.>.FOUND KEY >
-|<.>...........................................................................
-|<.>.Private Key : 0000000000000000000000000000000000000000000000000000000001000000 >
-|<.>.Hash160 Comp : 7620305cb19c2d3aab1d14605703f7f08f15d3b8 >
-|<.>.Hash160 Uncomp : 26e0fbd614d2ad7e49d25b74e360a3b8a0dbfaa0 >
-|<.>.BTC P2PKH Comp : 13ftDKrJheh9fsqCgbMPMxdZzakxgCYmukgKaneAmSRYS1Nf >
-|<.>.BTC P2PKH Uncomp : 1syevD9SM3kNmtHoRPYVYX2o55QUmkhtEuFoFi9uuwzrLs9 >
-|<.>.BTC P2SH-P2WPKH : aQ1ppKTAakaqTsdvYeX6LnFHdHemQWMqu7wESeaH34K9HzP >
-|<.>.BTC Bech32 P2WPKH : bc1qwcsrqh93nskn42caz3s9wqlh7z83t5actcsw9 >
-|<.>.ETH Address : 0x43c183126d60d36af2e806a42a34a39cfe0c2af7 >
-|<.>.Range : 25/256 >
-|<.>.Subrange : 0 >
-|<.>.Timestamp : 2026-10-29 05:00:16 UTC >
-|<.>...........................................................................
-|<.>...........................................................................
-|<.>.FOUND KEY >
-|<.>...........................................................................
-|<.>.Private Key : 000000000000000000000000000000000000000000000000000000000153aa72 >
-|<.>.Hash160 Comp : 8ba0b04a507c3cdad6b0bfd808c9a14e71ff2010 >
-|<.>.Hash160 Uncomp : af0ee90b19e1f3e7d5d4bb828a38778ea360cdc1 >
-|<.>.BTC P2PKH Comp : 14A5PeYAdUss4AJs9TiVvjdi7eZTkujybLFQDZRqCftgt4QP >
-|<.>.BTC P2PKH Uncomp : 14xXovs5u2X8B3Mmp9JoZB6k8aFWdGxhsAoWfvfeA53iqS3y >
-|<.>.BTC P2SH-P2WPKH : XAAMVoyhgGowPfmjYKrwR6bpw23w6M3bV6csNyMAEDABHZZ >
-|<.>.BTC Bech32 P2WPKH : bc1q3wstqjjs0s7d444shlvq3jdpfecl7gqskp4t7 >
-|<.>.ETH Address : 0xa1fe77cc6dbfe0345a8f1f04cab0c685b58fca3d >
-|<.>.Range : 25/256 >
-|<.>.Subrange : 2 >
-|<.>.Timestamp : 2026-10-29 05:00:28 UTC >
-|<.>...........................................................................
-|<.>...........................................................................
-|<.>.FOUND KEY >
-|<.>...........................................................................
-|<.>.Private Key : 00000000000000000000000000000000000000000000000000000000017fffff >
-|<.>.Hash160 Comp : 99a2f276eec7e3154ddfef00df10a026623661fe >
-|<.>.Hash160 Uncomp : 1fa6c6a73b179747b0c9850659d4eb248a502458 >
-|<.>.BTC P2PKH Comp : 14USjSfbxe94a83gzr4u2q4KZ3pV8hWttcPk29PBpZqsMG63 >
-|<.>.BTC P2PKH Uncomp : 1iW2aeSh1UGqZRJsWDA32MvWKC83idapGhga2AyDShfHCFh >
-|<.>.BTC P2SH-P2WPKH : aNui7hmQSymkPR9bgreT13fybZiU4CXS1wxABZ4EqnrAQ8P >
-|<.>.BTC Bech32 P2WPKH : bc1qnx30yahwcl332nwlauqd7y9qye3rvc07vldkg >
-|<.>.ETH Address : 0x3c43f9618b0f0e2f5e9d25f3f9b7c0188228bc36 >
-|<.>.Range : 25/256 >
-|<.>.Subrange : 3 >
-|<.>.Timestamp : 2026-10-29 05:00:35 UTC >
-|<.>...........................................................................
[OK] Rango 25 completado: 5 match(es)
root@localhost:~/BTCMobile#
```

---

### 5. Running Bidirectional Random Search Mode (`./BTC -R 25 -Random -t 4`)
```text
root@localhost:~/BTCMobile# ./BTC -R 25 -Random -t 4
[INFO] Select storage for BTC.bin : [1] RAM  [2] Disk MMAP
Choice [1-2]: 1
[INFO] Select storage for BTC.idx : [1] RAM  [2] Disk MMAP
Choice [1-2]: 1
[INFO] Select storage for BTC.xor : [1] RAM  [2] Disk MMAP
Choice [1-2]: 1

[INFO] Storage modes selected:
[INFO] BTC.bin : RAM
[INFO] BTC.idx : RAM
[INFO] BTC.xor : RAM
[INFO] Formato FULL verificado: 1174 entradas, 23480 bytes bin
[DIAG] Testing privkey 1:
[DIAG]   hash160 compressed  : 751e76e8199196d454941c45d1b3a323f1433bd6
[DIAG]   hash160 uncompressed: 91b24bf9f5288532960ac687abb035127b1d28a5
[DIAG]   expected compressed : 751e76e8199196d454941c45d1b3a323f1433bd6
[DIAG]   expected uncompressed: 91b24bf9f5288532960ac687abb035127b1d28a5
[DIAG]   match compressed    : yes
[DIAG]   match uncompressed  : yes
[DIAG]   xor_contains(comp)  : yes
[DIAG]   xor_contains(uncomp): no
[DIAG]   idx_lookup(comp)    : found=520 / not_found
[DIAG]   idx_lookup(uncomp)  : not_found=520 / not_found
-|<.>BTCMobile Zoey Alejandroo JF >
-|<.>\_____________________________________/
-|<.>.................................................................
-|<.>.Mode : RANDOM >
-|<.>\_____________________________________/
-|<.>.................................................................
-|<.>.Range : 25/256 >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.Bits >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.0x01000000 >
-|<.>\________________________________________________________________/
-|<.>..................................................................
-|<.>.0x02000000 >
-|<.>\________________________________________________________________/
-|<.>..................................................................
-|<.>.Search Type:Bidireccional-Random-Posittions >
-|<.>\_____________________________________/
     ....••●●      .....••●       ....••●       ....••●●      ....•
••●       ....••●●      ....••●●      .....••●       ....••●
....•••●      .....••●       ....••●●      ....••●●      .....••●
     ....••●●      ....•••●      .....••●       ....••●●      ....•
••●       ....••●       ....••●●      ....•••●      .....••●
....••●●      .....••●       ....••●       ....••●●      ....•••●
-|<.>\________________________________________________________________/
-|<.>..................................................................
-|<.>.[Thread 1: 100,664 keys/s ].-|<.>|-.[Thread 2: 126,509 keys/s ] >
-|<.>\________________________________________________________________/
-|<.>.[Thread 3: 115,520 keys/s ].-|<.>|-.[Thread 4: 124,745 keys/s ] >
-|<.>\________________________________________________________________/
-|<.>..................................................................
-|<.>.In 15/s [Total 7056384 Key/s ] >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.[Xor-Filter : 0.14] >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>.[Found : 4 ] >
-|<.>\_____________________________________/
-|<.>..................................................................
-|<.>...........................................................................
-|<.>.FOUND KEY >
-|<.>...........................................................................
-|<.>.Private Key : 0000000000000000000000000000000000000000000000000000000001ffffff >
-|<.>.Hash160 Comp : fcbefcf56d2c599f9b9a024cc4f4c5641c40466b >
-|<.>.Hash160 Uncomp : 39e64796ee0c31616227e4e87e19c878674df08c >
-|<.>.BTC P2PKH Comp : 16iPoXq6bxokRU2Dvb63edy3jc8M6i8wVGmMZYtUhEhZ9ers >
-|<.>.BTC P2PKH Uncomp : 12Jv8w6rxPzMCsRciJY5zjvwRyteFMVjmks4tPfpMAVPByeF >
-|<.>.BTC P2SH-P2WPKH : bb7WbV7DSrGuZ1Y7iCGeEAsaKiS6QxWEJL3yXLuEPxtiB3m >
-|<.>.BTC Bech32 P2WPKH : bc1qljl0eatd93velxu6qfxvfax9vswyq3nt30xfn >
-|<.>.ETH Address : 0xf83836de733521e50fd39b347caa00e0ef0e4466 >
-|<.>.Range : 25/256 >
-|<.>.Subrange : 3 >
-|<.>.Timestamp : 2026-10-29 05:01:32 UTC >
-|<.>...........................................................................
-|<.>...........................................................................
-|<.>.FOUND KEY >
-|<.>...........................................................................
-|<.>.Private Key : 0000000000000000000000000000000000000000000000000000000001fa5ee5 >
-|<.>.Hash160 Comp : 2f396b29b27324300d0c59b17c3abc1835bd3dbb >
-|<.>.Hash160 Uncomp : f9f514300900e45d6fcc2b568ce857d5033f4b2d >
-|<.>.BTC P2PKH Comp : 124vJqL1Xdrx8AKtrSbTzx3Yy3CFLXNvvVRKQWaSNXJYoGvb >
-|<.>.BTC P2PKH Uncomp : 16ejjAMgSBKt2MJC4kr5UGxt4hRmWQZfnoC1Ha16UAC9kmTM >
-|<.>.BTC P2SH-P2WPKH : bMFDmuh6gaGgr6yqu9JwGP23qxMLNUdcoPHWgn2eCxByoCB >
-|<.>.BTC Bech32 P2WPKH : bc1q9uukk2djwvjrqrgvtxchcw4urq6m60dmqs3gm >
-|<.>.ETH Address : 0xa96e58a5ca39ed6baf8bc7692e7d79df039fbcb8 >
-|<.>.Range : 25/256 >
-|<.>.Subrange : 3 >
-|<.>.Timestamp : 2026-10-29 05:01:33 UTC >
-|<.>...........................................................................
-|<.>...........................................................................
-|<.>.FOUND KEY >
-|<.>...........................................................................
-|<.>.Private Key : 0000000000000000000000000000000000000000000000000000000001000000 >
-|<.>.Hash160 Comp : 7620305cb19c2d3aab1d14605703f7f08f15d3b8 >
-|<.>.Hash160 Uncomp : 26e0fbd614d2ad7e49d25b74e360a3b8a0dbfaa0 >
-|<.>.BTC P2PKH Comp : 13ftDKrJheh9fsqCgbMPMxdZzakxgCYmukgKaneAmSRYS1Nf >
-|<.>.BTC P2PKH Uncomp : 1syevD9SM3kNmtHoRPYVYX2o55QUmkhtEuFoFi9uuwzrLs9 >
-|<.>.BTC P2SH-P2WPKH : aQ1ppKTAakaqTsdvYeX6LnFHdHemQWMqu7wESeaH34K9HzP >
-|<.>.BTC Bech32 P2WPKH : bc1qwcsrqh93nskn42caz3s9wqlh7z83t5actcsw9 >
-|<.>.ETH Address : 0x43c183126d60d36af2e806a42a34a39cfe0c2af7 >
-|<.>.Range : 25/256 >
-|<.>.Subrange : 1 >
-|<.>.Timestamp : 2026-10-29 05:01:36 UTC >
-|<.>...........................................................................
-|<.>...........................................................................
-|<.>.FOUND KEY >
-|<.>...........................................................................
-|<.>.Private Key : 000000000000000000000000000000000000000000000000000000000153aa72 >
-|<.>.Hash160 Comp : 8ba0b04a507c3cdad6b0bfd808c9a14e71ff2010 >
-|<.>.Hash160 Uncomp : af0ee90b19e1f3e7d5d4bb828a38778ea360cdc1 >
-|<.>.BTC P2PKH Comp : 14A5PeYAdUss4AJs9TiVvjdi7eZTkujybLFQDZRqCftgt4QP >
-|<.>.BTC P2PKH Uncomp : 14xXovs5u2X8B3Mmp9JoZB6k8aFWdGxhsAoWfvfeA53iqS3y >
-|<.>.BTC P2SH-P2WPKH : XAAMVoyhgGowPfmjYKrwR6bpw23w6M3bV6csNyMAEDABHZZ >
-|<.>.BTC Bech32 P2WPKH : bc1q3wstqjjs0s7d444shlvq3jdpfecl7gqskp4t7 >
-|<.>.ETH Address : 0xa1fe77cc6dbfe0345a8f1f04cab0c685b58fca3d >
-|<.>.Range : 25/256 >
-|<.>.Subrange : 0 >
-|<.>.Timestamp : 2026-10-29 05:01:36 UTC >
-|<.>...........................................................................
```

---

## ⚡ Build Instructions

To clean and compile all targets (`BTC`, `CREATE-BIX`, `Address-Hash160`):

```bash
make clean && make
```
Telegram – where you can find files and suggestions.
https://t.me/privatekeyfinderio

Web: https://privatekeyfinder.io/downloads

Web: http://addresses.loyce.club/

Credits and Acknowledgments


This project (BTCMobile) was developed and written completely from scratch, with an exclusive focus on ARM architecture and performance on mobile devices (Termux/Android). No code has been copied from other projects.


## 5. License & Attribution

This project is licensed under the **Apache License, Version 2.0**.

Third-party cryptographic implementations retain their original licenses:
- `Secp256k1/keccak.c` & `keccak.h`: Copyright (c) 2015 Taylor R. Campbell (BSD 2-Clause License).
- `Secp256k1/xxhash.c` & `xxhash.h`: Copyright (C) 2012-2020 Yann Collet (BSD 2-Clause License).
- `Secp256k1/sse2neon.h`: Copyright (c) 2015-2026 SSE2NEON Contributors (MIT License).
=======
However, the logical architecture and algorithmic design decisions of this tool were inspired after studying and analyzing the following excellent open-source projects:

Keyhunt: https://github.com/albertobsd/keyhunt
Inspired the approach and logic for extreme speed optimization in range scanning. 

BitCrack: https://github.com/brichard19/BitCrack
Inspired the strict validation methodology and brute-force structure to ensure no key is missed. 

Brainflayer: https://github.com/ryancdotorg/brainflayer/tree/master
Inspired the fast filtering concepts (adapted here into a custom XOR + IDX filter format instead of Bloom). 

I thank their authors and the open-source community for sharing their knowledge.

Third-Party Libraries

This project uses the following open source header files, which maintain their own original copyrights and licenses:

sse2neon.h: Used for the translation of SSE SIMD instructions to NEON on ARM. (See the Copyright and license notice within the file itself). 

xxhash.h: Used for fast data hashing. (See the Copyright and license notice within the file itself). 



Donations ☕

SEGWIT-BTC: bc1q4aqcpzlde5emla6c504pj9fn3jazsfetk8fgvp

ETH: 0x755d370be94a8b904d66539886f8a933067adf22

BNB-BSC: 0x755d370be94a8b904d66539886f8a933067adf22
