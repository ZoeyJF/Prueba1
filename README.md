
# BTCMobile - High-Performance Cryptography & Dual-Search Suite

High-performance cryptographic search engine and database generation suite written in **C++17**, optimized for **ARM64 / Android Termux / Linux** mobile devices and high-end workstations.

The suite provides a complete pipeline from raw address parsing and deduplication to database indexing and multi-threaded dual-network key search across **Ethereum** and **Bitcoin**.

---

## Architecture Overview

```text
+-----------------------------------------------------------------------------------+
| 1. Address-Hash160: Universal Address Parser, Sorter & Deduplicator                |
|    - Inputs: Any file format, layout, or extension (6 GB to 60+ GB)               |
|    - Extracts: ETH (0x...), BTC P2PKH (1...), P2SH (3...), SegWit (bc1...), Hex  |
|    - Bounded-RAM external merge sort (< 100 MB RAM) -> BTC.hex (unique hashes)    |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 2. CREATE-BIX: Scalable 64-bit Database Engine                                    |
|    - Reads: BTC.hex                                                               |
|    - Generates: BTC.bin (sorted 20-byte binary hashes)                            |
|                 BTC.idx (Option 1: Full 28B / Option 2: Sparse 24B with IDX_MAGIC)|
|                 BTC.xor (3-hash XOR filter for O(1) membership testing)           |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 3. BTC: Dual Ethereum & Bitcoin Search Engine                                     |
|    - Storage Options: Interactive RAM buffer vs 64-bit Disk MMAP (mmap64)         |
|    - Math Architecture: Solinas reduction (secp256k1) + Montgomery Batch Invert  |
|    - CPU Topology: Core frequency detection -> pins threads to Big/Prime cores     |
|    - Dual Pipeline: ETH (Keccak-256) FIRST -> BTC (Hash160 comp/uncomp) SECOND    |
|    - Search Modes: -S (Sequential forward) & -Random (Bidirectional sweep 5s)     |
|    - Real-Time Dashboard: Instant startup render + 15s refresh + 2-cycle match UI  |
+-----------------------------------------------------------------------------------+
```

---

## MODULE 1: `Address-Hash160.cpp` (Universal Address Parser & Sorter)

### Purpose & Functionality
`Address-Hash160` reads one or multiple arbitrary input files of any size (from a few MB up to 60+ GB), robustly extracts all valid cryptocurrency addresses and raw hashes, sorts them lexicographically via strict byte-by-byte comparison (`memcmp`), removes duplicates, and streams the unique 20-byte payloads into `BTC.hex`.

### Syntax
```bash
./Address-Hash160 <input_file_1> [input_file_2 ... input_file_N]
```

### Supported Formats & Token Parsing
The parser scans token by token, ignoring extraneous columns, balances, dates, timestamps, brackets, or commas:
1. **Bitcoin P2PKH (`1...`) & P2SH (`3...`):**
   - Decodes Base58 to 25 bytes.
   - Computes double SHA-256 (`SHA256(SHA256(payload))`) to verify the 4-byte checksum.
   - Extracts the 20-byte Hash160 payload.
2. **Bitcoin SegWit Bech32 (`bc1q...`) & Bech32m (`bc1p...`):**
   - Decodes BIP173 / BIP350 polymod checksum.
   - Converts 5-bit groups into 8-bit witness program bytes.
   - Validates the 20-byte program payload.
3. **Ethereum Addresses:**
   - Detects 40-character hex strings with or without `0x` / `0X` prefix.
   - Verifies valid hex characters and decodes into 20 bytes.
4. **Raw Hash160:**
   - Directly parses 40-character hexadecimal strings.

### Bounded-RAM External Merge Sort (OOM Elimination)
To prevent Out-Of-Memory (OOM) termination on mobile devices when handling massive files (e.g. 5 files between 6 GB and 12 GB, totaling 220+ million addresses):
- Extracted hashes accumulate in RAM up to **2,000,000 hashes** (~40 MB).
- Each chunk is sorted and deduplicated in RAM via `std::sort` with `memcmp` and `std::unique`, then flushed as binary data to a temporary file (`$TMPDIR/addr_chunk_*.tmp`).
- Once all files are scanned, an **external k-way merge sort** streams through all chunks using a min-priority queue with 64 KB per-stream buffers.
- Total peak RAM consumption remains **under 100 MB** regardless of total input size.

### Output (`BTC.hex`)
Unique 20-byte hashes written as 40 lowercase hexadecimal characters per line.

---

## MODULE 2: `CREATE-BIX.cpp` (Database Generator)

### Purpose & Functionality
`CREATE-BIX` transforms `BTC.hex` into high-performance binary structures for instant lookup during search operations: `BTC.bin`, `BTC.idx`, and `BTC.xor`.

### Syntax
```bash
# Interactive mode (prompts for Full vs Sparse index):
./CREATE-BIX BTC.hex

# Direct automated flags:
./CREATE-BIX BTC.hex --full
./CREATE-BIX BTC.hex --sparse
```

### Generated Files
1. **`BTC.bin`**:
   - Contiguous, sorted binary file containing 20-byte Hash160 entries ($N \times 20$ bytes).
   - Produced via external chunked merge sort.
2. **`BTC.idx`**:
   - Index file with an explicit 32-byte header:
     - `magic`: `0x49445831` (`IDX_MAGIC`, ASCII "IDX1")
     - `format_type`: `1` (Full Index) or `2` (Sparse Index)
     - `total_hashes`: Total count of 20-byte hashes
     - `record_count`: Number of index entries
     - `stride`: Stride size (64 for sparse, 1 for full)
     - `entry_size`: Entry size (28 bytes for full, 24 bytes for sparse)
   - **Option 1 (Full Index):** 28 bytes per entry (`hash[20]` + `uint64_t record_index`). Allows binary search directly in `.idx`.
   - **Option 2 (Sparse Index):** 24 bytes per entry (`hash[20]` + `uint32_t record_index`). Indexes every 64th entry, reducing index size by ~98%.
3. **`BTC.xor`**:
   - 3-hash XOR filter built over the 20-byte hashes.
   - Provides $O(1)$ negative-membership testing with false positive rates $< 0.01\%$, eliminating disk and index queries for >99.99% of non-matching private keys.

### 64-bit Scalability
All offsets, record indices, and file pointers strictly use `uint64_t` and 64-bit POSIX I/O (`pread64`, `pwrite64`), supporting databases from 1 GB to over 60 GB without integer overflow.

---

## MODULE 3: `BTC.cpp` (Dual Ethereum & Bitcoin Search Engine)

### Interactive Storage Selection
At startup, `BTC` prompts for storage mode on each database file:
```text
[INFO] Select storage for BTC.bin : [1] RAM [2] Disk MMAP
[INFO] Select storage for BTC.idx : [1] RAM [2] Disk MMAP
[INFO] Select storage for BTC.xor : [1] RAM [2] Disk MMAP
```
- **Option [1] RAM**: Allocates heap memory and loads files entirely into RAM. For files > 2 GB, uses chunked 64-bit `pread64` transfers.
- **Option [2] Disk MMAP**: Memory-maps files using 64-bit `mmap64` with `MAP_PRIVATE`. Enables searches on 60 GB+ databases on devices with only 4 GB to 8 GB of physical RAM.

### Command-Line Arguments
```bash
./BTC -R <range_num> [-S | -Random] [-t <threads>]
```
- `-R <1-256>`: Defines the search bit-range $[2^{R-1}, 2^R - 1]$.
- `-S`: Sequential forward search from range start to end.
- `-Random`: Bidirectional random search that anchors threads across the range, sweeps forward and backward around anchor points for 5 seconds, and re-anchors to new positions.
- `-t <threads>`: Thread count (capped to 32 and bound to Big/Prime cores).
- Unrecognized flags trigger a concise English usage guide.

### Mathematical & Cryptographic Architecture
1. **Solinas Special Reduction for secp256k1:**
   - Elliptic curve prime $p = 2^{256} - 2^{32} - 977$.
   - Generic divisions are replaced by fast multiplication and carry propagation using the constant $0x1000003d1$.
2. **Montgomery Batch Inversion (`IntGroup`):**
   - For every block of **512 keys**, computes only **1 single modular inversion** ($a^{p-2} \pmod p$).
   - Calculates affine coordinates $(X, Y)$ for all 512 points simultaneously using precomputed step tables.
3. **Contiguous Key Striding (Zero-Skip Guarantee):**
   - In `-S` mode, thread $T$ begins at $K_{\text{start}} + (T \times 512)$ and steps by $512 \times \text{num\_threads}$.
   - Every single private key in the range is processed without overlapping or skipping.
4. **Hardware Topology & Thermal Management:**
   - Reads `/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq`.
   - Identifies high-performance Big/Prime cores and sets CPU affinity using `pthread_setaffinity_np`.
   - Prevents worker threads from running on power-saving Little cores, avoiding thermal throttling on mobile devices.

### Dual-Network SIMD Verification Pipeline
For every point $P = (X, Y)$ generated:

```text
                        Point P = (X, Y)
                               |
               +---------------+---------------+
               |                               |
               v                               v
     [Step 1: Ethereum]              [Step 2: Bitcoin]
     Uncompressed (X, Y) (64B)       Compressed (02/03 + X)
               |                     Uncompressed (04 + X + Y)
               v                               |
          Keccak-256                           v
               |                          SHA-256 -> RIPEMD-160
               v                               |
          Last 20 Bytes                        v
               |                           Hash160
               +---------------+---------------+
                               |
                               v
                     Query BTC.xor Filter
                               | (Negative: skip instantly)
                               v (Positive: <0.01% hits)
                     Binary Search BTC.idx
                               |
                               v
                     Confirm in BTC.bin
                               |
                               v
                   MATCH FOUND: Log & Display
                   - ETH: 0x...
                   - BTC: P2PKH Comp/Uncomp, P2SH, Bech32
                   - Append to FOUND.txt
                   - Keep searching without stopping
```

### Dashboard Display (Every 15 Seconds)
- Renders the initial frame **immediately upon startup** (no initial 15-second delay).
- Refreshes every 15 seconds using non-destructive cursor repositioning (`\033[F\033[J`).
- Layout details:
  * Header banner: `-|<.>.BTCMobile Zoey Alejandroo JF >`
  * Mode: `SEQUENTIAL FORWARD` or `RANDOM`
  * Range: `R/256` and bit boundaries in hexadecimal
  * Range Progress bar (`[========>------------------------] XX.XX%`)
  * Individual thread speeds: `[Thread X: N keys/s]`
  * Cumulative speed: `In 15/s [Total N Key/s]` (strictly monotonic)
  * Filter performance: `[Xor-Filter : 0.00%]`
  * Match counter: `[Found : N]`
- Matches remain visible in the dashboard for 2 update cycles (30 seconds) while permanently recorded in `FOUND.txt`.

---

## Build System (`Makefile`)

Targeting C++17 with `-O3 -pthread`:
```bash
# Build all components:
make

# Build individual targets:
make BTC
make CREATE-BIX
make Address-Hash160

# Clean build artifacts:
make clean
```

### Hardware Flags Auto-Detection
- **x86_64 / i686**: `-mssse3 -DSSE2NEON_H -include tmmintrin.h`
- **ARM64 / aarch64**: `-march=armv8-a+crypto`
- **Generic / Non-SSE**: `-DNO_SSE`

---

## Quick Start Example

```bash
# 1. Parse raw address files into unique hashes:
./Address-Hash160 addresses_eth.txt addresses_btc.txt

# 2. Build the database (Full Index):
./CREATE-BIX BTC.hex --full

# 3. Start dual search on range 71 with 4 Big-core threads in Sequential mode:
./BTC -R 71 -S -t 4
```
=======
# BTCMobile - High-Performance Mobile Bitcoin Engine

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

