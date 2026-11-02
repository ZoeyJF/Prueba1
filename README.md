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
