# HDFS Read-Path Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make random/positional reads from libhdfs3 cheap (no over-fetch, connection reuse, no per-read NameNode RPC, thread-safe), and switch the DuckDB `hadoopfs` extension to use them.

**Architecture:** Add `pread` (positional, stateless, thread-safe) to `InputStreamImpl` by running the existing read state machine on a private per-call worker whose block-reader request length is capped at the requested range. When a `RemoteBlockReader` consumes its whole range it sends the read status, so its socket goes back to `PeerCache`. Cache the `DataEncryptionKey` in `FileSystemImpl`, which removes one NameNode RPC from every block-reader setup. Tighten forward-seek skipping, and decrypt in place in `CryptoSocketReader`.

**Tech Stack:** C++17, CMake, gtest/gmock 1.7 (vendored), OpenSSL EVP, protobuf; single-node Hadoop 3.0.0 in Docker for integration; DuckDB extension (`../hadoopfs`) for end-to-end checks.

## Global Constraints

- Repos and branches: `libhdfs3` from `vengine`, `hadoopfs` from `vengine-1.3.2`. Both use the new branch `perf/read-path`.
- Do not commit. The user has not asked for commits, so leave changes uncommitted on the branch and report the diff.
- Do not overwrite `~/.local` (shared install prefix). Stage libhdfs3 installs to `/tmp/libhdfs3-stage`.
- Keep the C API backward compatible. Only add symbols; never change existing signatures.
- `hdfsPread` signature must match Apache libhdfs: `tSize hdfsPread(hdfsFS fs, hdfsFile file, tOffset position, void * buffer, tSize length);`
- Match the existing code style: 4-space indent, `THROW`/`NESTED_THROW`, `LOG(...)`, `shared_ptr` from `Memory.h`.
- Test cluster: `/tmp/hdfs-test/start.sh false` (container `libhdfs3-it`, NameNode `127.0.0.1:9000`, replication 1). Remove the container and `/tmp/hdfs-test` at the end.

---

### Task 1: Restore the unit-test build (prerequisite)

At HEAD, `make unit` fails before any of our changes. `-Dprivate=public` breaks libstdc++ 11's `<sstream>`, and mocks/tests have drifted from `src/`. Known root causes (from `make -k unit`):

| Error | Fix |
|---|---|
| `__xfer_bufptrs redeclared with different access` | `test/CMakeLists.txt`: replace `-Dprivate=public -Dprotected=public` with `-fno-access-control` (GCC/Clang flag with the same intent) |
| `MockFileSystemInter` abstract: `getDataEncryptionKey` pure | `mock/MockFileSystemInter.h`: add `MOCK_METHOD0(getDataEncryptionKey, Hdfs::Internal::DataEncryptionKey());` |
| `MockBufferedSocketReader` has no default ctor | `mock/MockBufferedSocketReader.h`: add `MockBufferedSocketReader() : Hdfs::Internal::BufferedSocketReader(std::shared_ptr<Hdfs::Internal::Socket>()) {}` |
| `TestRpcChannelStub.h`: `RpcChannel` unknown | add `#include "rpc/RpcChannel.h"` |
| `TestRpcChannel.cpp:59` `BuildKey` too many args | forward-declare `RpcChannelKey BuildKey(SessionConfig & session);` above the zero-arg overload |
| `TestCryptoSocket.cpp` / `TestDataTransferSaslClient.cpp`: `HdfsIOException`/`SaslException` not a type | add `using namespace Hdfs;` (and the missing exception header if needed) |

**Files:** `test/CMakeLists.txt`, `mock/MockFileSystemInter.h`, `mock/MockBufferedSocketReader.h`, `mock/TestRpcChannelStub.h`, `test/unit/TestRpcChannel.cpp`, `test/unit/TestCryptoSocket.cpp`, `test/unit/TestDataTransferSaslClient.cpp`

- [ ] Step 1: Apply the fixes above. Re-run `cd build && cmake .. && make -k -j8 unit 2>&1 | grep ' error: '` and fix any newly surfaced compile/link error of the same kind (stale mock vs. current interface). Do not change `src/` behavior in this task.
- [ ] Step 2: Run `cd build/test/unit && ./unit 2>&1 | tail -40`. Record the pre-existing runtime failures in the final report; do not fix or delete them.
- [ ] Stop rule: if compile errors remain after fixing every root cause of the kinds listed above, record them and fall back to driver-based verification for Tasks 3 and 6.

### Task 2: Benchmark/verifier with random-read modes, plus baseline

**Files:** Modify `hdfs_benchmark/main.cpp`, `hdfs_benchmark/CMakeLists.txt`, `CMakeLists.txt:89`

**Produces:** the binary `build/hdfs_benchmark/hdfs_benchmark` with these modes:
- `-m write -s BYTES --block-size BYTES` writes a pattern file. The file is made of little-endian `uint64_t` words, and the word at byte offset `o` (with `o % 8 == 0`) has the value `o`.
- `-m seq` keeps the existing behavior.
- `-m seek -r N -b SIZE --seed S` performs N reads at random offsets using `hdfsSeek` + `hdfsRead` loops.
- `-m pread -r N -b SIZE -j THREADS` performs N random `hdfsPread` reads split across THREADS threads that share **one** `hdfsFile`. Only built when `HAVE_HDFS_PREAD` is defined; Task 4 defines it in `hdfs.h`.
- `--verify` checks every byte returned against the pattern and exits 2 on mismatch.
- `--no-sc` disables short-circuit reads.
- Output: ops, MiB/s, avg latency, and `lo rx bytes` delta (`/sys/class/net/lo/statistics/rx_bytes`; the test HDFS uses host networking, so DN→client traffic is on `lo`).

- [ ] Step 1: `CMakeLists.txt`: replace `# ADD_SUBDIRECTORY(hdfs_benchmark)` with `OPTION(BUILD_HDFS_BENCHMARK "Build hdfs_benchmark" OFF)` + `IF(BUILD_HDFS_BENCHMARK) ADD_SUBDIRECTORY(hdfs_benchmark) ENDIF()`. `hdfs_benchmark/CMakeLists.txt`: drop the x86-only `-march=native -msse -msse2` and `-std=c++11` (the parent sets C++17), and link `pthread libhdfs3-shared`.
- [ ] Step 2: Implement the modes in `main.cpp`. Keep the existing `seq` code path. Use `std::mt19937_64(seed)` for offsets in `[0, fileSize - SIZE]`. Short reads are only allowed at EOF.
- [ ] Step 3: Build: `cmake -DBUILD_HDFS_BENCHMARK=ON .. && make -j8 hdfs_benchmark`.
- [ ] Step 4: Start the test cluster and write test data:
  `hdfs_benchmark -m write -f /bench/f64m -s 67108864 --block-size 8388608` (64 MiB in 8 blocks) and `-f /bench/odd -s 9437191 --block-size 1048576` (not word-aligned at the end, which exercises EOF).
- [ ] Step 5: Record a baseline in the plan's results section, with and without `--no-sc`:
  `seq`, and `seek -r 2000 -b 65536 --seed 1 --verify`. Pread is not available yet.

### Task 3: Cache the DataEncryptionKey in FileSystemImpl

**Files:** Modify `src/client/FileSystemImpl.h`, `src/client/FileSystemImpl.cpp:612-617`; Test: `test/unit/TestDataEncryptionKeyCache.cpp` (new) if Task 1 succeeded.

**Interfaces:** `FileSystemImpl::getDataEncryptionKey()` keeps the same signature and becomes thread-safe and cached.

Rule: refetch when there is no cached key, or when `key.getExpiryDate() != 0 && nowMs >= expiryDate - 60000`, or when `key.getExpiryDate() == 0 && nowMs - fetchedAtMs >= 600000`. The expiry-0 case means encryption is disabled; the NameNode returns an empty key, and we re-check it every 10 minutes.

```cpp
// FileSystemImpl.h (private)
    mutex dataEncryptionKeyMutex;
    bool hasDataEncryptionKey = false;
    DataEncryptionKey dataEncryptionKey;
    steady_clock::time_point dataEncryptionKeyFetchedAt;

// FileSystemImpl.cpp
DataEncryptionKey FileSystemImpl::getDataEncryptionKey() {
    if (!nn) {
        THROW(HdfsIOException, "FileSystemImpl: not connected.");
    }

    lock_guard<mutex> lock(dataEncryptionKeyMutex);
    int64_t now = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    bool expired = !hasDataEncryptionKey;

    if (!expired && dataEncryptionKey.getExpiryDate() != 0) {
        expired = now >= static_cast<int64_t>(dataEncryptionKey.getExpiryDate()) - 60 * 1000;
    } else if (!expired) {
        expired = ToMilliSeconds(dataEncryptionKeyFetchedAt, steady_clock::now()) >= 600 * 1000;
    }

    if (expired) {
        dataEncryptionKey = nn->getDataEncryptionKey();
        dataEncryptionKeyFetchedAt = steady_clock::now();
        hasDataEncryptionKey = true;
    }

    return dataEncryptionKey;
}
```

- [ ] Step 1: Write the test first. Construct a `FileSystemImpl` with a `MockNamenode` (see `mock/MockNamenode.h`; if it lacks `getDataEncryptionKey`, add `MOCK_METHOD0`). Expect `getDataEncryptionKey` called **once** across 3 calls when the expiry is far in the future, and called again when the expiry is in the past. Run it and confirm it FAILS (called 3 times).
- [ ] Step 2: Implement the code above. Run the test and confirm it PASSES.
- [ ] Step 3: Integration check: `seek -r 2000 --verify` passes. With `dfs.client.log.severity=DEBUG1`, the NameNode RPC log shows a single `getDataEncryptionKey`.

### Task 4: `pread` — positional, bounded, thread-safe read

**Files:** Modify `src/client/InputStreamInter.h`, `src/client/InputStream.h/.cpp`, `src/client/InputStreamImpl.h/.cpp`, `src/client/hdfs.h`, `src/client/Hdfs.cpp`.

**Interfaces (produced):**
- `virtual int32_t InputStreamInter::pread(char * buf, int32_t size, int64_t position) = 0;`
- `int32_t Hdfs::InputStream::pread(char * buf, int32_t size, int64_t position);`
- `tSize hdfsPread(hdfsFS fs, hdfsFile file, tOffset position, void * buffer, tSize length);`. It returns the number of bytes read, which is less than `length` only at EOF, 0 if `position >= file length`, and -1 with errno on error. It does not move the file position, and it is safe to call concurrently on the same `hdfsFile` from multiple threads (not concurrently with `hdfsRead`/`hdfsSeek` on that handle).
- `#define HAVE_HDFS_PREAD 1` in `hdfs.h`.

Design:
1. New member `int64_t readLimit` in `InputStreamImpl`, initialized to `std::numeric_limits<int64_t>::max()` and restored in `close()`. In `setupBlockReader`, change the length computation to
   ```cpp
   int64_t blockEnd = curBlock->getOffset() + curBlock->getNumBytes();
   len = (readLimit < blockEnd ? readLimit : blockEnd) - cursor;
   ```
   The sequential path is unchanged because `readLimit` is max. A bounded `RemoteBlockReader` reads exactly through `endOffset`, then `readNextPacket()` consumes the trailing empty packet and `sendStatus()`, so its destructor returns the socket to `PeerCache`.
2. New members `mutex preadMutex; shared_ptr<LocatedBlocks> preadLbs;`. `preadLbs` is a block-location cache shared by pread callers and is separate from the sequential `lbs`.
3. `pread` builds a private worker `InputStreamImpl` per call, so retry, failover, short-circuit and under-construction handling are all reused unchanged:
   ```cpp
   int32_t InputStreamImpl::pread(char * buf, int32_t size, int64_t position) {
       checkStatus();

       if (position < 0) {
           THROW(InvalidParameter, "InputStreamImpl: invalid pread position %" PRId64 " for file %s.",
                 position, path.c_str());
       }

       InputStreamImpl worker;
       worker.filesystem = filesystem;
       worker.conf = conf;
       worker.auth = auth;
       worker.path = path;
       worker.verify = verify;
       worker.localRead = localRead;
       worker.maxGetBlockInfoRetry = maxGetBlockInfoRetry;
       worker.prefetchSize = prefetchSize;
       worker.peerCache = peerCache;
       worker.hostname = hostname;
   #ifdef MOCK
       worker.stub = stub;
   #endif
       {
           lock_guard<mutex> lock(preadMutex);
           if (preadLbs) {
               worker.lbs = shared_ptr<LocatedBlocksImpl>(
                   new LocatedBlocksImpl(static_cast<const LocatedBlocksImpl &>(*preadLbs)));
               worker.lastBlockBeingWrittenLength = preadLastBlockBeingWrittenLength;
           }
       }
       worker.cursor = position;
       worker.readLimit = position + size;
       worker.closed = false;
       int32_t done = 0;

       try {
           while (done < size) {
               done += worker.readInternal(buf + done, size - done);
           }
       } catch (const HdfsEndOfStream & e) {
           // short read at EOF
       }

       {
           lock_guard<mutex> lock(preadMutex);
           preadLbs = worker.lbs;
           preadLastBlockBeingWrittenLength = worker.lastBlockBeingWrittenLength;
       }
       return done;
   }
   ```
   (`preadLastBlockBeingWrittenLength` is an `int64_t` member next to `preadLbs`. `readInternal` already refreshes `lbs` when `cursor` is outside the cached range. `HdfsEndOfStream` after `done == 0` means `position >= length`, so return 0. Other exceptions propagate and do **not** set the parent's `lastError`.)
   Before writing this, confirm `LocatedBlocksImpl` is copy-constructible (`src/client/LocatedBlocks.h`). If it is not, add a defaulted copy ctor.
4. `InputStream::pread` forwards to `impl->pread`. `hdfsPread` follows `hdfsRead`'s error handling: `PARAMETER_ASSERT(fs && file && buffer && length > 0 && position >= 0, -1, EINVAL)` and `PARAMETER_ASSERT(file->isInput(), -1, EINVAL)`, and maps `HdfsEndOfStream` to 0.

- [ ] Step 1: Test first (if Task 1 succeeded), in `test/unit/UnitTestInputStream.cpp`: calling `pread` on a closed stream throws `HdfsIOException`, and calling it with `position < 0` throws `InvalidParameter`. Run and confirm a compile FAIL (no `pread`).
- [ ] Step 2: Implement items 1–4. Run the unit tests and confirm they PASS.
- [ ] Step 3: Rebuild `hdfs_benchmark` (now with `HAVE_HDFS_PREAD`). Run `pread -r 2000 -b 65536 -j 1 --verify` and `-j 8 --verify` on `/bench/f64m`, plus `pread -r 2000 -b 1500000 --verify` on `/bench/odd` (cross-block and EOF). All must exit 0.
- [ ] Step 4: Evidence of connection reuse: run with `dfs.client.log.severity=DEBUG1` and `--no-sc`, then count `PeerCache hit` vs `PeerCache miss`. Expect hits to dominate. Compare the `lo rx bytes` of pread against the seek baseline for the same `-r/-b/--seed`; expect roughly `N × SIZE`.
- [ ] Step 5: Sequential regression: `seq --verify` passes.

### Task 5: Bounded forward skip in `seekInternal`

A remote reader currently skips any forward distance inside the block by downloading and checksumming the gap. Mirror Java `DFSInputStream`: skip only if the gap is `<= max(blockReader->available(), 128 KiB)` (Java's `TCP_WINDOW_SIZE`). Otherwise drop the reader. Local short-circuit readers always skip, because their skip is an mmap seek.

**Files:** Modify `src/client/InputStreamImpl.cpp` (`seekInternal`).

```cpp
static const int64_t MAX_REMOTE_SKIP_BYTES = 128 * 1024;
...
        if (blockReader && pos > cursor && pos < endOfCurBlock) {
            int64_t gap = pos - cursor;
            bool local = dynamic_cast<LocalBlockReader *>(blockReader.get()) != NULL;

            if (local || gap <= std::max(blockReader->available(), MAX_REMOTE_SKIP_BYTES)) {
                blockReader->skip(gap);
                cursor = pos;
                return;
            }
        }
```

- [ ] Step 1: Test first (if Task 1 succeeded): with a gmock `BlockReader` (`MOCK_METHOD1(skip, void(int64_t))`, `MOCK_METHOD0(available, int64_t())` returning 0) installed as `ins.blockReader`, plus `cursor=0`, `endOfCurBlock=8MiB` and a non-null `lbs` whose `getFileLength` is 8 MiB: `seek(64KiB)` calls `skip(65536)`, while `seek(4MiB)` does not call `skip` and leaves `blockReader` null. Confirm it FAILS before the change.
- [ ] Step 2: Implement. The test PASSES.
- [ ] Step 3: Benchmark `seek -r 2000 -b 65536 --seed 1 --verify --no-sc`. Compare `lo rx bytes` and MiB/s with the baseline.

### Task 6: In-place decryption in `CryptoSocketReader`

**Files:** Modify `src/network/CryptoSocketReader.h/.cpp`; Test: `test/unit/TestCryptoSocket.cpp`.

```cpp
// header: replace decrypt(std::string&, const std::string_view&) with
    void decrypt(char * buf, int32_t size);

// cpp
void CryptoSocketReader::decrypt(char * buf, int32_t size) {
    if (size <= 0) {
        return;
    }
    int updateOutSize = 0;
    unsigned char * p = reinterpret_cast<unsigned char *>(buf);
    if (1 != EVP_DecryptUpdate(evpCipherCtx, p, &updateOutSize, p, size)
            || updateOutSize != size) {
        THROW(HdfsIOException, "Decrypt data error!");
    }
}

int32_t CryptoSocketReader::read(char * b, int32_t s) {
    int32_t size = underlyingSocket->read(b, s);
    decrypt(b, size);
    return size;
}

void CryptoSocketReader::readFully(char * b, int32_t s, int timeout) {
    underlyingSocket->readFully(b, s, timeout);
    decrypt(b, s);
}
```

AES-CTR is a stream mode, so `EVP_DecryptUpdate` with `in == out` is supported and output length equals input length.

- [ ] Step 1: Add the test `TestCryptoSocket.ReadPartialChunksContinuity`: encrypt 40 bytes with an `EVP_aes_128_ctr` context. The mock `read` returns them in chunks of 7, 13, and 20 bytes, and the concatenated plaintext must match. This test passes on the old code too; it is a regression guard. Run it and confirm it PASSES before the change.
- [ ] Step 2: Implement. `TestCryptoSocket.*` all PASS.

### Task 7: hadoopfs positional reads use `hdfsPread`

**Files:** Modify `../hadoopfs/src/hadoopfs.cpp` (`ReadFromHDFS(handle, buffer, nr_bytes, location)`).

```cpp
    int64_t HadoopFileSystem::ReadFromHDFS(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location)
    {
        auto &hfh = dynamic_cast<HadoopFileHandle &>(handle);
        int64_t read_byte_count = 0;
        while (read_byte_count < nr_bytes)
        {
            void *offset_buffer = static_cast<char *>(buffer) + read_byte_count;
            tSize todo = static_cast<tSize>(std::min<int64_t>(nr_bytes - read_byte_count, std::numeric_limits<tSize>::max()));
            auto length = hdfsPread(hfh.hdfs, hfh.hdfs_file, location + read_byte_count, offset_buffer, todo);
            ... (keep existing TRACE logs / error log / break)
        }
        return read_byte_count;
    }
```

`read_byte_count` changes from `auto ... = 0` (int) to `int64_t`. The old code truncated reads larger than 2 GiB.

- [ ] Step 1: Stage libhdfs3: `cd libhdfs3/build && make -j8 && make install DESTDIR=/tmp/libhdfs3-stage`. Headers and lib land under `/tmp/libhdfs3-stage/home/vincent/.local`.
- [ ] Step 2: Edit hadoopfs, then build against the staged copy: `cmake -DLIBHDFS3_INCLUDE_DIR=<stage>/include -DLIBHDFS3_LIBRARIES=<stage>/lib/libhdfs3.so build/release && ninja -C build/release hadoopfs_loadable_extension vengine-cli` (confirm target names with `ninja -C build/release -t targets | grep hadoopfs`).
- [ ] Step 3: E2E: create a ~200 MB Parquet file locally with `vengine-cli` (`COPY (SELECT range AS id, hash(range) AS h, range::VARCHAR AS s FROM range(20000000)) TO '/tmp/hdfs-test/t.parquet'`), `docker cp` it into the container, then `hdfs dfs -put` it to `/bench/t.parquet`. With `LD_LIBRARY_PATH=<stage>/lib` and `SET hdfs_default_namenode='127.0.0.1:9000'`, run `SELECT count(*), sum(h), max(s) FROM 'hdfs://127.0.0.1:9000/bench/t.parquet'` and one projected/filtered query. Results must equal the same queries on the local file. Record wall time and `lo rx bytes`. For the before/after comparison, run the same queries with the old extension build and the old `~/.local` lib (the stock `build/release` output kept from before Step 2, copied to `/tmp/hadoopfs-old.duckdb_extension`).
- [ ] Step 4: Reset the hadoopfs CMake cache to `~/.local` paths (`cmake -DLIBHDFS3_INCLUDE_DIR=$HOME/.local/include -DLIBHDFS3_LIBRARIES=$HOME/.local/lib/libhdfs3.so build/release`). Note in the report that hadoopfs on this branch requires the new libhdfs3 to be installed.

### Task 8: Final measurements, diagnostics, cleanup

- [ ] Re-run the Task 2 matrix (`seq`, `seek`, `pread -j1`, `pread -j8`, with and without SC) and fill in the results table below.
- [ ] Run `lsp_diagnostics` on the changed files, the `libhdfs3` full build (exit 0), and `unit` (compare to the Task 1 baseline).
- [ ] Clean up: `docker rm -f libhdfs3-it`, `rm -rf /tmp/hdfs-test /tmp/libhdfs3-stage /tmp/hadoopfs-old.duckdb_extension /tmp/*.log` (only files this work created).

## Out of scope (recorded, not done)

- Enlarging `BufferedSocketReader`: `readFully` already bypasses the buffer for large reads, so the earlier suggestion would not save copies.
- `readv` direct-to-user-buffer for remote reads, hedged reads, `SO_RCVBUF` tuning, async I/O, and `CryptoSocketWriter` buffer reuse.
- Integration testing with Kerberos/SASL encryption. The local cluster uses simple auth, which never takes the SASL/crypto path, so Task 6 is covered by unit tests only.

## Results

Single-node HDFS 3.0.0 (Docker, host network), aarch64 8 cores. Every row was first run with `--verify` and passed. The MiB/s figures come from a second run without verify. "lo rx" is the loopback bytes received during the timed run.

| Scenario | Baseline MiB/s | Baseline lo rx | After MiB/s | After lo rx |
|---|---|---|---|---|
| seq 64 MiB, remote (`--no-sc`) | 317.7 | 67.9 MB | 325.5 | 67.8 MB |
| seek 2000×64 KiB, remote | 44.0 | 2997 MB | 83.7 | 3009 MB |
| **pread 2000×64 KiB, remote, 1 thread** | — | — | **187.8** | **135 MB** |
| **pread 2000×64 KiB, remote, 8 threads, one handle** | — | — | **505.8** | 135 MB |
| seek 500×1.5 MB cross-block, remote | 268.6 | 1002 MB | 293.0 | 1009 MB |
| pread 500×1.5 MB cross-block, remote, 4 threads | — | — | 1214.9 | 760 MB |
| seq 64 MiB, short-circuit | 332.0 | — | 336.7 | — |
| seek 2000×64 KiB, short-circuit | 24.4 | — | 25.0 | — |
| pread 2000×64 KiB, short-circuit, 8 threads | — | — | 136.3 | — |

hadoopfs E2E (DuckDB, 8 threads, 328 MB Parquet, remote path; results identical to the local file):

| Query | Old time / lo rx | New time / lo rx |
|---|---|---|
| full scan `count, sum(h), max(s)` | 0.34 s / 336 MiB | 0.31 s / 240 MiB |
| `WHERE id BETWEEN …` (row-group pruning) | 0.09 s / 34.8 MiB | 0.09 s / 23.4 MiB |
| `WHERE s = …` (single column) | 0.09 s / 43.5 MiB | 0.09 s / 21.1 MiB |
