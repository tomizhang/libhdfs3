#include <iostream>
#include <getopt.h>

#include <string.h>
#include "../src/client/hdfs.h"

#include <atomic>
#include <cassert>
#include <fstream>
#include <inttypes.h>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace std;

// On Mac OS X clock_gettime is not available
#ifdef __MACH__

#include <mach/mach_time.h>

#define CLOCK_MONOTONIC 0

int clock_gettime(int clk_id, struct timespec *t) {
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t time;
    time = mach_absolute_time();
    double nseconds = ((double) time * (double) timebase.numer) / ((double) timebase.denom);
    double seconds = ((double) time * (double) timebase.numer) / ((double) timebase.denom * 1e9);
    t->tv_sec = seconds;
    t->tv_nsec = nseconds;
    return 0;
}

#endif

#define EXPECT_NONZERO(r, func) if(r==NULL) { \
                                    fprintf(stderr, "%s failed: %s\n", func, hdfsGetLastError()); \
                                    exit(1); \
                                }

#define EXPECT_NONNEGATIVE(r, func) if(r < 0) { \
                                    fprintf(stderr, "%s failed: %s\n", func, hdfsGetLastError()); \
                                    exit(1); \
                                }

timespec timespec_diff(timespec start, timespec end) {
    timespec temp;
    if ((end.tv_nsec - start.tv_nsec) < 0) {
        temp.tv_sec = end.tv_sec - start.tv_sec - 1;
        temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    } else {
        temp.tv_sec = end.tv_sec - start.tv_sec;
        temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return temp;
}

static double now_seconds() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

typedef enum {
    undefined = 0, standard, scr, zcr
} type_t;

typedef enum {
    mode_seq = 0, mode_write, mode_seek, mode_pread
} mode_t_;

struct {
    const char *path = NULL;
    const char *socket = "/var/lib/hadoop-hdfs/dn_socket";
    const char *namenode = "localhost";
    int namenode_port = 9000;
    size_t buffer_size = 4096;
    int verbose = false;
    int skip_checksums = false;
    int sample = false;
    type_t type = type_t::undefined;
    mode_t_ mode = mode_seq;
    int64_t file_size = 64LL * 1024 * 1024;
    int64_t block_size = 0;
    int reads = 1000;
    int threads = 1;
    uint64_t seed = 1;
    int verify = false;
    int no_sc = false;
    const char *log_severity = NULL;
} options;

void print_usage() {
    printf("hdfs_benchmark -f FILE [-m MODE] [-b BUFFER_SIZE] [-t TYPE] [-n NAMENODE] [-p NAMENODE_PORT]\n"
                   "  -f, --file           File to read/write\n"
                   "  -m, --mode           One of seq (default), write, seek, pread\n"
                   "  -b, --buffer         Buffer / read size, defaults to 4096\n"
                   "  -t, --type           One of standard, sc, zcr\n"
                   "  -n, --namenode       Namenode hostname, default: localhost\n"
                   "  -p, --namenode-port  Namenode port, default: 9000\n"
                   "  -s, --size           File size for write mode, default: 64MiB\n"
                   "      --block-size     Block size for write mode\n"
                   "  -r, --reads          Number of random reads for seek/pread, default: 1000\n"
                   "  -j, --threads        Threads for pread mode (sharing one file handle), default: 1\n"
                   "      --seed           Random seed, default: 1\n"
                   "      --verify         Verify the data against the pattern written by write mode\n"
                   "      --no-sc          Disable short-circuit read\n"
                   "      --log            libhdfs3 log severity, e.g. DEBUG1\n"
                   "  -v, --verbose        Verbose output, e.g. statistics, formatted speed\n"
                   "  -x, --sample         Sample the copy speed every 1s\n");
}

void parse_options(int argc, char *argv[]) {

    static struct option options_config[] = {
            {"file",           required_argument, 0,                       'f'},
            {"buffer",         required_argument, 0,                       'b'},
            {"help",           no_argument,       0,                       'h'},
            {"type",           required_argument, 0,                       't'},
            {"socket",         required_argument, 0,                       'S'},
            {"namenode",       required_argument, 0,                       'n'},
            {"namenode-port",  required_argument, 0,                       'p'},
            {"mode",           required_argument, 0,                       'm'},
            {"size",           required_argument, 0,                       's'},
            {"block-size",     required_argument, 0,                       'B'},
            {"reads",          required_argument, 0,                       'r'},
            {"threads",        required_argument, 0,                       'j'},
            {"seed",           required_argument, 0,                       'E'},
            {"log",            required_argument, 0,                       'L'},
            {"verbose",        no_argument,       &options.verbose,        1},
            {"sample",         no_argument,       &options.sample,         1},
            {"skip-checksums", no_argument,       &options.skip_checksums, 1},
            {"verify",         no_argument,       &options.verify,         1},
            {"no-sc",          no_argument,       &options.no_sc,          1},

            {0, 0,                                0,                       0}
    };

    int c = 0;
    while (c >= 0) {
        int option_index;
        c = getopt_long(argc, argv, "f:b:n:p:t:m:s:r:j:S:vxh", options_config, &option_index);

        switch (c) {
            case 'v':
                options.verbose = true;
                break;
            case 'f':
                options.path = optarg;
                break;
            case 'b':
                options.buffer_size = atoi(optarg);
                break;
            case 'n':
                options.namenode = optarg;
                break;
            case 'p':
                options.namenode_port = atoi(optarg);
                break;
            case 'h':
                print_usage();
                exit(1);
            case 'S':
                options.socket = optarg;
                break;
            case 'x':
                options.sample = true;
                break;
            case 's':
                options.file_size = atoll(optarg);
                break;
            case 'B':
                options.block_size = atoll(optarg);
                break;
            case 'r':
                options.reads = atoi(optarg);
                break;
            case 'j':
                options.threads = atoi(optarg);
                break;
            case 'E':
                options.seed = strtoull(optarg, NULL, 10);
                break;
            case 'L':
                options.log_severity = optarg;
                break;
            case 'm':
                if (strcmp(optarg, "seq") == 0) {
                    options.mode = mode_seq;
                } else if (strcmp(optarg, "write") == 0) {
                    options.mode = mode_write;
                } else if (strcmp(optarg, "seek") == 0) {
                    options.mode = mode_seek;
                } else if (strcmp(optarg, "pread") == 0) {
#ifdef HAVE_HDFS_PREAD
                    options.mode = mode_pread;
#else
                    printf("pread mode is not supported by this libhdfs3\n");
                    exit(1);
#endif
                } else {
                    printf("%s is not a valid mode\n", optarg);
                    exit(1);
                }
                break;
            case 't':
                if (strcmp(optarg, "standard") == 0) {
                    options.type = type_t::standard;
                } else if (strcmp(optarg, "scr") == 0) {
                    options.type = type_t::scr;
                } else if (strcmp(optarg, "zcr") == 0) {
                    options.type = type_t::zcr;
                } else {
                    printf("%s is not a valid type\n", optarg);
                    exit(1);
                }
                break;
            default:
                break;
        }
    }

    if (options.path == NULL) {
        print_usage();
        exit(1);
    }
}

inline void useData(void *buffer, tSize len) __attribute__((__always_inline__));

inline void useData(void *buffer, tSize len) {
    uint64_t sum = 0;
    for (size_t i = 0; i < len / sizeof(uint64_t); i++) {
        sum += *(((uint64_t *) buffer) + i);
    }
    assert(sum);
}

/*
 * The pattern file is a sequence of little-endian uint64_t words,
 * the word at byte offset o (o % 8 == 0) holds the value o.
 */
static inline char patternByte(int64_t offset) {
    uint64_t word = static_cast<uint64_t>(offset & ~7LL);
    return static_cast<char>((word >> ((offset & 7) * 8)) & 0xff);
}

static bool verifyPattern(const char *buf, int64_t offset, int64_t len) {
    for (int64_t i = 0; i < len; ++i) {
        if (buf[i] != patternByte(offset + i)) {
            fprintf(stderr, "verify failed at file offset %" PRId64 "\n", offset + i);
            return false;
        }
    }
    return true;
}

static int64_t loRxBytes() {
    std::ifstream in("/sys/class/net/lo/statistics/rx_bytes");
    int64_t v = 0;
    in >> v;
    return v;
}

static void report(const char *name, int64_t ops, int64_t bytes, double seconds, int64_t rx) {
    printf("mode=%s ops=%" PRId64 " bytes=%" PRId64 " time=%.3fs MiB/s=%.1f avg_latency_ms=%.3f lo_rx_bytes=%" PRId64 "\n",
           name, ops, bytes, seconds, bytes / seconds / (1024.0 * 1024.0),
           ops ? seconds * 1000.0 / ops : 0.0, rx);
}

static int runWrite(hdfsFS fs) {
    hdfsFile file = hdfsOpenFile(fs, options.path, O_WRONLY, 0, 0, options.block_size);
    EXPECT_NONZERO(file, "hdfsOpenFile")
    std::vector<char> buffer(1024 * 1024);
    int64_t written = 0;

    while (written < options.file_size) {
        int64_t todo = options.file_size - written;
        todo = todo < static_cast<int64_t>(buffer.size()) ? todo : buffer.size();

        for (int64_t i = 0; i < todo; ++i) {
            buffer[i] = patternByte(written + i);
        }

        tSize rc = hdfsWrite(fs, file, &buffer[0], static_cast<tSize>(todo));
        EXPECT_NONNEGATIVE(rc, "hdfsWrite")
        written += rc;
    }

    EXPECT_NONNEGATIVE(hdfsCloseFile(fs, file), "hdfsCloseFile")
    printf("wrote %" PRId64 " bytes to %s\n", written, options.path);
    return 0;
}

static std::vector<int64_t> randomOffsets(int64_t fileSize) {
    std::mt19937_64 rng(options.seed);
    int64_t maxOffset = fileSize - static_cast<int64_t>(options.buffer_size);
    maxOffset = maxOffset > 0 ? maxOffset : 0;
    std::uniform_int_distribution<int64_t> dist(0, maxOffset);
    std::vector<int64_t> offsets(options.reads);

    for (int i = 0; i < options.reads; ++i) {
        offsets[i] = dist(rng);
    }

    return offsets;
}

static int64_t expectedLength(int64_t offset, int64_t fileSize) {
    int64_t len = static_cast<int64_t>(options.buffer_size);
    return offset + len > fileSize ? fileSize - offset : len;
}

static int runSeek(hdfsFS fs, int64_t fileSize) {
    hdfsFile file = hdfsOpenFile(fs, options.path, O_RDONLY, 0, 0, 0);
    EXPECT_NONZERO(file, "hdfsOpenFile")
    std::vector<int64_t> offsets = randomOffsets(fileSize);
    std::vector<char> buffer(options.buffer_size);
    int64_t total = 0, rx = loRxBytes();
    double start = now_seconds();

    for (size_t i = 0; i < offsets.size(); ++i) {
        EXPECT_NONNEGATIVE(hdfsSeek(fs, file, offsets[i]), "hdfsSeek")
        int64_t want = expectedLength(offsets[i], fileSize), done = 0;

        while (done < want) {
            tSize rc = hdfsRead(fs, file, &buffer[done], static_cast<tSize>(want - done));
            EXPECT_NONNEGATIVE(rc, "hdfsRead")

            if (rc == 0) {
                break;
            }

            done += rc;
        }

        if (done != want) {
            fprintf(stderr, "short read at %" PRId64 ": %" PRId64 " of %" PRId64 "\n", offsets[i], done, want);
            return 2;
        }

        if (options.verify && !verifyPattern(&buffer[0], offsets[i], done)) {
            return 2;
        }

        total += done;
    }

    double seconds = now_seconds() - start;
    report("seek", offsets.size(), total, seconds, loRxBytes() - rx);
    hdfsCloseFile(fs, file);
    return 0;
}

#ifdef HAVE_HDFS_PREAD
static int runPread(hdfsFS fs, int64_t fileSize) {
    hdfsFile file = hdfsOpenFile(fs, options.path, O_RDONLY, 0, 0, 0);
    EXPECT_NONZERO(file, "hdfsOpenFile")
    std::vector<int64_t> offsets = randomOffsets(fileSize);
    std::atomic<int64_t> total(0), next(0);
    std::atomic<int> failed(0);
    int64_t rx = loRxBytes();
    double start = now_seconds();
    std::vector<std::thread> workers;

    for (int t = 0; t < options.threads; ++t) {
        workers.emplace_back([&]() {
            std::vector<char> buffer(options.buffer_size);
            int64_t i;

            while (!failed && (i = next++) < static_cast<int64_t>(offsets.size())) {
                int64_t want = expectedLength(offsets[i], fileSize);
                tSize rc = hdfsPread(fs, file, offsets[i], &buffer[0], static_cast<tSize>(options.buffer_size));

                if (rc < 0) {
                    fprintf(stderr, "hdfsPread failed: %s\n", hdfsGetLastError());
                    failed = 1;
                    return;
                }

                if (rc != want) {
                    fprintf(stderr, "short pread at %" PRId64 ": %d of %" PRId64 "\n", offsets[i], rc, want);
                    failed = 2;
                    return;
                }

                if (options.verify && !verifyPattern(&buffer[0], offsets[i], rc)) {
                    failed = 2;
                    return;
                }

                total += rc;
            }
        });
    }

    for (size_t t = 0; t < workers.size(); ++t) {
        workers[t].join();
    }

    if (failed) {
        return failed == 1 ? 1 : 2;
    }

    if (hdfsTell(fs, file) != 0) {
        fprintf(stderr, "hdfsPread moved the file position to %" PRId64 "\n", hdfsTell(fs, file));
        return 2;
    }

    char probe;

    if (hdfsPread(fs, file, fileSize, &probe, 1) != 0) {
        fprintf(stderr, "hdfsPread at EOF did not return 0\n");
        return 2;
    }

    double seconds = now_seconds() - start;
    report("pread", offsets.size(), total, seconds, loRxBytes() - rx);
    hdfsCloseFile(fs, file);
    return 0;
}
#endif

static int runSeq(hdfsFS fs) {
    hdfsFileInfo *fileInfo = hdfsGetPathInfo(fs, options.path);
    printf("Block size %i, %i\n", (int)fileInfo->mBlockSize, (int)hdfsGetDefaultBlockSize(fs));

    char ***hosts = hdfsGetHosts(fs, options.path, 0, fileInfo->mSize);
    EXPECT_NONZERO(hosts, "hdfsGetHosts")

    // Start Time
    struct timespec start, end;
    int64_t rx = loRxBytes();
    clock_gettime(CLOCK_MONOTONIC, &start);

    int64_t block = 0;
    for (block = 0; hosts[block]; block++) {
        if (options.verbose) {
            cout << "Block[" << block << "]" << endl;
        }
        uint j = 0;
        for (j = 0; hosts[block][j]; j++)
            if (options.verbose) {
                cout << "\t[" << j << "]: " << hosts[block][j] << endl;
            }

        // Open and read the file
        const char *hostname = hosts[block][j-1];
        hdfsFile file = hdfsOpenFile2(fs, hostname, options.path, O_RDONLY, options.buffer_size, 0, 0);
        //hdfsFile file = hdfsOpenFile(fs, options.path, O_RDONLY, options.buffer_size, 0, 0);
        EXPECT_NONZERO(file, "hdfsOpenFile")

        int64_t seek = fileInfo->mBlockSize*block;
        if (options.verbose) {
            printf("Seeking to %" PRId64 "\n", seek);
        }
        int r = hdfsSeek(fs, file, seek);
        EXPECT_NONNEGATIVE(r, "hdfsSeek")

        char *buffer = static_cast<char *>(malloc(options.buffer_size));
        int64_t read = 0, totalRead = 0;
        do {
            read = hdfsRead(fs, file, buffer, options.buffer_size);
            EXPECT_NONNEGATIVE(read, "hdfsRead")

            if (read > 0) {
                if (options.verify && !verifyPattern(buffer, seek + totalRead, read)) {
                    exit(2);
                }
                useData(buffer, read);
            }

            totalRead += read;
        } while (read > 0 && totalRead < fileInfo->mBlockSize);

        if (options.verbose) {
            printf("Read %" PRId64 "B from %s\n", totalRead, hostname);
        }

        free(buffer);
        hdfsCloseFile(fs, file);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    struct timespec d = timespec_diff(start, end);
    double seconds = (double) d.tv_sec + d.tv_nsec / 1000000000.0;
    report("seq", block, fileInfo->mSize, seconds, loRxBytes() - rx);

    hdfsFreeHosts(hosts);
    hdfsFreeFileInfo(fileInfo, 1);
    return 0;
}

int main(int argc, char *argv[]) {
    parse_options(argc, argv);

    if (options.verbose) {
        cout << "Namenode:  " << options.namenode << ":" << options.namenode_port << endl;
        cout << "Socket:    " << options.socket << endl;
        cout << "File:      " << options.path << endl;
        cout << "Buffer:    " << options.buffer_size << endl;
        cout << "Checksums: " << (options.skip_checksums ? "false" : "true") << endl;
        cout << "Type:      " << options.type << endl;
    }

    struct hdfsBuilder *hdfsBuilder = hdfsNewBuilder();
    hdfsBuilderSetNameNode(hdfsBuilder, options.namenode);
    hdfsBuilderSetNameNodePort(hdfsBuilder, options.namenode_port);
    if (options.no_sc) {
        hdfsBuilderConfSetStr(hdfsBuilder, "dfs.client.read.shortcircuit", "false");
    } else if (options.type == type_t::undefined || options.type == type_t::scr || options.type == type_t::zcr) {
        hdfsBuilderConfSetStr(hdfsBuilder, "dfs.client.read.shortcircuit", "true");
        hdfsBuilderConfSetStr(hdfsBuilder, "dfs.domain.socket.path", options.socket);
        // TODO Test
        //hdfsBuilderConfSetStr(hdfsBuilder, "dfs.client.domain.socket.data.traffic", "true");
        //hdfsBuilderConfSetStr(hdfsBuilder, "dfs.client.read.shortcircuit.streams.cache.size", "4000");
        hdfsBuilderConfSetStr(hdfsBuilder, "dfs.client.read.shortcircuit.skip.checksum",
                              options.skip_checksums > 0 ? "true" : "false");
    }
    if (options.log_severity) {
        hdfsBuilderConfSetStr(hdfsBuilder, "dfs.client.log.severity", options.log_severity);
    }

    // Connect
    hdfsFS fs = hdfsBuilderConnect(hdfsBuilder);
    EXPECT_NONZERO(fs, "hdfsBuilderConnect")
    int rc = 0;

    if (options.mode == mode_write) {
        rc = runWrite(fs);
    } else if (hdfsExists(fs, options.path) != 0) {
        printf("File %s does not exist\n", options.path);
        rc = 1;
    } else {
        hdfsFileInfo *fileInfo = hdfsGetPathInfo(fs, options.path);
        EXPECT_NONZERO(fileInfo, "hdfsGetPathInfo")
        int64_t fileSize = fileInfo->mSize;
        hdfsFreeFileInfo(fileInfo, 1);

        if (options.mode == mode_seek) {
            rc = runSeek(fs, fileSize);
#ifdef HAVE_HDFS_PREAD
        } else if (options.mode == mode_pread) {
            rc = runPread(fs, fileSize);
#endif
        } else {
            rc = runSeq(fs);
        }
    }

    hdfsDisconnect(fs);
    hdfsFreeBuilder(hdfsBuilder);

    return rc;
}
