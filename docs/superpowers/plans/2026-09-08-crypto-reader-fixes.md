# Encrypted Data Transfer Bugfix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `dfs.encrypt.data.transfer` / SASL-protected data-transfer reads and writes protocol-correct and defined-behavior, without changing PeerCache reuse of already-wrapped sockets.

**Architecture:** Keep the existing stack (`TcpSocket` → optional `WrapSocket(Crypto*|Sasl*)` → `BufferedSocketReader` / `DataTransferProtocolSender`). Fix the wrapping decision, SASL framing, AES-CTR streaming, and handshake parsing in place. Extract two small pure helpers (`Payload::Parse` already exists; add `chooseDataTransferQop` / `shouldWrapDataTransferSocket`) so the handshake policy can be unit-tested without a live DataNode.

**Tech Stack:** C++11/14, OpenSSL EVP AES-CTR, libgsasl DIGEST-MD5 (`qop-auth` / `qop-int` / `qop-conf`), Protobuf `CipherOptionProto`, gtest/gmock, existing `MockSocket`.

## Global Constraints

- Do **not** stop caching `WrapSocket` in `PeerCache`. AES-CTR / SASL state is per-connection; Hadoop `EncryptedPeer` does the same. MiniMax finding C2 is a false positive.
- Do **not** change `Socket::read()` short-read semantics (MiniMax H3 is not a bug).
- Do **not** add CBC/GCM or extra cipher suites. AES-CTR remains the only OpenSSL path; everything else stays on `SaslSocketReader/Writer`.
- libgsasl QOP **property strings stay** `qop-auth` / `qop-int` / `qop-conf`. Do not send Java `auth` / `auth-int` / `auth-conf` to `gsasl_property_set(GSASL_QOP, ...)`.
- Match existing code style: `THROW(Exception, "fmt", ...)`, `std::shared_ptr`, no `as any`-style suppression, no new dependencies.
- Unit tests live under `test/unit/`. `test/unit/CMakeLists.txt` currently does **not** link OpenSSL; Task 1 adds that.
- Do not commit unless the user later asks. Plan steps still say “Commit” so an executing agent knows the intended checkpoint; skip git commits until explicitly requested.
- `RemoteBlockReader` mutex cleanup (MiniMax H2) is optional polish at the end, not required for correctness.

## Out of scope

- PeerCache keying by user / encryption key / FileSystem instance (pre-existing, not introduced by crypto).
- Dead `dataEncryptionKey` members on CryptoSocket* (L1) beyond not using them for AES.
- Heap-allocation reuse in CryptoSocketReader (L4) except where Task 6 already touches `decrypt()`.
- Cluster/function tests against a live encrypted HDFS. Call those out as **manual verification** after unit tests.

## File map

| File | Role |
|------|------|
| `src/network/WrapSocket.h` | C1: return poll result; prefer reader poll on read-only |
| `src/network/SaslSocketReader.{h,cpp}` | C3 + N5 + N6: loop `readFully`, bound SASL frame, poll leftover plaintext |
| `src/network/SaslSocketWriter.cpp` | no protocol change; keep 4-byte length prefix |
| `src/network/CryptoSocketReader.{h,cpp}` | H1/M4 validation, N4 leak, CTR streaming (no per-packet Final) |
| `src/network/CryptoSocketWriter.{h,cpp}` | same validation/leak/CTR; N3 `write()` must emit full ciphertext |
| `src/client/DataTransferSaslClient.{h,cpp}` | N1 wrap decision, N7 QOP intersection, H1 reject empty cipher, N2 Parse bounds |
| `src/client/RemoteBlockReader.h` | optional: delete unused mutexes |
| `test/unit/CMakeLists.txt` | link OpenSSL for crypto unit tests |
| `test/unit/TestWrapSocket.cpp` | new |
| `test/unit/TestSaslSocketReader.cpp` | new |
| `test/unit/TestCryptoSocket.cpp` | new |
| `test/unit/TestDataTransferSaslClient.cpp` | new (Parse, QOP, wrap helpers) |

## Decision table (locked)

### When to wrap the socket after SASL

Wrap iff **any** of:

1. Negotiated libgsasl QOP is `qop-int` or `qop-conf`, or
2. Selected `CipherOptionProto.suite() == AES_CTR_NOPADDING` **and** in/out keys+IVs are present and correctly sized.

`dfs.encrypt.data.transfer=true` must force the handshake to request `qop-conf` (Hadoop). After a successful handshake that still has neither privacy/integrity QOP nor a valid AES-CTR option, **THROW** — do not return a bare `TcpSocket`.

### QOP selection (`chooseDataTransferQop`)

Inputs: client `dfs.data.transfer.protection`, `dfs.encrypt.data.transfer`, server DIGEST-MD5 `qop` list.

| Client protection | encrypt.data.transfer | Required GSASL_QOP | If server cannot offer it |
|-------------------|-----------------------|--------------------|---------------------------|
| (empty) | false | `qop-auth` | THROW |
| (empty) | true | `qop-conf` | THROW |
| `authentication` | false | `qop-auth` | THROW |
| `authentication` | true | `qop-conf` (encrypt wins) | THROW |
| `integrity` | false | `qop-int` | THROW |
| `integrity` | true | `qop-conf` (encrypt wins) | THROW |
| `privacy` | * | `qop-conf` | THROW |

Never upgrade (do not pick `qop-conf` just because the server advertised it). Never pick a QOP the server did not advertise.

Server advertisement parsing: `payload.qop` contains `auth`, `auth-int`, `auth-conf` (RFC 2831 wire tokens). Mapping to GSASL property: `auth`→`qop-auth`, `auth-int`→`qop-int`, `auth-conf`→`qop-conf`.

### AES-CTR streaming

- `EVP_CIPHER_CTX_set_padding(ctx, 0)` after init.
- Each `decrypt`/`encrypt` call: **only** `EVP_DecryptUpdate` / `EVP_EncryptUpdate`. Do **not** call `Final` per packet.
- Destructor may call `Final` once (ignore output) then `EVP_CIPHER_CTX_free`.
- Allocate `dst` as `src.size()` for CTR (block size 1; output length == input length). Delete the `if (updateOutSize > initSize) dst.resize(...)` branch.

### Cipher option validation

Before constructing CryptoSocket*:

- `outkey.size() == keyBitLength/8` and `outiv.size() == 16` (reader uses **out** key/iv — traffic from DN).
- `inkey.size() == keyBitLength/8` and `iniv.size() == 16` (writer uses **in** key/iv — traffic to DN).
- `keyBitLength` ∈ {128, 192, 256}.
- If handshake selected AES_CTR but keys are empty: THROW with sizes in the message. Do **not** invent a suite-only `CipherOptionProto`.

### SASL frame limit

Reject SASL length prefix `> 10 * 1024 * 1024` (same cap as `RemoteBlockReader::checkResponse`). THROW `HdfsIOException`, do not `resize` then OOM.

---

### Task 1: Unit-test build links OpenSSL

**Files:**
- Modify: `test/unit/CMakeLists.txt`

**Interfaces:**
- Consumes: existing `unit` target
- Produces: `unit` links `${OPENSSL_LIBRARIES}` and includes `${OPENSSL_INCLUDE_DIR}`

- [ ] **Step 1: Add OpenSSL to the unit test binary**

In `test/unit/CMakeLists.txt`, after the existing `INCLUDE_DIRECTORIES(${GSASL_INCLUDE_DIR})` line add:

```cmake
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
```

After `TARGET_LINK_LIBRARIES(unit ${GSASL_LIBRARIES})` add:

```cmake
TARGET_LINK_LIBRARIES(unit ${OPENSSL_LIBRARIES})
```

`src/CMakeLists.txt` already finds OpenSSL for the library; do not change that.

- [ ] **Step 2: Configure/build unit target**

```bash
# from the existing build directory, or:
mkdir -p build && cd build && ../bootstrap && make unit -j$(nproc)
```

Expected: `unit` links. If OpenSSL is missing, bootstrap already fails for the main library — do not add a new find_package.

- [ ] **Step 3: Checkpoint**

```bash
git add test/unit/CMakeLists.txt
git commit -m "test: link OpenSSL into the unit test binary"
```

Skip the commit if the user has not asked to commit.

---

### Task 2: C1 — `WrapSocket::poll` returns, and read-only poll uses the reader

**Files:**
- Modify: `src/network/WrapSocket.h` (poll, ~163–165)
- Modify: `src/network/SaslSocketReader.cpp` (`poll`)
- Modify: `src/network/CryptoSocketReader.cpp` (`poll` — keep forwarding; no buffer)
- Create: `test/unit/TestWrapSocket.cpp`

**Interfaces:**
- Consumes: `SocketReader::poll(int timeout)`, `Socket::poll(bool, bool, int)`
- Produces: `WrapSocket::poll` is defined-behavior and true if SASL plaintext remains

- [ ] **Step 1: Write failing tests**

Create `test/unit/TestWrapSocket.cpp`:

```cpp
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "MockSocket.h"
#include "network/WrapSocket.h"
#include "network/SocketReader.h"
#include "network/SocketWriter.h"

using namespace Hdfs::Internal;
using namespace testing;

class FakeReader : public SocketReader {
public:
    bool readable = false;
    int32_t read(char *, int32_t) override { return 0; }
    void readFully(char *, int32_t, int) override {}
    bool poll(int) override { return readable; }
};

class FakeWriter : public SocketWriter {
public:
    int32_t write(const char *, int32_t size) override { return size; }
    void writeFully(const void *, size_t, int) override {}
};

TEST(TestWrapSocket, PollReturnsUnderlyingValue) {
    auto sock = std::make_shared<MockSocket>();
    auto reader = std::make_shared<FakeReader>();
    auto writer = std::make_shared<FakeWriter>();
    WrapSocket wrap(sock, reader, writer);
    reader->readable = false;
    EXPECT_CALL(*sock, poll(false, true, 10)).WillOnce(Return(true));
    EXPECT_TRUE(wrap.poll(false, true, 10));
}

TEST(TestWrapSocket, ReadOnlyPollUsesReaderBuffer) {
    auto sock = std::make_shared<MockSocket>();
    auto reader = std::make_shared<FakeReader>();
    auto writer = std::make_shared<FakeWriter>();
    WrapSocket wrap(sock, reader, writer);
    reader->readable = true;
    EXPECT_CALL(*sock, poll(_, _, _)).Times(0);
    EXPECT_TRUE(wrap.poll(true, false, 10));
}
```

- [ ] **Step 2: Run tests — expect fail / UB currently**

```bash
./unit --gtest_filter=TestWrapSocket.*
```

Expected: `PollReturnsUnderlyingValue` fails or is flaky (missing `return`). `ReadOnlyPollUsesReaderBuffer` fails because poll always hits TCP.

- [ ] **Step 3: Implement `WrapSocket::poll`**

Replace the body in `src/network/WrapSocket.h`:

```cpp
inline bool poll(bool read, bool write, int timeout) {
    if (read && !write) {
        return socketReader->poll(timeout);
    }
    return underlyingSocket->poll(read, write, timeout);
}
```

- [ ] **Step 4: Implement `SaslSocketReader::poll` leftover check**

In `src/network/SaslSocketReader.cpp`, replace `poll`:

```cpp
bool SaslSocketReader::poll(int timeout){
    if (oStart < oFinish) {
        return true;
    }
    return underlyingSocket->poll(true, false, timeout);
}
```

Leave `CryptoSocketReader::poll` as `return underlyingSocket->poll(true, false, timeout);`.

- [ ] **Step 5: Re-run tests**

```bash
./unit --gtest_filter=TestWrapSocket.*
```

Expected: PASS.

- [ ] **Step 6: Checkpoint**

```bash
git add src/network/WrapSocket.h src/network/SaslSocketReader.cpp test/unit/TestWrapSocket.cpp
git commit -m "fix: WrapSocket::poll returns and honors SASL reader buffer"
```

---

### Task 3: N2 — `Payload::Parse` must not index `string[size()]`

**Files:**
- Modify: `src/client/DataTransferSaslClient.h` (`Payload::Parse`)
- Create: `test/unit/TestDataTransferSaslClient.cpp` (Parse tests first; later tasks append)

**Interfaces:**
- Consumes: DIGEST-MD5 challenge string (`realm=...,qop="auth,auth-conf",...`)
- Produces: `Payload` fields without UB on empty / exact-length input

- [ ] **Step 1: Write failing tests** at the top of `test/unit/TestDataTransferSaslClient.cpp`

```cpp
#include "gtest/gtest.h"
#include "client/DataTransferSaslClient.h"

using namespace Hdfs::Internal;

TEST(TestPayloadParse, EmptyString) {
    Payload p;
    Payload::Parse("", p);
    EXPECT_TRUE(p.realms.empty());
    EXPECT_TRUE(p.qop.empty());
}

TEST(TestPayloadParse, QuotedCommaInCipher) {
    Payload p;
    Payload::Parse(
        "realm=\"foo\",qop=\"auth,auth-conf\",algorithm=md5-sess,"
        "nonce=\"abc\",charset=utf-8,cipher=\"3des,rc4\"", p);
    ASSERT_EQ(1u, p.realms.size());
    EXPECT_EQ("foo", p.realms[0]);
    EXPECT_EQ("auth,auth-conf", p.qop);
    ASSERT_EQ(2u, p.cipher.size());
    EXPECT_EQ("3des", p.cipher[0]);
    EXPECT_EQ("rc4", p.cipher[1]);
}

TEST(TestPayloadParse, TrailingComma) {
    Payload p;
    Payload::Parse("realm=\"x\",", p);
    ASSERT_EQ(1u, p.realms.size());
    EXPECT_EQ("x", p.realms[0]);
}
```

- [ ] **Step 2: Run under ASan if available, else just run**

```bash
./unit --gtest_filter=TestPayloadParse.*
```

Expected: empty-string case is UB today (may crash or “pass”). Treat crash or ASan report as the fail.

- [ ] **Step 3: Rewrite `Payload::Parse` loop**

Replace the `while (end <= input.length())` loop in `src/client/DataTransferSaslClient.h` with an index-safe version. Keep the same field mapping (`realm`, `qop`, `algorithm`, `nonce`, `charset`, `cipher`, `rspauth`). Required shape:

```cpp
static inline void Parse(const std::string & input, Payload & payload) {
    std::string key, value;
    bool inQuotes = false;
    size_t start = 0;
    for (size_t end = 0; end <= input.size(); ++end) {
        const bool atEnd = end == input.size();
        if (!atEnd && input[end] == '"' && (end == 0 || input[end - 1] != '\\')) {
            inQuotes = !inQuotes;
        }
        if (atEnd || (!inQuotes && input[end] == ',')) {
            // existing token split / trim / field assign, using
            // input.substr(start, end - start)
            start = end + 1;
        }
    }
}
```

Do **not** call `input[end]` when `atEnd` is true.

- [ ] **Step 4: Re-run**

```bash
./unit --gtest_filter=TestPayloadParse.*
```

Expected: PASS.

- [ ] **Step 5: Checkpoint**

```bash
git add src/client/DataTransferSaslClient.h test/unit/TestDataTransferSaslClient.cpp
git commit -m "fix: bound-check DIGEST-MD5 payload parser"
```

---

### Task 4: N7 + N1 — QOP intersection and wrap decision

**Files:**
- Modify: `src/client/DataTransferSaslClient.h` (declare helpers + store negotiated QOP)
- Modify: `src/client/DataTransferSaslClient.cpp` (`selectSaslQop`, `doHandshake` wrap block, `selectCipherOption`)
- Modify: `test/unit/TestDataTransferSaslClient.cpp`

**Interfaces:**
- Produces:

```cpp
// in namespace Hdfs::Internal, declared in DataTransferSaslClient.h
std::string chooseDataTransferQop(
    const std::string & clientProtection, // dfs.data.transfer.protection
    bool encryptDataTransfer,
    bool serverAuth, bool serverInt, bool serverConf);
// returns "qop-auth" | "qop-int" | "qop-conf"; throws SaslException if impossible

bool shouldWrapDataTransferSocket(
    const std::string & negotiatedGsaslQop,
    bool hasValidAesCtrCipher);
```

- [ ] **Step 1: Write policy tests** (append to `TestDataTransferSaslClient.cpp`)

```cpp
TEST(TestChooseQop, EmptyProtectionNoEncryptIsAuth) {
    EXPECT_EQ("qop-auth", chooseDataTransferQop("", false, true, true, true));
}

TEST(TestChooseQop, EmptyProtectionDoesNotUpgradeToConf) {
    EXPECT_EQ("qop-auth", chooseDataTransferQop("", false, true, true, true));
}

TEST(TestChooseQop, EncryptForcesConf) {
    EXPECT_EQ("qop-conf", chooseDataTransferQop("", true, true, true, true));
}

TEST(TestChooseQop, IntegrityWithoutServerIntThrows) {
    EXPECT_THROW(chooseDataTransferQop("integrity", false, true, false, true),
                 SaslException);
}

TEST(TestChooseQop, PrivacyRequiresConf) {
    EXPECT_EQ("qop-conf", chooseDataTransferQop("privacy", false, true, true, true));
}

TEST(TestShouldWrap, AuthWithoutAesDoesNotWrap) {
    EXPECT_FALSE(shouldWrapDataTransferSocket("qop-auth", false));
}

TEST(TestShouldWrap, ConfAlwaysWraps) {
    EXPECT_TRUE(shouldWrapDataTransferSocket("qop-conf", false));
}

TEST(TestShouldWrap, AesCtrWrapsEvenIfQopAuth) {
    EXPECT_TRUE(shouldWrapDataTransferSocket("qop-auth", true));
}
```

Include `"common/Exception.h"` / `"common/ExceptionInternal.h"` as other unit tests do.

- [ ] **Step 2: Run — expect link failure** (`chooseDataTransferQop` undefined)

- [ ] **Step 3: Implement helpers** in `DataTransferSaslClient.cpp` (not anonymous namespace — tests need the symbols). Case-insensitive compare of `clientProtection` against `authentication` / `integrity` / `privacy` using existing `strcasecmp`.

Logic:

```cpp
std::string chooseDataTransferQop(const std::string & clientProtection,
                                  bool encryptDataTransfer,
                                  bool serverAuth, bool serverInt, bool serverConf) {
    const bool wantConf =
        encryptDataTransfer ||
        strcasecmp(clientProtection.c_str(), DFS_DATA_TRANSFER_PROTECTION_PRIVACY) == 0;
    const bool wantInt =
        !wantConf &&
        strcasecmp(clientProtection.c_str(), DFS_DATA_TRANSFER_PROTECTION_INTEGRITY) == 0;

    if (wantConf) {
        if (!serverConf) {
            THROW(SaslException,
                  "Data transfer privacy required but server QOP has no auth-conf");
        }
        return "qop-conf";
    }
    if (wantInt) {
        if (!serverInt) {
            THROW(SaslException,
                  "Data transfer integrity required but server QOP has no auth-int");
        }
        return "qop-int";
    }
    if (!serverAuth) {
        THROW(SaslException,
              "Data transfer authentication required but server QOP has no auth");
    }
    return "qop-auth";
}

bool shouldWrapDataTransferSocket(const std::string & negotiatedGsaslQop,
                                  bool hasValidAesCtrCipher) {
    return negotiatedGsaslQop == "qop-int" ||
           negotiatedGsaslQop == "qop-conf" ||
           hasValidAesCtrCipher;
}
```

Declare both in `DataTransferSaslClient.h` (public, namespace scope).

- [ ] **Step 4: Replace `selectSaslQop` body**

```cpp
void DataTransferSaslClientInternal::selectSaslQop(Payload & payload) {
    const bool serverAuth = payload.qop.find("auth") != std::string::npos &&
                            payload.qop.find("auth-int") == std::string::npos ||
                            /* careful: "auth" is a prefix of "auth-int"/"auth-conf".
                               Parse tokens, do not substring-search the raw string. */;
}
```

**Do not** use `payload.qop.find("auth")` — it matches `auth-int`. Split `payload.qop` on comma (and spaces) into tokens and compare each token to `auth`, `auth-int`, `auth-conf` exactly.

```cpp
static void splitQopTokens(const std::string & qop, bool * auth, bool * integ, bool * conf) {
    *auth = *integ = *conf = false;
    std::string token;
    std::istringstream in(qop);
    while (std::getline(in, token, ',')) {
        // trim spaces
        auto b = token.find_first_not_of(" \t");
        auto e = token.find_last_not_of(" \t");
        if (b == std::string::npos) continue;
        token = token.substr(b, e - b + 1);
        if (token == "auth") *auth = true;
        else if (token == "auth-int") *integ = true;
        else if (token == "auth-conf") *conf = true;
    }
}
```

Then:

```cpp
bool serverAuth, serverInt, serverConf;
splitQopTokens(payload.qop, &serverAuth, &serverInt, &serverConf);
const std::string qop = chooseDataTransferQop(
    conf.getDfsDataTransferProtection(),
    conf.isDfsEncryptDataTransfer(),
    serverAuth, serverInt, serverConf);
gsasl_property_set(session, GSASL_QOP, qop.c_str());
negotiatedQop = qop;  // add std::string negotiatedQop member on Internal
```

- [ ] **Step 5: Replace wrap block in `DataTransferSaslClient::doHandshake`**

Remove the `strcasecmp(INTEGRITY) || strcasecmp(PRIVACY)` gate.

After handshake:

```cpp
CipherOptionProto cipherOption = saslClient->getCipherOption();
const bool validAes =
    cipherOption.has_suite() &&
    cipherOption.suite() == CipherSuiteProto::AES_CTR_NOPADDING &&
    cipherOption.outkey().size() * 8 ==
        static_cast<size_t>(conf.getDfsEncryptDataTransferCipherKeyBitlength()) &&
    cipherOption.outiv().size() == 16 &&
    cipherOption.inkey().size() * 8 ==
        static_cast<size_t>(conf.getDfsEncryptDataTransferCipherKeyBitlength()) &&
    cipherOption.iniv().size() == 16;

const std::string qop = saslClient->getNegotiatedQop(); // add getter

if (!shouldWrapDataTransferSocket(qop, validAes)) {
    if (conf.isDfsEncryptDataTransfer()) {
        THROW(SaslException,
              "dfs.encrypt.data.transfer is true but handshake produced no privacy layer");
    }
    return socket;
}

std::shared_ptr<SocketReader> socketReader;
std::shared_ptr<SocketWriter> socketWriter;
if (validAes) {
    socketReader = std::make_shared<CryptoSocketReader>(
        socket, dataEncryptionKey, cipherOption,
        conf.getDfsEncryptDataTransferCipherKeyBitlength());
    socketWriter = std::make_shared<CryptoSocketWriter>(
        socket, dataEncryptionKey, cipherOption,
        conf.getDfsEncryptDataTransferCipherKeyBitlength());
} else {
    socketReader = std::make_shared<SaslSocketReader>(socket, saslClient);
    socketWriter = std::make_shared<SaslSocketWriter>(socket, saslClient);
}
return std::make_shared<WrapSocket>(socket, socketReader, socketWriter);
```

Add `getNegotiatedQop() const` on `DataTransferSaslClientInternal` and a forwarding getter if the outer class needs it. Store `negotiatedQop` when `selectSaslQop` runs.

- [ ] **Step 6: Stop inventing empty AES cipher options (H1)**

In `selectCipherOption`, **delete** the branch:

```cpp
if (dataTransferEncryptorMessage.cipheroption_size() == 0) {
    if (strcasecmp(..., AES/CTR/NoPadding) == 0) {
        cipherOption.set_suite(AES_CTR_NOPADDING);
    }
}
```

If size is 0, leave `cipherOption` unchanged (default / unset). AES wrap then requires `validAes == false` and falls through to SASL wrap or bare socket per the table above.

When a listed option is AES_CTR, keep the existing inkey/outkey SASL-decrypt. If decrypt yields the wrong size, THROW there rather than constructing CryptoSocket*.

- [ ] **Step 7: Run tests**

```bash
./unit --gtest_filter=TestChooseQop.*:TestShouldWrap.*:TestPayloadParse.*
```

Expected: PASS.

- [ ] **Step 8: Checkpoint**

```bash
git add src/client/DataTransferSaslClient.h src/client/DataTransferSaslClient.cpp test/unit/TestDataTransferSaslClient.cpp
git commit -m "fix: wrap data-transfer sockets from negotiated QOP, not config strings"
```

---

### Task 5: C3 + N5 — `SaslSocketReader::readFully` loops; bound frame length

**Files:**
- Modify: `src/network/SaslSocketReader.cpp`
- Modify: `src/network/SaslSocketReader.h` (optional: expose max frame as constant)
- Create: `test/unit/TestSaslSocketReader.cpp`

**Interfaces:**
- Consumes: `SaslClient::decrypt`
- Produces: `readFully` copies exactly `s` bytes or THROWs; `read` remains short-read

Need a fake SASL client. Put it in the test file:

```cpp
class IdentitySaslClient : public SaslClient {
public:
    IdentitySaslClient(std::shared_ptr<Socket> s, const SessionConfig & c,
                       const Token & t)
        : SaslClient(s, c, t, "") {}
    std::shared_ptr<Socket> doHandshake() override { return underlyingSocket; }
    std::string evaluateChallenge(const std::string &) override { return std::string(); }
    void encrypt(std::string & dst, const std::string_view & src) override {
        dst.assign(src.data(), src.size());
    }
    void decrypt(std::string & dst, const std::string_view & src) override {
        dst.assign(src.data(), src.size());
    }
};
```

Helper to build a SASL frame (4-byte big-endian length + payload) matching `SaslSocketWriter`.

- [ ] **Step 1: Write tests**

```cpp
TEST(TestSaslSocketReader, ReadFullySpansTwoFrames) {
    // MockSocket readFully: first call 4-byte len=3 "abc", then len=3 "def"
    // readFully(buf, 5) must yield "abcde"
}

TEST(TestSaslSocketReader, ReadMayReturnShort) {
    // one frame of 3 bytes, read(10) returns 3
}

TEST(TestSaslSocketReader, OversizeFrameThrows) {
    // length prefix 10*1024*1024+1 → HdfsIOException, no huge resize
}
```

Implement the mock with `WillOnce` / `WillRepeatedly` `Invoke` that copies from a `std::string` cursor, same pattern as `TestBufferedSocketReader.cpp`.

- [ ] **Step 2: Run — expect `ReadFullySpansTwoFrames` fail** (only first frame copied)

- [ ] **Step 3: Implement `readMoreData` cap**

```cpp
static const uint64_t kMaxSaslFrame = 10ull * 1024 * 1024;

size_t SaslSocketReader::readMoreData(int timeout) {
    char lengthData[4];
    underlyingSocket->readFully(lengthData, 4, timeout);
    uint64_t length = (uint8_t)lengthData[3] |
                      ((uint8_t)lengthData[2] << 8) |
                      ((uint8_t)lengthData[1] << 16) |
                      ((uint8_t)lengthData[0] << 24);
    if (length == 0 || length > kMaxSaslFrame) {
        THROW(HdfsIOException, "Invalid SASL frame length: %llu",
              (unsigned long long)length);
    }
    // existing read + decrypt into oBuffer, set oStart/oFinish
    return oFinish;
}
```

Cast length bytes as `unsigned char` / `uint8_t` (current `lengthData[i] & 0xFF` on `char` is sign-extension-hostile on some platforms).

- [ ] **Step 4: Loop `readFully`**

```cpp
void SaslSocketReader::readFully(char * b, int32_t s, int timeout) {
    if (s <= 0) return;
    int32_t copied = 0;
    while (copied < s) {
        if (oStart >= oFinish) {
            readMoreData(timeout);
        }
        size_t available = oFinish - oStart;
        size_t toCopy = static_cast<size_t>(s - copied) < available
                            ? static_cast<size_t>(s - copied)
                            : available;
        memcpy(b + copied, oBuffer.data() + oStart, toCopy);
        oStart += toCopy;
        copied += static_cast<int32_t>(toCopy);
    }
}
```

Remove the `size_t i; while (i == 0); if (i == -1)` pattern. `readMoreData` either returns a positive `oFinish` or THROWs (including on empty decrypt: THROW `HdfsIOException`, do not spin).

Empty decrypt (`oBuffer.empty()` after `gsasl_decode`): THROW rather than `while (i == 0)` infinite loop.

- [ ] **Step 5: Keep `read()` short-read**, but drop `if (i == -1) return -1` (`size_t` never equals -1). If `readMoreData` throws, let it throw.

- [ ] **Step 6: Run**

```bash
./unit --gtest_filter=TestSaslSocketReader.*
```

Expected: PASS.

- [ ] **Step 7: Checkpoint**

```bash
git add src/network/SaslSocketReader.cpp src/network/SaslSocketReader.h test/unit/TestSaslSocketReader.cpp
git commit -m "fix: SaslSocketReader::readFully consumes multiple SASL frames"
```

---

### Task 6: CryptoSocketReader/Writer — validate keys, no leak, CTR stream, full write

**Files:**
- Modify: `src/network/CryptoSocketReader.cpp`
- Modify: `src/network/CryptoSocketWriter.cpp`
- Create: `test/unit/TestCryptoSocket.cpp`

**Interfaces:**
- Consumes: `CipherOptionProto` with in/out key+iv, `keyBitLength`
- Produces: OpenSSL CTR context that survives many Update calls; `write()` emits all ciphertext

- [ ] **Step 1: Shared validation helper**

Add a file-local function in **both** .cpp files (keep them independent; do not add a new header unless it is tiny). Prefer one static in each file:

Reader:

```cpp
static void ValidateCipher(const CipherOptionProto & cipher, size_t keyBitLength, bool forDecrypt) {
    if (keyBitLength != 128 && keyBitLength != 192 && keyBitLength != 256) {
        THROW(HdfsIOException,
              "dfs.encrypt.data.transfer.cipher.key.bitlength must be in (128/192/256): %zu",
              keyBitLength);
    }
    const std::string & key = forDecrypt ? cipher.outkey() : cipher.inkey();
    const std::string & iv  = forDecrypt ? cipher.outiv()  : cipher.iniv();
    const size_t expect = keyBitLength / 8;
    if (key.size() != expect) {
        THROW(HdfsIOException, "Invalid AES-CTR key size: %zu, expected %zu",
              key.size(), expect);
    }
    if (iv.size() != 16) {
        THROW(HdfsIOException, "Invalid AES-CTR IV size: %zu, expected 16",
              iv.size());
    }
}
```

Writer uses `forDecrypt=false`. Fix the existing `"dfs.encrypt.dta.transfer..."` typo to `data`. Fix writer init-failure string `"Cannot init evp cipher decrypt."` → `"Cannot init evp cipher encrypt."`.

- [ ] **Step 2: Constructor leak (N4)**

Pattern for both classes:

```cpp
if (!(evpCipherCtx = EVP_CIPHER_CTX_new())) {
    THROW(HdfsIOException, "Cannot init evp cipher context.");
}
try {
    ValidateCipher(...);
    // EVP_aes_*_ctr, DecryptInit/EncryptInit
    if (1 != EVP_*Init_ex(...)) {
        THROW(HdfsIOException, "Cannot init evp cipher decrypt.");
    }
    EVP_CIPHER_CTX_set_padding(evpCipherCtx, 0);
    evpCipherBlockSize = EVP_CIPHER_block_size(evpCipher);
} catch (...) {
    EVP_CIPHER_CTX_free(evpCipherCtx);
    evpCipherCtx = nullptr;
    throw;
}
```

- [ ] **Step 3: Streaming Update only**

Replace `decrypt` / `encrypt`:

```cpp
void CryptoSocketReader::decrypt(std::string & dst, const std::string_view & src) {
    dst.resize(src.size());
    int updateOutSize = 0;
    if (src.empty()) {
        return;
    }
    if (1 != EVP_DecryptUpdate(evpCipherCtx,
                               reinterpret_cast<unsigned char *>(&dst[0]),
                               &updateOutSize,
                               reinterpret_cast<const unsigned char *>(src.data()),
                               static_cast<int>(src.size()))) {
        THROW(HdfsIOException, "Decrypt data error!");
    }
    dst.resize(updateOutSize);
}
```

Same for encrypt. Delete the `updateOutSize > initSize` resize branch and the per-call `EVP_*Final_ex`.

In the destructor, after the existing free:

```cpp
if (evpCipherCtx) {
    int unused = 0;
    unsigned char tail[32];
    EVP_DecryptFinal_ex(evpCipherCtx, tail, &unused); // writer: EncryptFinal_ex
    EVP_CIPHER_CTX_free(evpCipherCtx);
    evpCipherCtx = nullptr;
}
```

- [ ] **Step 4: `CryptoSocketWriter::write` must not drop ciphertext (N3)**

```cpp
int32_t CryptoSocketWriter::write(const char * b, int32_t s) {
    if (s <= 0) return 0;
    std::string_view inBuffer(b, s);
    std::string outBuffer;
    encrypt(outBuffer, inBuffer);
    underlyingSocket->writeFully(outBuffer.data(), outBuffer.size(), -1);
    return s;  // plaintext bytes accepted; all ciphertext sent
}
```

`writeFully` on the writer stays as today (encrypt then `underlyingSocket->writeFully`).

- [ ] **Step 5: Unit tests** in `test/unit/TestCryptoSocket.cpp`

Use OpenSSL to generate matching ciphertext independently, or construct two CryptoSocket* over a `MockSocket` that records bytes.

Minimum cases:

1. Construct with empty `outkey` → `HdfsIOException` (no leak; ASan optional).
2. Encrypt 20 bytes then 20 bytes via Writer; decrypt the concatenation via Reader with swapped in/out keys — plaintext matches. This proves CTR counter continues across calls **without** Final-per-packet.
3. Writer `write()` when mock `write` would have been short: EXPECT `writeFully` called (or mock `write` never used). Easiest: mock `writeFully` and do not stub `write`; if implementation still calls `write`, gmock fails.

CipherOption for tests: 16-byte key for 128-bit, 16-byte iv, `set_suite(AES_CTR_NOPADDING)`, `set_inkey`/`set_iniv`/`set_outkey`/`set_outiv`. DataEncryptionKey can be default-constructed.

- [ ] **Step 6: Run**

```bash
./unit --gtest_filter=TestCryptoSocket.*
```

Expected: PASS.

- [ ] **Step 7: Checkpoint**

```bash
git add src/network/CryptoSocketReader.cpp src/network/CryptoSocketWriter.cpp test/unit/TestCryptoSocket.cpp
git commit -m "fix: validate AES-CTR keys, stream without per-packet Final, write full ciphertext"
```

---

### Task 7: Optional polish (do only if Tasks 2–6 are green)

**Files:**
- Modify: `src/client/RemoteBlockReader.h` — delete unused `mutex readMut; mutex writeMut;`
- Modify: `src/network/CryptoSocketReader.cpp` / `CryptoSocketWriter.cpp` — already fixed typo in Task 6
- Modify: `src/client/RemoteBlockReader.cpp` — replace `assert(position >= size)` / `assert(dataSize > 0 || ...)` with `if (!cond) THROW(HdfsIOException, ...)` so NDEBUG builds still check

Do **not** add cipher suites. Do **not** change PeerCache.

- [ ] **Step 1: Delete mutex members** if no other file references them (confirmed: only the header).

- [ ] **Step 2: Convert the two asserts in `readNextPacket`** to THROW with block/datanode in the message, matching nearby errors.

- [ ] **Step 3: Run the new plus existing unit tests**

```bash
./unit --gtest_filter=TestWrapSocket.*:TestPayloadParse.*:TestChooseQop.*:TestShouldWrap.*:TestSaslSocketReader.*:TestCryptoSocket.*:TestBufferedSocketReader.*:TestSocket.*
```

Expected: PASS.

- [ ] **Step 4: Full `make unittest`**

Expected: PASS. Do not “fix” pre-existing failures unrelated to these files.

---

## Manual verification (not in unit tests)

After implementation, on a cluster with `dfs.encrypt.data.transfer=true` and socket cache enabled:

1. Read a **single-block** file — must succeed (this is the C1 path: first `checkResponse` varint).
2. Read a **multi-block** file on one DN — must succeed (cached `WrapSocket`, same CTR state, new `OP_READ_BLOCK`). If this fails, **do not** unwrap PeerCache; debug CTR/QOP instead.
3. Repeat with `dfs.data.transfer.protection=integrity` and AES-CTR **disabled** on the DN — SASL framing path (C3).
4. `dfs.encrypt.data.transfer=true` with empty `dfs.data.transfer.protection` — must wrap (N1), not send plaintext `OP_READ_BLOCK`.

Disable cache (`dfs.client.socketcache.capacity=0`) only as a comparison, not as a fix.

---

## Coverage vs review findings

| Finding | Task |
|---------|------|
| C1 missing `return` | Task 2 |
| C2 PeerCache WrapSocket | **Won't fix** (false positive) |
| C3 `readFully` one frame | Task 5 |
| H1 empty cipher option | Task 4 step 6 + Task 6 validation |
| H2 unused mutex | Task 7 optional |
| H3 short `read()` | **Won't fix** (API contract) |
| M1 resize UAF / dead branch | Task 6 |
| M2 only AES-CTR | **Won't fix** (explicit limit) |
| M3 `dta` typo | Task 6 |
| M4 key/iv length | Task 6 |
| N1 wrap vs config | Task 4 |
| N2 Parse OOB | Task 3 |
| N3 writer short write | Task 6 |
| N4 EVP ctx leak | Task 6 |
| N5 SASL length cap | Task 5 |
| N6 poll leftover | Task 2 |
| N7 QOP upgrade | Task 4 |
| Q2 CTR Final | Task 6 (stop calling Final per packet) |

## Placeholder / consistency check

- Helper names used later match Task 4: `chooseDataTransferQop`, `shouldWrapDataTransferSocket`, `getNegotiatedQop`.
- Reader uses **out** key/iv; writer uses **in** key/iv — unchanged from current constructors.
- No task implements MiniMax C2 “unwrap before cache”.
