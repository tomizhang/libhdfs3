/********************************************************************
 * Copyright (c) 2024 - 2025, Vincent.
 * All rights reserved.
 *
 * Author: Vincent
 ********************************************************************/
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "Exception.h"
#include "ExceptionInternal.h"
#include "gtest/gtest.h"
#include "MockSocket.h"
#include "network/SaslSocketReader.h"
#include "network/SaslClient.h"
#include "common/SessionConfig.h"
#include "client/Token.h"

#include <string>
#include <cstring>

using namespace Hdfs;
using namespace Hdfs::Internal;
using namespace testing;

// ---------------------------------------------------------------------------
// IdentitySaslClient: no-op encrypt/decrypt (identity transform)
// ---------------------------------------------------------------------------
class IdentitySaslClient : public SaslClient {
public:
    IdentitySaslClient(std::shared_ptr<Socket> s, const SessionConfig & c,
                       const Token & t)
        : SaslClient(s, c, t, "") {}

    std::shared_ptr<Socket> doHandshake() override { return underlyingSocket; }

    std::string evaluateChallenge(const std::string &) override {
        return std::string();
    }

    void encrypt(std::string & dst, const std::string_view & src) override {
        dst.assign(src.data(), src.size());
    }

    void decrypt(std::string & dst, const std::string_view & src) override {
        dst.assign(src.data(), src.size());
    }
};

// ---------------------------------------------------------------------------
// Helper: build a SASL frame (4-byte big-endian length + payload)
// ---------------------------------------------------------------------------
static std::string MakeSaslFrame(const std::string & payload) {
    uint32_t len = static_cast<uint32_t>(payload.size());
    std::string frame(4, '\0');
    frame[0] = static_cast<char>((len >> 24) & 0xFF);
    frame[1] = static_cast<char>((len >> 16) & 0xFF);
    frame[2] = static_cast<char>((len >>  8) & 0xFF);
    frame[3] = static_cast<char>( len        & 0xFF);
    frame += payload;
    return frame;
}

// ---------------------------------------------------------------------------
// Cursor-based readFully action (stateful, advances through wire data)
// ---------------------------------------------------------------------------
struct ReadCursor {
    std::string data;
    size_t pos = 0;

    void readFully(char * buf, int32_t size, int /*timeout*/) {
        ASSERT_LE(pos + static_cast<size_t>(size), data.size())
            << "ReadCursor ran out of data";
        std::memcpy(buf, data.data() + pos, size);
        pos += size;
    }
};

// ---------------------------------------------------------------------------
// TEST: readFully spans two SASL frames
// ---------------------------------------------------------------------------
TEST(TestSaslSocketReader, ReadFullySpansTwoFrames) {
    // Wire: frame("abc") + frame("def")
    std::string wire = MakeSaslFrame("abc") + MakeSaslFrame("def");

    auto cursor = std::make_shared<ReadCursor>();
    cursor->data = wire;

    auto sock = std::make_shared<MockSocket>();
    EXPECT_CALL(*sock, readFully(_, _, _))
        .WillRepeatedly(Invoke([cursor](char * buf, int32_t sz, int timeout) {
            cursor->readFully(buf, sz, timeout);
        }));

    Config conf;
    SessionConfig sc(conf);
    Token tok;
    auto client = std::make_shared<IdentitySaslClient>(sock, sc, tok);
    SaslSocketReader reader(sock, client);

    char buf[6] = {};
    reader.readFully(buf, 5, -1);

    EXPECT_EQ(std::string(buf, 5), "abcde");
}

// ---------------------------------------------------------------------------
// TEST: read() may return short (one frame of 3 bytes, ask for 10)
// ---------------------------------------------------------------------------
TEST(TestSaslSocketReader, ReadMayReturnShort) {
    std::string wire = MakeSaslFrame("abc");

    auto cursor = std::make_shared<ReadCursor>();
    cursor->data = wire;

    auto sock = std::make_shared<MockSocket>();
    EXPECT_CALL(*sock, readFully(_, _, _))
        .WillRepeatedly(Invoke([cursor](char * buf, int32_t sz, int timeout) {
            cursor->readFully(buf, sz, timeout);
        }));

    Config conf;
    SessionConfig sc(conf);
    Token tok;
    auto client = std::make_shared<IdentitySaslClient>(sock, sc, tok);
    SaslSocketReader reader(sock, client);

    char buf[10] = {};
    int32_t n = reader.read(buf, 10);

    EXPECT_EQ(n, 3);
    EXPECT_EQ(std::string(buf, 3), "abc");
}

// ---------------------------------------------------------------------------
// TEST: oversized frame length → HdfsIOException, no huge resize
// ---------------------------------------------------------------------------
TEST(TestSaslSocketReader, OversizeFrameThrows) {
    // 4-byte big-endian: 10*1024*1024 + 1 = 0x00A00001
    uint32_t badLen = 10u * 1024u * 1024u + 1u;
    char lengthData[4];
    lengthData[0] = static_cast<char>((badLen >> 24) & 0xFF);
    lengthData[1] = static_cast<char>((badLen >> 16) & 0xFF);
    lengthData[2] = static_cast<char>((badLen >>  8) & 0xFF);
    lengthData[3] = static_cast<char>( badLen        & 0xFF);

    auto sock = std::make_shared<MockSocket>();
    EXPECT_CALL(*sock, readFully(_, 4, _))
        .WillOnce(Invoke([&lengthData](char * buf, int32_t sz, int /*timeout*/) {
            std::memcpy(buf, lengthData, 4);
        }));
    // The second readFully (payload) must NOT be called.
    EXPECT_CALL(*sock, readFully(_, Ne(4), _)).Times(0);

    Config conf;
    SessionConfig sc(conf);
    Token tok;
    auto client = std::make_shared<IdentitySaslClient>(sock, sc, tok);
    SaslSocketReader reader(sock, client);

    char buf[16] = {};
    EXPECT_THROW(reader.readFully(buf, 16, -1), HdfsIOException);
}
