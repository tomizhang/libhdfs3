/********************************************************************
 * Copyright (c) 2024 - 2025, Visionsky.
 * All rights reserved.
 *
 * Author: Vincent
 ********************************************************************/
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
