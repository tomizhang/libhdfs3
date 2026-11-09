/********************************************************************
 * Copyright (c) 2013 - 2014, Pivotal Inc.
 * All rights reserved.
 *
 * Author: Zhanwei Wang
 ********************************************************************/
/********************************************************************
 * 2014 -
 * open source under Apache License Version 2.0
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
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "client/FileSystemImpl.h"
#include "MockNamenode.h"
#include "XmlConfig.h"

#include <sys/time.h>

using namespace Hdfs;
using namespace Hdfs::Internal;
using namespace Hdfs::Mock;
using namespace testing;

static uint64_t NowMs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return static_cast<uint64_t>(tv.tv_sec) * 1000 + tv.tv_usec / 1000;
}

static DataEncryptionKey MakeKey(uint32_t id, uint64_t expiry) {
    DataEncryptionKey key;
    key.setKeyId(id);
    key.setExpiryDate(expiry);
    return key;
}

class TestDataEncryptionKeyCache: public ::testing::Test {
protected:
    TestDataEncryptionKeyCache() : fs(FileSystemKey("hdfs://localhost:9000", "test"), Config()) {
        nn = new MockNamenode();
        fs.nn = nn;
    }

    FileSystemImpl fs;
    MockNamenode * nn;
};

TEST_F(TestDataEncryptionKeyCache, ValidKeyIsFetchedOnce) {
    EXPECT_CALL(*nn, getDataEncryptionKey()).Times(1)
        .WillOnce(Return(MakeKey(7, NowMs() + 3600 * 1000)));

    EXPECT_EQ(7u, fs.getDataEncryptionKey().getKeyId());
    EXPECT_EQ(7u, fs.getDataEncryptionKey().getKeyId());
    EXPECT_EQ(7u, fs.getDataEncryptionKey().getKeyId());
}

TEST_F(TestDataEncryptionKeyCache, ExpiredKeyIsRefetched) {
    EXPECT_CALL(*nn, getDataEncryptionKey()).Times(2)
        .WillOnce(Return(MakeKey(1, NowMs() + 30 * 1000)))
        .WillOnce(Return(MakeKey(2, NowMs() + 3600 * 1000)));

    EXPECT_EQ(1u, fs.getDataEncryptionKey().getKeyId());
    EXPECT_EQ(2u, fs.getDataEncryptionKey().getKeyId());
    EXPECT_EQ(2u, fs.getDataEncryptionKey().getKeyId());
}

TEST_F(TestDataEncryptionKeyCache, EmptyKeyIsCached) {
    EXPECT_CALL(*nn, getDataEncryptionKey()).Times(1)
        .WillOnce(Return(DataEncryptionKey()));

    fs.getDataEncryptionKey();
    fs.getDataEncryptionKey();
}

TEST_F(TestDataEncryptionKeyCache, ClearCausesRefetch) {
    EXPECT_CALL(*nn, getDataEncryptionKey()).Times(2)
        .WillOnce(Return(MakeKey(1, NowMs() + 3600 * 1000)))
        .WillOnce(Return(MakeKey(2, NowMs() + 3600 * 1000)));

    EXPECT_EQ(1u, fs.getDataEncryptionKey().getKeyId());
    EXPECT_EQ(1u, fs.getDataEncryptionKey().getKeyId()); // still cached
    fs.clearDataEncryptionKey();
    EXPECT_EQ(2u, fs.getDataEncryptionKey().getKeyId()); // refetched
    EXPECT_EQ(2u, fs.getDataEncryptionKey().getKeyId()); // cached again
}

TEST_F(TestDataEncryptionKeyCache, ClearOnFreshStateIsSafe) {
    fs.clearDataEncryptionKey(); // must not crash or throw
    EXPECT_CALL(*nn, getDataEncryptionKey()).Times(1)
        .WillOnce(Return(MakeKey(5, NowMs() + 3600 * 1000)));
    EXPECT_EQ(5u, fs.getDataEncryptionKey().getKeyId());
}
