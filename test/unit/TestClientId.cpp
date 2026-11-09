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
#include "ClientId.h"

#include <cstring>
#include <set>
#include <string>

using namespace Hdfs::Internal;

TEST(TestClientId, TestLengthAndUuidV4Bits) {
    for (int i = 0; i < 100; ++i) {
        std::string id = GenerateClientId();
        ASSERT_EQ(CLIENT_ID_LENGTH, id.size());
        EXPECT_EQ(0x40, static_cast<unsigned char>(id[6]) & 0xF0);
        EXPECT_EQ(0x80, static_cast<unsigned char>(id[8]) & 0xC0);
    }
}

TEST(TestClientId, TestUnique) {
    std::set<std::string> ids;

    for (int i = 0; i < 10000; ++i) {
        ids.insert(GenerateClientId());
    }

    EXPECT_EQ(10000u, ids.size());
}

static void CheckSource(bool (*fill)(unsigned char *, size_t)) {
    unsigned char a[CLIENT_ID_LENGTH], b[CLIENT_ID_LENGTH];
    ASSERT_TRUE(fill(a, sizeof(a)));
    ASSERT_TRUE(fill(b, sizeof(b)));
    EXPECT_NE(0, memcmp(a, b, sizeof(a)));
}

TEST(TestClientId, TestOpenSSLSource) {
    CheckSource(FillRandomFromOpenSSL);
}

TEST(TestClientId, TestUrandomSource) {
    CheckSource(FillRandomFromUrandom);
}

TEST(TestClientId, TestRandomDeviceSource) {
    CheckSource(FillRandomFromRandomDevice);
}

TEST(TestClientId, TestRandomDeviceOddLength) {
    unsigned char buf[7];
    memset(buf, 0, sizeof(buf));
    EXPECT_TRUE(FillRandomFromRandomDevice(buf, sizeof(buf)));
}
