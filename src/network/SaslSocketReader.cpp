/********************************************************************
 * Copyright (c) 2024 - 2025, Vincent.
 * All rights reserved.
 *
 * Author: Vincent
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
#include "SaslSocketReader.h"

#include "common/Memory.h"
#include "common/DebugUtil.h"
#include "common/Logger.h"
#include "Exception.h"
#include "ExceptionInternal.h"

#include <iomanip>

namespace Hdfs {
namespace Internal {

SaslSocketReader::SaslSocketReader(std::shared_ptr<Socket> socket,
                                   std::shared_ptr<SaslClient> client): 
    underlyingSocket(socket), saslClient(client), oStart(0), oFinish(0) {
}

SaslSocketReader::~SaslSocketReader(){
    saslClient.reset();
    underlyingSocket.reset();
}

void SaslSocketReader::decrypt(std::string & dst, const std::string_view & src){
    //LOG(DEBUG1, "SaslSocketReader::decrypt Begin");
    saslClient->decrypt(dst, src);
    //LOG(DEBUG1, "SaslSocketReader::decrypt End");
}

static const uint64_t kMaxSaslFrame = 10ull * 1024 * 1024;

size_t SaslSocketReader::readMoreData(int timeout) {
    //LOG(DEBUG1, "SaslSocketReader::readMoreData Begin");
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
    std::string inBuffer;
    inBuffer.resize(length);
    underlyingSocket->readFully(inBuffer.data(), static_cast<int32_t>(length), timeout);
    std::string_view inBufferView(inBuffer);
    decrypt(oBuffer, inBufferView);
    oStart = 0;
    if (oBuffer.empty()) {
        THROW(HdfsIOException, "SASL decrypt produced empty output for non-empty frame");
    }
    oFinish = oBuffer.size();
    //LOG(DEBUG1, "SaslSocketReader::readMoreData End");
    return oFinish;
}


int32_t SaslSocketReader::read(char * b, int32_t s) {
    //LOG(DEBUG1, "SaslSocketReader::read Begin");
    if (s <= 0) return 0;

    if (oStart >= oFinish) {
        readMoreData(-1);
    }
    size_t available = oFinish - oStart;
    if (static_cast<size_t>(s) < available) available = static_cast<size_t>(s);
    memcpy(b, oBuffer.data() + oStart, available);
    oStart = oStart + available;
    //LOG(DEBUG1, "SaslSocketReader::read End");
    return static_cast<int32_t>(available);
}

void SaslSocketReader::readFully(char * b, int32_t s, int timeout) {
    //LOG(DEBUG1, "SaslSocketReader::readFully Begin");
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
    //LOG(DEBUG1, "SaslSocketReader::readFully End");
}

bool SaslSocketReader::poll(int timeout){
    if (oStart < oFinish) {
        return true;
    }
    return underlyingSocket->poll(true, false, timeout);
}


}
}
