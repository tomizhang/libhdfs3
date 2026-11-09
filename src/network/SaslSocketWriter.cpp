/********************************************************************
 * Copyright (c) 2024 - 2025, Visionsky.
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

#include "SaslSocketWriter.h"

#include "common/Logger.h"
#include "common/DebugUtil.h"
#include "Socket.h"
#include "SocketWriter.h"
#include "SaslClient.h"

#include <iostream>
#include <iomanip>

namespace Hdfs {
namespace Internal {

SaslSocketWriter::SaslSocketWriter(std::shared_ptr<Socket> socket,
                                   std::shared_ptr<SaslClient> client):
    underlyingSocket(socket), saslClient(client) {

}

/**
 * Destroy a Sasl data writer.
 * @throw nothrow
 */
SaslSocketWriter::~SaslSocketWriter() {
    saslClient.reset();
    underlyingSocket.reset();
};

void SaslSocketWriter::encrypt(std::string & dst, const std::string_view & src) {
    //LOG(DEBUG1, "SaslSocketWriter::encrypt Begin");
    saslClient->encrypt(dst, src);
    //LOG(DEBUG1, "SaslSocketWriter::encrypt End");
}

int32_t SaslSocketWriter::write(const char * b, int32_t s){
    //LOG(DEBUG1, "SaslSocketWriter::write Begin");
    //LOG(DEBUG1, "SaslSocketWriter::write->in: [%s]", dataToHex((unsigned char *)b, s).c_str());
    std::string_view inBuffer(b, s);
    std::string outBuffer;
    encrypt(outBuffer, inBuffer);
    //LOG(DEBUG1, "SaslSocketWriter::write->out: [%s]", stringToHex(outBuffer).c_str());
    char lengthData[4];
    lengthData[0] = ((outBuffer.size()) >> 24) & 0xFF;
    lengthData[1] = ((outBuffer.size()) >> 16) & 0xFF;
    lengthData[2] = ((outBuffer.size()) >> 8) & 0xFF;
    lengthData[3] = (outBuffer.size()) & 0xFF;
    //LOG(DEBUG1, "SaslSocketWriter::write->lengthData: [%s]", dataToHex((unsigned char *)lengthData, 4).c_str());
    underlyingSocket->writeFully(lengthData, 4, -1);
    underlyingSocket->writeFully(outBuffer.data(), outBuffer.size(), -1);
    //LOG(DEBUG1, "SaslSocketWriter::write End");
    return s;
}

/**
 * Write a vector to socket.
 * @param bytes The data be written.
 * @param s The size of data.
 */
void SaslSocketWriter::writeFully(const void * b, size_t s, int timeout){
    //LOG(DEBUG1, "SaslSocketWriter::writeFully Begin");
    //LOG(DEBUG1, "SaslSocketWriter::writeFully->in: [%s]", dataToHex((unsigned char *)b, s).c_str());
    std::string_view inBuffer((const char *)b, s);
    std::string outBuffer;
    encrypt(outBuffer, inBuffer);
    //LOG(DEBUG1, "SaslSocketWriter::writeFully->out: [%s]", stringToHex(outBuffer).c_str());
    char lengthData[4];
    lengthData[0] = ((outBuffer.size()) >> 24) & 0xFF;
    lengthData[1] = ((outBuffer.size()) >> 16) & 0xFF;
    lengthData[2] = ((outBuffer.size()) >> 8) & 0xFF;
    lengthData[3] = (outBuffer.size()) & 0xFF;
    //LOG(DEBUG1, "SaslSocketWriter::writeFully->lengthData: [%s]", dataToHex((unsigned char *)lengthData, 4).c_str());
    underlyingSocket->writeFully(lengthData, 4, timeout);
    underlyingSocket->writeFully(outBuffer.data(), outBuffer.size(), timeout);
    //LOG(DEBUG1, "SaslSocketWriter::writeFully End");
}

}
}
