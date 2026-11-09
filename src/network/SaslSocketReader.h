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
#ifndef _HDFS_LIBHDFS3_NETWORK_SASLSOCKETREADER_H_
#define _HDFS_LIBHDFS3_NETWORK_SASLSOCKETREADER_H_

#include "common/Memory.h"
#include "Socket.h"
#include "SocketReader.h"
#include "SaslClient.h"

#include <string_view>

namespace Hdfs {
namespace Internal {

class SaslSocketReader: public SocketReader {
public:

    SaslSocketReader(std::shared_ptr<Socket> socket,
                     std::shared_ptr<SaslClient> client);

    /**
     * Destroy a crypto data reader.
     * @throw nothrow
     */
    ~SaslSocketReader();

     /**
     * Read data from socket.
     * If there is nothing can be read, the caller will be blocked.
     * @param b The buffer used to receive data.
     * @param s The size of bytes to be read.
     * @return The size of data already read.
     * @throw HdfsNetworkException
     * @throw HdfsEndOfStream
     */
    int32_t read(char * b, int32_t s);

    /**
     * Read data form socket.
     * If there is not enough data can be read, the caller will be blocked.
     * @param b The buffer used to receive data.
     * @param s The size of bytes to read.
     * @param timeout The timeout interval of this read operation, negative means infinite.
     * @throw HdfsNetworkException
     * @throw HdfsEndOfStream
     * @throw HdfsTimeout
     */
    void readFully(char * b, int32_t s, int timeout);

    /**
     * Test if the socket can be read without blocking.
     * @param timeout Time timeout interval of this operation, negative means infinite.
     * @return Return true if the socket can be read without blocking, false on timeout.
     * @throw HdfsNetworkException
     * @throw HdfsTimeout
     */
    bool poll(int timeout);

private:
    void decrypt(std::string & dst, const std::string_view & src);
    size_t readMoreData(int timeout);

private:

    std::shared_ptr<Socket> underlyingSocket;
    std::shared_ptr<SaslClient> saslClient;

    std::string oBuffer;
    size_t oStart, oFinish;

};

}
}

#endif /* _HDFS_LIBHDFS3_NETWORK_SASLSOCKETREADER_H_ */
