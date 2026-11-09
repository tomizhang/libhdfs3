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
#ifndef _HDFS_LIBHDFS3_NETWORK_SOCKETWRITER_H_
#define _HDFS_LIBHDFS3_NETWORK_SOCKETWRITER_H_

#include "common/Memory.h"
#include "network/Socket.h"

namespace Hdfs {
namespace Internal {

/**
 * a data buffer used to read and write.
 */
class SocketWriter {
public:

    virtual ~SocketWriter() {
    }

    /**
     * Send data to socket.
     * The caller will be blocked until send operation finished,
     *      but not guarantee that all data has been sent.
     * @param buffer The data to be sent.
     * @param size The size of bytes to be sent.
     * @return The size of data already be sent.
     * @throw HdfsNetworkException
     */
    virtual int32_t write(const char * buffer, int32_t size) = 0;

    /**
     * Write a vector to socket.
     * @param bytes The data be written.
     * @param s The size of data.
     */
    virtual void writeFully(const void * bytes, size_t s, int timeout) = 0;

};


class SocketWriterImpl: public SocketWriter {
public:
    SocketWriterImpl(std::shared_ptr<Socket> s);

    ~SocketWriterImpl();

    /**
     * Send data to socket.
     * The caller will be blocked until send operation finished,
     *      but not guarantee that all data has been sent.
     * @param buffer The data to be sent.
     * @param size The size of bytes to be sent.
     * @return The size of data already be sent.
     * @throw HdfsNetworkException
     */
    inline int32_t write(const char * buffer, int32_t size){
        return socket->write(buffer, size);
    }

    /**
     * Write a vector to socket.
     * @param bytes The data be written.
     * @param s The size of data.
     */
    inline void writeFully(const void * bytes, size_t s, int timeout){
        socket->writeFully((const char *)bytes, s, timeout);
    }

protected:
    std::shared_ptr<Socket> socket;

};

}
}
#endif /* _HDFS_LIBHDFS3_NETWORK_SOCKETWRITER_H_ */
