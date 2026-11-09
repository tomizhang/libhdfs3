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
#ifndef _HDFS_LIBHDFS3_NETWORK_WRAPSOCKET_H_
#define _HDFS_LIBHDFS3_NETWORK_WRAPSOCKET_H_

#include "Socket.h"
#include "SocketReader.h"
#include "SocketWriter.h"

namespace Hdfs {
namespace Internal {

/**
 * A wrapped socket client
 */
class WrapSocket: public Socket {
public:
    /**
     * Construct a Socket object.
     * @throw nothrow
     */
    WrapSocket(std::shared_ptr<Socket> underlyingSocket,
               std::shared_ptr<SocketReader> socketReader,
               std::shared_ptr<SocketWriter> socketWriter):
        underlyingSocket(underlyingSocket), socketReader(socketReader),socketWriter(socketWriter){

    }

    /**
     * Destroy a WappedSocket instance.
     */
    ~WrapSocket(){
        socketReader.reset();
        socketWriter.reset();
        underlyingSocket.reset();
    }

    /**
     * Read data from socket.
     * If there is nothing can be read, the caller will be blocked.
     * @param buffer The buffer to store the data.
     * @param size The size of bytes to be read.
     * @return The size of data already read.
     * @throw HdfsNetworkException
     * @throw HdfsEndOfStream
     */
    inline int32_t read(char * buffer, int32_t size) {
        return socketReader->read(buffer, size);
    }

    /**
     * Read data from socket until get enough data.
     * If there is not enough data can be read, the caller will be blocked.
     * @param buffer The buffer to store the data.
     * @param size The size of bytes to be read.
     * @param timeout The timeout interval of this read operation, negative means infinite.
     * @throw HdfsNetworkException
     * @throw HdfsEndOfStream
     * @throw HdfsTimeout
     */
    inline void readFully(char * buffer, int32_t size, int timeout) {
        socketReader->readFully(buffer, size, timeout);
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
    inline int32_t write(const char * buffer, int32_t size) {
        return socketWriter->write(buffer, size);
    }

    /**
     * Send all data to socket.
     * The caller will be blocked until all data has been sent.
     * @param buffer The data to be sent.
     * @param size The size of bytes to be sent.
     * @param timeout The timeout interval of this write operation, negative means infinite.
     * @throw HdfsNetworkException
     * @throw HdfsTimeout
     */
    inline void writeFully(const char * buffer, int32_t size, int timeout) {
        socketWriter->writeFully(buffer, size, timeout);
    }

    /**
     * Connection to a tcp server.
     * @param host The host of server.
     * @param port The port of server.
     * @param timeout The timeout interval of this read operation, negative means infinite.
     * @throw HdfsNetworkException
     * @throw HdfsTimeout
     */
    inline void connect(const char * host, int port, int timeout) {
        underlyingSocket->connect(host, port, timeout);
    }

    /**
     * Connection to a tcp server.
     * @param host The host of server.
     * @param port The port of server.
     * @param timeout The timeout interval of this read operation, negative means infinite.
     * @throw HdfsNetworkException
     * @throw HdfsTimeout
     */
    inline void connect(const char * host, const char * port, int timeout) {
        underlyingSocket->connect(host, port, timeout);
    }

    /**
     * Connection to a tcp server.
     * @param paddr The address of server.
     * @param host The host of server used in error message.
     * @param port The port of server used in error message.
     * @param timeout The timeout interval of this read operation, negative means infinite.
     * @throw HdfsNetworkException
     * @throw HdfsTimeout
     */
    inline void connect(struct addrinfo * paddr, 
                        const char * host, const char * port, int timeout) {
        underlyingSocket->connect(paddr, host, port, timeout);
    }

    /**
     * Test if the socket can be read or written without blocking.
     * @param read Test socket if it can be read.
     * @param write Test socket if it can be written.
     * @param timeout Time timeout interval of this operation, negative means infinite.
     * @return Return true if the socket can be read or written without blocking, false on timeout.
     * @throw HdfsNetworkException
     * @throw HdfsTimeout
     */
    inline bool poll(bool read, bool write, int timeout) {
        if (read && !write) {
            return socketReader->poll(timeout);
        }
        return underlyingSocket->poll(read, write, timeout);
    }

    /**
     * Set socket blocking mode.
     * @param enable If true, set socket into blocking mode, else non-block mode.
     * @throw HdfsNetworkException
     */
    inline void setBlockMode(bool enable) {
        underlyingSocket->setBlockMode(enable);
    }

    /**
     * Set socket no delay mode.
     * @param enable If true, set socket into no delay mode, else delay mode.
     * @throw HdfsNetworkException
     */
    inline void setNoDelay(bool enable) {
        underlyingSocket->setNoDelay(enable);
    }

    /**
     * Set socket linger timeout
     * @param timeout Linger timeout of the socket in millisecond, disable linger if it is less than 0.
     * @throw HdfsNetworkException
     */
    inline void setLingerTimeout(int timeout) {
        underlyingSocket->setLingerTimeout(timeout);
    }

    /**
     * Disable SIGPIPE on this socket.
     * It only works on some platform.
     *      Write operation guarantee that no SIGPIPE will be raised.
     * @throw HdfsNetworkException
     */
    inline void disableSigPipe() {
        underlyingSocket->disableSigPipe();
    }

    /**
     * Shutdown and close the socket.
     * @throw nothrow
     */
    inline void close() {
        underlyingSocket->close();
    }

protected:
    std::shared_ptr<Socket> underlyingSocket;
    std::shared_ptr<SocketReader> socketReader;
    std::shared_ptr<SocketWriter> socketWriter;
};

}
}

#endif /* _HDFS_LIBHDFS3_NETWORK_WRAPSOCKET_H_ */
