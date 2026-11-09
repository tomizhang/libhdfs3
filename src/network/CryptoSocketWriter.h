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
#ifndef _HDFS_LIBHDFS3_NETWORK_CRYPTOSOCKETWRITER_H_
#define _HDFS_LIBHDFS3_NETWORK_CRYPTOSOCKETWRITER_H_

#include "common/Memory.h"
#include "server/DataEncryptionKey.h"

#include "Socket.h"
#include "SocketWriter.h"
#include "hdfs.pb.h"

#include <openssl/evp.h>
#include <openssl/aes.h>

namespace Hdfs {
namespace Internal {

class CryptoSocketWriter: public SocketWriter {
public:

    CryptoSocketWriter(std::shared_ptr<Socket> socket,
                       DataEncryptionKey key,
                       CipherOptionProto cipher,
                       size_t keyBitLength);

    /**
     * Destroy a crypto data writer.
     * @throw nothrow
     */
    ~CryptoSocketWriter();


    int32_t write(const char * buffer, int32_t size);

    /**
     * Write a vector to socket.
     * @param bytes The data be written.
     * @param s The size of data.
     */
    void writeFully(const void * bytes, size_t s, int timeout);

private:
    void encrypt(std::string & dst, const std::string_view & src);

private:

    std::shared_ptr<Socket> underlyingSocket;
    DataEncryptionKey dataEncryptionKey;
    CipherOptionProto cipherOption;
    size_t cipherKeyBitLength;

    EVP_CIPHER_CTX *evpCipherCtx;
    int evpCipherBlockSize;

};

}
}

#endif /* _HDFS_LIBHDFS3_NETWORK_CRYPTOSOCKETWRITER_H_ */
