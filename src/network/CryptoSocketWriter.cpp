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

#include "CryptoSocketWriter.h"
#include "common/Memory.h"
#include "common/Logger.h"
#include "common/DebugUtil.h"
#include "common/Exception.h"
#include "common/ExceptionInternal.h"
#include "server/DataEncryptionKey.h"
#include "Socket.h"
#include "SocketWriter.h"
#include "hdfs.pb.h"

#include <openssl/evp.h>
#include <openssl/aes.h>

namespace Hdfs {
namespace Internal {

static void ValidateCipher(const CipherOptionProto & cipher, size_t keyBitLength, bool forDecrypt) {
    if (keyBitLength != 128 && keyBitLength != 192 && keyBitLength != 256) {
        THROW(HdfsIOException,
              "dfs.encrypt.data.transfer.cipher.key.bitlength must be in (128/192/256): %zu",
              keyBitLength);
    }
    const std::string & key = forDecrypt ? cipher.outkey() : cipher.inkey();
    const std::string & iv  = forDecrypt ? cipher.outiv()  : cipher.iniv();
    const size_t expect = keyBitLength / 8;
    if (key.size() != expect) {
        THROW(HdfsIOException, "Invalid AES-CTR key size: %zu, expected %zu",
              key.size(), expect);
    }
    if (iv.size() != 16) {
        THROW(HdfsIOException, "Invalid AES-CTR IV size: %zu, expected 16",
              iv.size());
    }
}

CryptoSocketWriter::CryptoSocketWriter(std::shared_ptr<Socket> socket,
                                       DataEncryptionKey key,
                                       CipherOptionProto cipher,
                                       size_t keyBitLength):
        underlyingSocket(socket), dataEncryptionKey(key), cipherOption(cipher), cipherKeyBitLength(keyBitLength),
        evpCipherCtx(nullptr) {

    if (!(evpCipherCtx = EVP_CIPHER_CTX_new())) {
        THROW(HdfsIOException, "Cannot init evp cipher context.");
    }
    try {
        ValidateCipher(cipher, keyBitLength, false);
        const EVP_CIPHER *evpCipher;
        switch (keyBitLength) {
        case 128:
            evpCipher = EVP_aes_128_ctr();
            break;
        case 192:
            evpCipher = EVP_aes_192_ctr();
            break;
        default: /* 256 */
            evpCipher = EVP_aes_256_ctr();
            break;
        }
        if (1 != EVP_EncryptInit_ex(evpCipherCtx, evpCipher, NULL,
                                    (const unsigned char *)(cipher.inkey().data()),
                                    (const unsigned char *)(cipher.iniv().data()))) {
            THROW(HdfsIOException, "Cannot init evp cipher encrypt.");
        }
        EVP_CIPHER_CTX_set_padding(evpCipherCtx, 0);
        evpCipherBlockSize = EVP_CIPHER_block_size(evpCipher);
    } catch (...) {
        EVP_CIPHER_CTX_free(evpCipherCtx);
        evpCipherCtx = nullptr;
        throw;
    }
}

/**
 * Destroy a crypto data writer.
 * @throw nothrow
 */
CryptoSocketWriter::~CryptoSocketWriter() {
    if (evpCipherCtx) {
        int unused = 0;
        unsigned char tail[32];
        EVP_EncryptFinal_ex(evpCipherCtx, tail, &unused);
        EVP_CIPHER_CTX_free(evpCipherCtx);
        evpCipherCtx = nullptr;
    }
    underlyingSocket.reset();
}

void CryptoSocketWriter::encrypt(std::string & dst, const std::string_view & src) {
    if (src.empty()) {
        dst.resize(0);
        return;
    }
    dst.resize(src.size());
    int updateOutSize = 0;
    if (1 != EVP_EncryptUpdate(evpCipherCtx,
                               reinterpret_cast<unsigned char *>(&dst[0]),
                               &updateOutSize,
                               reinterpret_cast<const unsigned char *>(src.data()),
                               static_cast<int>(src.size()))) {
        THROW(HdfsIOException, "Encrypt data error!");
    }
    dst.resize(updateOutSize);
}

int32_t CryptoSocketWriter::write(const char * b, int32_t s) {
    if (s <= 0) return 0;
    std::string_view inBuffer(b, s);
    std::string outBuffer;
    encrypt(outBuffer, inBuffer);
    underlyingSocket->writeFully(outBuffer.data(), outBuffer.size(), -1);
    return s;
}

/**
 * Write a vector to socket.
 * @param bytes The data be written.
 * @param s The size of data.
 */
void CryptoSocketWriter::writeFully(const void * b, size_t s, int timeout) {
    //LOG(INFO, "CryptoSocketWriter::writeFully Begin");
    std::string_view inBuffer((const char *)b, s);
    std::string outBuffer;
    //LOG(INFO, "CryptoSocketReader::writeFully->inBuffer: [%s]", dataToHex((unsigned char *)b,s).c_str());
    encrypt(outBuffer, inBuffer);
    //LOG(INFO, "CryptoSocketReader::writeFully->outBuffer: [%s]", stringToHex(outBuffer).c_str());
    underlyingSocket->writeFully(outBuffer.data(), outBuffer.size(), timeout);
    //LOG(INFO, "CryptoSocketWriter::writeFully End");
}

}
}
