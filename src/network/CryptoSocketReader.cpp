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
#include "CryptoSocketReader.h"
#include "common/Memory.h"
#include "common/Logger.h"
#include "common/DebugUtil.h"
#include "common/Exception.h"
#include "common/ExceptionInternal.h"
#include "BufferedSocketReader.h"

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

CryptoSocketReader::CryptoSocketReader(std::shared_ptr<Socket> socket,
                                       DataEncryptionKey key,
                                       CipherOptionProto cipher,
                                       size_t keyBitLength):
    dataEncryptionKey(key), cipherOption(cipher), cipherKeyBitLength(keyBitLength),
    underlyingSocket(socket), evpCipherCtx(nullptr) {

    if (!(evpCipherCtx = EVP_CIPHER_CTX_new())) {
        THROW(HdfsIOException, "Cannot init evp cipher context.");
    }
    try {
        ValidateCipher(cipher, keyBitLength, true);
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
        if (1 != EVP_DecryptInit_ex(evpCipherCtx, evpCipher, NULL,
                                    (const unsigned char *)(cipher.outkey().data()),
                                    (const unsigned char *)(cipher.outiv().data()))) {
            THROW(HdfsIOException, "Cannot init evp cipher decrypt.");
        }
        EVP_CIPHER_CTX_set_padding(evpCipherCtx, 0);
        evpCipherBlockSize = EVP_CIPHER_block_size(evpCipher);
    } catch (...) {
        EVP_CIPHER_CTX_free(evpCipherCtx);
        evpCipherCtx = nullptr;
        throw;
    }
}

CryptoSocketReader::~CryptoSocketReader() {
    if (evpCipherCtx) {
        int unused = 0;
        unsigned char tail[32];
        EVP_DecryptFinal_ex(evpCipherCtx, tail, &unused);
        EVP_CIPHER_CTX_free(evpCipherCtx);
        evpCipherCtx = nullptr;
    }
    underlyingSocket.reset();
}

void CryptoSocketReader::decrypt(char * buf, int32_t size) {
    if (size <= 0) {
        return;
    }
    int updateOutSize = 0;
    unsigned char * p = reinterpret_cast<unsigned char *>(buf);
    if (1 != EVP_DecryptUpdate(evpCipherCtx, p, &updateOutSize, p, size)
            || updateOutSize != size) {
        THROW(HdfsIOException, "Decrypt data error!");
    }
}

int32_t CryptoSocketReader::read(char * b, int32_t s){
    int32_t size = underlyingSocket->read(b, s);
    decrypt(b, size);
    return size;
}

void CryptoSocketReader::readFully(char * b, int32_t s, int timeout) {
    underlyingSocket->readFully(b, s, timeout);
    decrypt(b, s);
}

bool CryptoSocketReader::poll(int timeout){
    return underlyingSocket->poll(true, false, timeout);
}


}
}
