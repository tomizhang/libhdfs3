/********************************************************************
 * Copyright (c) 2024 - 2025, Vincent.
 * All rights reserved.
 *
 * Author: Vincent
 ********************************************************************/
/**
 * Unit tests for CryptoSocketReader and CryptoSocketWriter.
 *
 * Covers:
 *   H1/M4 — ValidateCipher throws on bad key
 *   Q2     — CTR stream continuity across multiple Update calls (no per-call Final)
 *   N3     — CryptoSocketWriter::write uses writeFully, not write
 */
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "network/CryptoSocketReader.h"
#include "network/CryptoSocketWriter.h"
#include "server/DataEncryptionKey.h"
#include "common/Exception.h"
#include "common/ExceptionInternal.h"
#include "MockSocket.h"
#include "hdfs.pb.h"

#include <openssl/evp.h>
#include <string>
#include <memory>
#include <vector>

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SaveArg;

using namespace Hdfs;
using namespace Hdfs::Internal;

// Helper: build a 128-bit AES-CTR CipherOptionProto
static CipherOptionProto MakeCipherOption(
        const std::string & inkey, const std::string & iniv,
        const std::string & outkey, const std::string & outiv) {
    CipherOptionProto co;
    co.set_suite(CipherSuiteProto::AES_CTR_NOPADDING);
    co.set_inkey(inkey);
    co.set_iniv(iniv);
    co.set_outkey(outkey);
    co.set_outiv(outiv);
    return co;
}

// ---- Test 1: empty outkey must throw HdfsIOException (M4/H1) ----------------

TEST(TestCryptoSocket, EmptyOutKeyThrows) {
    // outkey is empty — ValidateCipher(forDecrypt=true) checks outkey size
    CipherOptionProto co = MakeCipherOption(
        std::string(16, 'a'), std::string(16, 'b'),   // inkey/iniv (valid)
        std::string(),         std::string(16, 'b'));  // outkey empty → throw

    auto sock = std::make_shared<MockSocket>();
    DataEncryptionKey dek;

    EXPECT_THROW(
        CryptoSocketReader(sock, dek, co, 128),
        HdfsIOException
    );
}

// ---- Test 2: end-to-end CTR stream continuity via Writer + Reader (Q2) ------
//
// writer.write(plain1) then writer.write(plain2) — captures ciphertext bytes
// delivered to writeFully on the mock, then feeds those bytes to a reader mock
// and asserts the recovered plaintext equals plain1 + plain2.
//
// Writer uses inkey/iniv; Reader uses outkey/outiv.
// We use the same key+iv for both so encrypt and decrypt are inverse.

TEST(TestCryptoSocket, CtrStreamContinuity) {
    const std::string key(16, 'k');
    const std::string iv(16, 'v');

    // same key/iv in all slots so writer-inkey == reader-outkey
    CipherOptionProto writerOpt = MakeCipherOption(key, iv, key, iv);
    CipherOptionProto readerOpt = MakeCipherOption(key, iv, key, iv);

    const std::string plain1(20, 'A');
    const std::string plain2(20, 'B');

    // --- Phase 1: encrypt via CryptoSocketWriter, capture ciphertext ----------
    std::vector<std::string> captured;  // one entry per writeFully call

    auto writerSock = std::make_shared<MockSocket>();
    EXPECT_CALL(*writerSock, writeFully(_, _, _))
        .Times(2)
        .WillRepeatedly(Invoke([&captured](const char* buf, int32_t size, int /*timeout*/) {
            captured.emplace_back(buf, static_cast<size_t>(size));
        }));

    DataEncryptionKey dek;
    {
        CryptoSocketWriter writer(writerSock, dek, writerOpt, 128);
        int32_t r1 = writer.write(plain1.data(), static_cast<int32_t>(plain1.size()));
        ASSERT_EQ(r1, static_cast<int32_t>(plain1.size()));
        int32_t r2 = writer.write(plain2.data(), static_cast<int32_t>(plain2.size()));
        ASSERT_EQ(r2, static_cast<int32_t>(plain2.size()));
    }

    ASSERT_EQ(captured.size(), 2u) << "writeFully must be called exactly twice";
    ASSERT_EQ(captured[0].size(), 20u);
    ASSERT_EQ(captured[1].size(), 20u);

    // Concatenate both ciphertext chunks
    std::string ciphertext = captured[0] + captured[1];
    ASSERT_EQ(ciphertext.size(), 40u);

    // --- Phase 2: decrypt via CryptoSocketReader, verify plaintext -----------
    // readFully delivers the full ciphertext in one shot
    auto readerSock = std::make_shared<MockSocket>();
    EXPECT_CALL(*readerSock, readFully(_, _, _))
        .Times(1)
        .WillOnce(Invoke([&ciphertext](char* buf, int32_t size, int /*timeout*/) {
            ASSERT_EQ(static_cast<size_t>(size), ciphertext.size());
            memcpy(buf, ciphertext.data(), ciphertext.size());
        }));

    CryptoSocketReader reader(readerSock, dek, readerOpt, 128);
    std::string recovered(40, '\0');
    reader.readFully(&recovered[0], 40, -1);

    const std::string expected = plain1 + plain2;
    EXPECT_EQ(recovered, expected)
        << "CryptoSocketReader must recover original plaintext across two write() calls";
}

// ---- Test 2b: OpenSSL CTR counter-advance sanity (CtrCounterAdvanceProperty) -
//
// Two separate EVP_EncryptUpdate calls on the same context must produce the
// same bytes as one call over the concatenation.  This is a property of
// OpenSSL AES-CTR that our production code relies on.

TEST(TestCryptoSocket, CtrCounterAdvanceProperty) {
    const std::string key(16, 'k');
    const std::string iv(16, 'v');

    const std::string plain1(20, 'A');
    const std::string plain2(20, 'B');
    const std::string allPlain = plain1 + plain2;

    // Reference: single Update over 40 bytes
    std::string refCipher(40, '\0');
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        ASSERT_NE(ctx, nullptr);
        ASSERT_EQ(1, EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL,
                                        (const unsigned char *)key.data(),
                                        (const unsigned char *)iv.data()));
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outLen = 0;
        ASSERT_EQ(1, EVP_EncryptUpdate(ctx,
                                       (unsigned char *)&refCipher[0], &outLen,
                                       (const unsigned char *)allPlain.data(), 40));
        EXPECT_EQ(40, outLen);
        EVP_CIPHER_CTX_free(ctx);
    }

    // Two-call: Update(20) then Update(20) on the same context
    std::string twoCallCipher(40, '\0');
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        ASSERT_NE(ctx, nullptr);
        ASSERT_EQ(1, EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL,
                                        (const unsigned char *)key.data(),
                                        (const unsigned char *)iv.data()));
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outLen = 0;
        ASSERT_EQ(1, EVP_EncryptUpdate(ctx,
                                       (unsigned char *)&twoCallCipher[0], &outLen,
                                       (const unsigned char *)plain1.data(), 20));
        EXPECT_EQ(20, outLen);
        ASSERT_EQ(1, EVP_EncryptUpdate(ctx,
                                       (unsigned char *)&twoCallCipher[20], &outLen,
                                       (const unsigned char *)plain2.data(), 20));
        EXPECT_EQ(20, outLen);
        EVP_CIPHER_CTX_free(ctx);
    }

    EXPECT_EQ(refCipher, twoCallCipher)
        << "CTR stream must continue across calls without per-call Final";
}

// ---- Test 3: CryptoSocketWriter::write must use writeFully, not write (N3) --

TEST(TestCryptoSocket, WriteUsesWriteFully) {
    const std::string key(16, 'k');
    const std::string iv(16, 'v');
    CipherOptionProto co = MakeCipherOption(key, iv, key, iv);

    auto sock = std::make_shared<MockSocket>();

    // writeFully must be called at least once
    EXPECT_CALL(*sock, writeFully(_, _, _)).Times(1);
    // write() must never be called — if it is, gmock will error (no stub)
    EXPECT_CALL(*sock, write(_, _)).Times(0);

    DataEncryptionKey dek;
    CryptoSocketWriter writer(sock, dek, co, 128);

    const char data[] = "Hello, CTR!";
    int32_t ret = writer.write(data, static_cast<int32_t>(sizeof(data) - 1));
    EXPECT_EQ(ret, static_cast<int32_t>(sizeof(data) - 1));
}
