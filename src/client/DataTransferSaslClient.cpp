/********************************************************************
 * Copyright (c) 2024 - 2025, Vincent.
 * All rights reserved.
 *
 * Author: Vincnet
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

#include "DataTransferSaslClient.h"

#include "common/ClientId.h"
#include "common/Memory.h"
#include "common/Logger.h"
#include "common/DateTime.h"
#include "common/DebugUtil.h"
#include "common/WriteBuffer.h"
#include "network/Socket.h"
#include "network/CryptoSocketReader.h"
#include "network/CryptoSocketWriter.h"
#include "network/SaslSocketReader.h"
#include "network/SaslSocketWriter.h"
#include "network/WrapSocket.h"
#include "datatransfer.pb.h"

#include <krb5/krb5.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <gsasl.h>

#define RPC_HEADER_MAGIC "hrpc"
#define RPC_HEADER_VERSION 9
#define INVALID_RETRY_COUNT -1
#define CONNECTION_CONTEXT_CALL_ID -3

#define DATANODE_VERSION 1
#define DATANODE_PROTOCOL "org.apache.hadoop.hdfs.protocol.DataTransferProtos"
#define BLOCK_TOKEN_KIND "HDFS_BLOCK_TOKEN"

#define DFS_DATA_TRANSFER_PROTECTION_AUTHENTICATION "authentication"
#define DFS_DATA_TRANSFER_PROTECTION_INTEGRITY "integrity"
#define DFS_DATA_TRANSFER_PROTECTION_PRIVACY "privacy"

#define DFS_ENCRYPT_DATA_TRANSFER_ALGORITHM_3DES "3des"
#define DFS_ENCRYPT_DATA_TRANSFER_ALGORITHM_RC4 "rc4"
#define DFS_ENCRYPT_DATA_TRANSFER_ALGORITHM_DES "des"
#define DFS_ENCRYPT_DATA_TRANSFER_ALGORITHM_RC4_56 "rc4-56"
#define DFS_ENCRYPT_DATA_TRANSFER_ALGORITHM_RC4_40 "rc4-40"

#define DFS_ENCRYPT_DATA_TRANSFER_CIPHER_SUITES_AES_CTR_NOPADDING "AES/CTR/NoPadding"

using namespace ::google::protobuf;
using namespace google::protobuf::io;

namespace Hdfs {
namespace Internal {

static void splitQopTokens(const std::string & qop, bool * auth, bool * integ, bool * conf) {
    *auth = *integ = *conf = false;
    std::string token;
    std::istringstream in(qop);
    while (std::getline(in, token, ',')) {
        auto b = token.find_first_not_of(" \t");
        auto e = token.find_last_not_of(" \t");
        if (b == std::string::npos) continue;
        token = token.substr(b, e - b + 1);
        if (token == "auth") *auth = true;
        else if (token == "auth-int") *integ = true;
        else if (token == "auth-conf") *conf = true;
    }
}

std::string chooseDataTransferQop(const std::string & clientProtection,
                                  bool encryptDataTransfer,
                                  bool serverAuth, bool serverInt, bool serverConf) {
    const bool wantConf =
        encryptDataTransfer ||
        strcasecmp(clientProtection.c_str(), DFS_DATA_TRANSFER_PROTECTION_PRIVACY) == 0;
    const bool wantInt =
        !wantConf &&
        strcasecmp(clientProtection.c_str(), DFS_DATA_TRANSFER_PROTECTION_INTEGRITY) == 0;

    if (wantConf) {
        if (!serverConf) {
            THROW(SaslException,
                  "Data transfer privacy required but server QOP has no auth-conf");
        }
        return "qop-conf";
    }
    if (wantInt) {
        if (!serverInt) {
            THROW(SaslException,
                  "Data transfer integrity required but server QOP has no auth-int");
        }
        return "qop-int";
    }
    if (!serverAuth) {
        THROW(SaslException,
              "Data transfer authentication required but server QOP has no auth");
    }
    return "qop-auth";
}

bool shouldWrapDataTransferSocket(const std::string & negotiatedGsaslQop,
                                  bool hasValidAesCtrCipher) {
    return negotiatedGsaslQop == "qop-int" ||
           negotiatedGsaslQop == "qop-conf" ||
           hasValidAesCtrCipher;
}

DataTransferSaslClientInternal::DataTransferSaslClientInternal(const std::shared_ptr<Socket> s,
                                                               const SessionConfig & c, 
                                                               const DataEncryptionKey & k,
                                                               const Token & t, 
                                                               const std::string & p): 
        GSaslClient(s, c, t, p), dataEncryptionKey(k) {
    readTimeout = conf.getInputReadTimeout();
    writeTimeout = conf.getInputWriteTimeout();
    authMethod = RpcAuth::ParseMethod(conf.getRpcAuthMethod());
    if (authMethod == AuthMethod::KERBEROS)
    {
        clientId = GenerateClientId();
        //principal = conf.getDatanodeKerberosPrincipal();
        //LOG(DEBUG1, "DataTransferSaslClientInternal->AuthMethod: KERBEROS, Principal: %s", principal.c_str());
        if (!principal.empty())
        {
            std::string keytab = conf.getDatanodeKerberosKeytabFile();
            if (keytab.empty()) {
                keytab = conf.getNamenodeKerberosKeytabFile();
            }
            if (!keytab.empty())
            {
                LOG(DEBUG1, "DataTransferSaslClientInternal->AuthMethod: KERBEROS, Principal: %s, Keytab: %s", principal.c_str(), keytab.c_str());
                setKRB5ClientKTName(keytab);
                // Note: DataTransfer uses DIGEST-MD5 with tokens/DEK, NOT Kerberos tickets.
                // Do not invoke kinitFromKeytab here to avoid repeated KDC network roundtrips.
            }
        }
        else if(!conf.getKerberosCachePath().empty())
        {
            principal = extractPrincipalFromTicketCache(conf.getKerberosCachePath());
        }
        if(!principal.empty())
        {
            user = UserInfo(principal);
        }
    }
    //LOG(DEBUG1, "DataTransferSaslClientInternal->DataEncryptionKey->KeyId: %u", this->dataEncryptionKey.getKeyId());
    //LOG(DEBUG1, "DataTransferSaslClientInternal->DataEncryptionKey->BlockPoolId: %s", this->dataEncryptionKey.getBlockPoolId().c_str());
    //LOG(DEBUG1, "DataTransferSaslClientInternal->DataEncryptionKey->Nonce: %s", stringToHex(this->dataEncryptionKey.getNonce()).c_str());
    //LOG(DEBUG1, "DataTransferSaslClientInternal->DataEncryptionKey->EncryptionKey: [%s]", stringToHex(this->dataEncryptionKey.getEncryptionKey()).c_str());
    //LOG(DEBUG1, "DataTransferSaslClientInternal->DataEncryptionKey->ExpiryDate: %llu", this->dataEncryptionKey.getExpiryDate());
    //LOG(DEBUG1, "DataTransferSaslClientInternal->DataEncryptionKey->EncryptionAlgorithm: %s", this->dataEncryptionKey.getEncryptionAlgorithm().c_str());
}

DataTransferSaslClientInternal::~DataTransferSaslClientInternal(){
    LOG(DEBUG1, "DataTransferSaslClientInternal::~DataTransferSaslClientInternal");
}

void DataTransferSaslClientInternal::readAndPrint()
{
    //LOG(DEBUG1, "DataTransferSaslClientInternal::readAndPrint Begin");
    char b[1024];
    int32_t length;
    uint32_t count = 0;
    std::cout << std::hex<<std::setfill('0');
    std::cout << std::showbase;
    std::cout << std::uppercase;
    while(true)
    {
        length = underlyingSocketReader->read(b, sizeof(b));
        //LOG(DEBUG1, "DataTransferSaslClientInternal::readAndPrint length: %d", length);
        for(int index=0; index< length; index++)
        {
            std::cout<<"["<<std::setw(2)<<static_cast<int>(static_cast<unsigned char>(b[index]))<<"]";
            if((count+index+1) % 10 == 0){
                std::cout<<std::endl;
            } else {
                std::cout<<" ";
            }
        }
        std::cout<<std::endl;
        count += length;
        //LOG(DEBUG1, "DataTransferSaslClientInternal::readAndPrint count: %d", count);
    }
    std::cout << std::dec;
    std::cout << std::noshowbase;
    std::cout << std::nouppercase;
    //LOG(DEBUG1, "DataTransferSaslClientInternal::readAndPrint End");
}

#if 0
static void logBuffer(std::vector<char> & buffer){
    //LOG(DEBUG1, "DataTransferSaslClientInternal::logBuffer Begin");
    std::cout << std::hex<<std::setfill('0');
    std::cout << std::showbase;
    std::cout << std::uppercase;
    for(size_t index=0; index< buffer.size(); index++)
    {
        std::cout<<"["<<std::setw(2)<<static_cast<int>(static_cast<unsigned char>(buffer[index]))<<"]";
        if((index+1) % 10 == 0){
            std::cout<<std::endl;
        } else {
            std::cout<<" ";
        }
    }
    std::cout << std::dec;
    std::cout << std::noshowbase;
    std::cout << std::nouppercase;
    //LOG(DEBUG1, "DataTransferSaslClientInternal::logBuffer End");
}
#endif

void DataTransferSaslClientInternal::sendSaslMessage()
{
    std::string payload, message;
    sendSaslMessage(true, DataTransferEncryptorMessageProto::DataTransferEncryptorStatus
        ::DataTransferEncryptorMessageProto_DataTransferEncryptorStatus_SUCCESS, payload, message, NULL);
}

void DataTransferSaslClientInternal::sendSaslMessage(const bool handshakeMagic, 
                                        const DataTransferEncryptorMessageProto::DataTransferEncryptorStatus status,
                                        const std::string & payload, 
                                        const std::string & message, 
                                        const CipherOptionProto * inCipherOption)
{
    //LOG(DEBUG1, "DataTransferSaslClientInternal::sendSaslMessage Begin");
    DataTransferEncryptorMessageProto dataTransferEncryptorMessage;
    dataTransferEncryptorMessage.set_status(status);
    dataTransferEncryptorMessage.set_payload(payload);
    if( message.size()>0 ){
        dataTransferEncryptorMessage.set_message(message);
    }
    if (inCipherOption != NULL)
    {
        CipherOptionProto *outCipherOption = dataTransferEncryptorMessage.add_cipheroption();
        outCipherOption->set_suite(inCipherOption->suite());
        if (inCipherOption->has_inkey())
        {
            outCipherOption->set_inkey(inCipherOption->inkey());
        }
        if (inCipherOption->has_iniv())
        {
            outCipherOption->set_iniv(inCipherOption->iniv());
        }
        if (inCipherOption->has_outkey())
        {
            outCipherOption->set_outkey(inCipherOption->outkey());
        }
        if (inCipherOption->has_outiv())
        {
            outCipherOption->set_outiv(inCipherOption->outiv());
        }
    }

    sendSaslMessage(handshakeMagic, dataTransferEncryptorMessage);
    //LOG(DEBUG1, "DataTransferSaslClientInternal::sendSaslMessage End");
}

void DataTransferSaslClientInternal::sendSaslMessage(const bool handshakeMagic, 
                                        const DataTransferEncryptorMessageProto &dataTransferEncryptorMessage)
{
    //LOG(DEBUG1, "DataTransferSaslClientInternal::sendSaslMessage Begin");
    WriteBuffer buffer;
    if(handshakeMagic)
    {
        unsigned char magic[] = {0xDE, 0xAD, 0xBE, 0xEF};
        buffer.write(magic, sizeof(magic));
    }
    int32_t size = dataTransferEncryptorMessage.ByteSize();
    buffer.writeVarint32(size);
    dataTransferEncryptorMessage.SerializeToArray(buffer.alloc(size), size);
    underlyingSocketWriter->writeFully(buffer.getBuffer(0), buffer.getDataSize(0), writeTimeout);
    //LOG(DEBUG1, "DataTransferSaslClientInternal::sendSaslMessage End");
}

void DataTransferSaslClientInternal::readSaslMessage(DataTransferEncryptorMessageProto &dataTransferEncryptorMessage)
{
    //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage Begin");
    std::vector<char> buffer(128);
    uint32_t totalen;
    totalen =  std::static_pointer_cast<BufferedSocketReader>(underlyingSocketReader)->readVarint32(readTimeout);
    //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage read size: %d", totalen);
    buffer.resize(totalen);
    underlyingSocketReader->readFully(&buffer[0], totalen, readTimeout);
    if (!dataTransferEncryptorMessage.ParseFromArray(&buffer[0], totalen))
    {
        THROW(HdfsIOException, "Cannot parse data transfer encryptor message.");
    }

    if(dataTransferEncryptorMessage.status() == DataTransferEncryptorMessageProto::DataTransferEncryptorStatus
        ::DataTransferEncryptorMessageProto_DataTransferEncryptorStatus_ERROR_UNKNOWN_KEY)
    {
        THROW(HdfsInvalidEncryptionKey, "Data transfer encryptor unknown key error: %s", dataTransferEncryptorMessage.message().c_str());
    }else if(dataTransferEncryptorMessage.status() == DataTransferEncryptorMessageProto::DataTransferEncryptorStatus
        ::DataTransferEncryptorMessageProto_DataTransferEncryptorStatus_ERROR)
    {
        THROW(HdfsIOException, "Data transfer encryptor error: %s", dataTransferEncryptorMessage.message().c_str());
    }
    
    //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage->payload: %s", dataTransferEncryptorMessage.payload().c_str());

    for(int index=0; index<dataTransferEncryptorMessage.cipheroption().size();index++)
    {
        CipherOptionProto cipherOption = dataTransferEncryptorMessage.cipheroption().Get(index);
        if (cipherOption.suite()==CipherSuiteProto::AES_CTR_NOPADDING)
        {
            //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage->cipherOption->cipherSuite: AES_CTR_NOPADDING");
        } else {
            //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage->cipherOption->cipherSuite: UNKNOWN");
        }
        if (cipherOption.has_inkey())
        {
            //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage->cipherOption->inkey: %s", stringToHex(cipherOption.inkey()).c_str());
        }
        if (cipherOption.has_iniv())
        {
            //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage->cipherOption->iniv: %s", stringToHex(cipherOption.iniv()).c_str());
        }
        if (cipherOption.has_outkey())
        {
            //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage->cipherOption->outkey: %s", stringToHex(cipherOption.outkey()).c_str());
        }
        if (cipherOption.has_outiv())
        {
            //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage->cipherOption->outiv: %s", stringToHex(cipherOption.outiv()).c_str());
        }
    }
    //LOG(DEBUG1, "DataTransferSaslClientInternal::readSaslMessage End");
}

void DataTransferSaslClientInternal::selectPayloadCipher(Payload & payload){
    //LOG(DEBUG1, "DataTransferSaslClientInternal::selectPayloadCipher Begin");
    //LOG(DEBUG1, "DataTransferSaslClientInternal::selectPayloadCipher->DfsEncryptDataTransferAlgorithm: [%s]", 
    //    conf.getDfsEncryptDataTransferAlgorithm().c_str());
    if (payload.cipher.size() > 0 && !conf.getDfsEncryptDataTransferAlgorithm().empty()) {
        bool payloadCipherFound = false;
        for (size_t index = 0; index < payload.cipher.size(); index++){
            if (strcasecmp(payload.cipher[index].c_str(), conf.getDfsEncryptDataTransferAlgorithm().c_str()) == 0 ){
                payloadCipherFound = true;
                break;
            }
        }
        if (payloadCipherFound) {
            //LOG(DEBUG1, "DataTransferSaslClientInternal::selectPayloadCipher Found!");
            payload.cipher.clear();
            payload.cipher.emplace_back(conf.getDfsEncryptDataTransferAlgorithm());
        } else {
            //LOG(DEBUG1, "DataTransferSaslClientInternal::selectPayloadCipher Not Found!");
        }
    }
    //LOG(DEBUG1, "DataTransferSaslClientInternal::selectPayloadCipher End");
}

void DataTransferSaslClientInternal::selectSaslQop(Payload & payload){
    bool serverAuth, serverInt, serverConf;
    splitQopTokens(payload.qop, &serverAuth, &serverInt, &serverConf);
    const std::string qop = chooseDataTransferQop(
        conf.getDfsDataTransferProtection(),
        conf.isDfsEncryptDataTransfer(),
        serverAuth, serverInt, serverConf);
    gsasl_property_set(session, GSASL_QOP, qop.c_str());
    negotiatedQop = qop;
}

void DataTransferSaslClientInternal::selectCipherOption(DataTransferEncryptorMessageProto & dataTransferEncryptorMessage, 
                                                        CipherOptionProto & cipherOption){
    if (dataTransferEncryptorMessage.cipheroption_size() > 0) {
        for(int index=0; index<dataTransferEncryptorMessage.cipheroption().size();index++)
        {
            CipherOptionProto co = dataTransferEncryptorMessage.cipheroption().Get(index);
            if (co.suite() == CipherSuiteProto::AES_CTR_NOPADDING && 
                (strcasecmp(DFS_ENCRYPT_DATA_TRANSFER_CIPHER_SUITES_AES_CTR_NOPADDING, conf.getDfsEncryptDataTransferCipherSuites().c_str()) == 0)){
                cipherOption = co;
                std::string inKeybuffer, outKeybuffer;
                decrypt(inKeybuffer, cipherOption.inkey());
                const size_t expectedBytes =
                    static_cast<size_t>(conf.getDfsEncryptDataTransferCipherKeyBitlength()) / 8;
                if (inKeybuffer.size() != expectedBytes) {
                    THROW(SaslException,
                          "AES-CTR inkey size mismatch: got %zu bytes, expected %zu",
                          inKeybuffer.size(), expectedBytes);
                }
                cipherOption.set_inkey(std::string(inKeybuffer.data(), inKeybuffer.size()));
                decrypt(outKeybuffer, cipherOption.outkey());
                if (outKeybuffer.size() != expectedBytes) {
                    THROW(SaslException,
                          "AES-CTR outkey size mismatch: got %zu bytes, expected %zu",
                          outKeybuffer.size(), expectedBytes);
                }
                cipherOption.set_outkey(std::string(outKeybuffer.data(), outKeybuffer.size()));
            } else if (co.suite() == CipherSuiteProto::CIPHER_SUITE_UNKNOWN && conf.getDfsEncryptDataTransferCipherSuites().empty()){
                cipherOption = co;
            }
        }
    }
}

std::shared_ptr<Socket> DataTransferSaslClientInternal::doHandshake(){
    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake Begin");
    if(complete || ctx!=nullptr || session != nullptr) {
        THROW(SaslException, "SaslClient is already complete or initialized.");
    }
    DataTransferEncryptorMessageProto dataTransferEncryptorMessage;
    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake->Send [1]");
    sendSaslMessage();
    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake->Read [1]");
    readSaslMessage(dataTransferEncryptorMessage);
    Payload payload;
    Payload::Parse(dataTransferEncryptorMessage.payload(), payload);
    selectPayloadCipher(payload);
    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake->Payload: %s", dataTransferEncryptorMessage.payload().c_str());
    
    //取得 qop 构建 sasl
    int rc;
    rc = gsasl_init(&ctx);
    if (rc != GSASL_OK) {
        THROW(SaslException, "cannot initialize libgsasl");
    }
    //rc = gsasl_nonce(const_cast<char*>(payload.nonce.c_str()), payload.nonce.size());

    if ((rc = gsasl_client_start(ctx, "DIGEST-MD5", &session)) != GSASL_OK) {
        THROW(SaslException, "Cannot initialize client (%d): %s", rc, gsasl_strerror(rc));
    }

    std::string identifier;
    std::string password;
    if (dataEncryptionKey.getKeyId() > 0) {
        std::stringstream ss;
        ss << static_cast<int32_t>(dataEncryptionKey.getKeyId()) << " ";
        ss << dataEncryptionKey.getBlockPoolId() << " ";
        ss << base64Encode(dataEncryptionKey.getNonce());
        identifier = ss.str();
        password = base64Encode(dataEncryptionKey.getEncryptionKey());
        LOG(DEBUG1, "DataTransferSaslClientInternal: using DataEncryptionKey (keyId=%u, blockPool=%s)",
            dataEncryptionKey.getKeyId(), dataEncryptionKey.getBlockPoolId().c_str());
    } else {
        identifier = base64Encode(token.getIdentifier());
        password = base64Encode(token.getPassword());
        LOG(DEBUG1, "DataTransferSaslClientInternal: fallback to BlockToken (identifier_len=%zu)",
            token.getIdentifier().size());
    }
    
    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake->GSASL_REALM: [%s]", payload.realms.empty() ? "" : payload.realms[0].c_str());
    
    gsasl_property_set(session, GSASL_AUTHID, identifier.c_str());
    // NOTE: In DIGEST-MD5 token authentication, GSASL_AUTHZID must NOT be set to DataNode principal!
    // Setting authzid causes DataNode to fail authorization or reject digest verification.
    gsasl_property_set(session, GSASL_PASSWORD, password.c_str());
    if (!payload.realms.empty()) {
        gsasl_property_set(session, GSASL_REALM, payload.realms[0].c_str());
    }
    gsasl_property_set(session, GSASL_HOSTNAME, "0");
    gsasl_property_set(session, GSASL_SERVICE, "hdfs");
    selectSaslQop(payload);

    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake->evaluateChallenge [1]");
    std::string challenge = dataTransferEncryptorMessage.payload();
    challenge = evaluateChallenge(challenge);

    CipherOptionProto proposedCipher;
    if (strcasecmp(conf.getDfsEncryptDataTransferCipherSuites().c_str(),
                   DFS_ENCRYPT_DATA_TRANSFER_CIPHER_SUITES_AES_CTR_NOPADDING) == 0) {
        proposedCipher.set_suite(CipherSuiteProto::AES_CTR_NOPADDING);
    }

    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake->Send [2]");
    sendSaslMessage(false,
        DataTransferEncryptorMessageProto::DataTransferEncryptorStatus
        ::DataTransferEncryptorMessageProto_DataTransferEncryptorStatus_SUCCESS,
        challenge, std::string(), proposedCipher.has_suite() ? &proposedCipher : NULL);
    
    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake->Read [2]");
    readSaslMessage(dataTransferEncryptorMessage);
    Payload step2Payload;
    Payload::Parse(dataTransferEncryptorMessage.payload(), step2Payload);
    if (step2Payload.rspauth.empty()) {
        THROW(SaslException, "Sasl failed! rspauth is empty!");
    }
    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake->evaluateChallenge [2]");
    challenge = evaluateChallenge(dataTransferEncryptorMessage.payload());
    complete = true;
    selectCipherOption(dataTransferEncryptorMessage, cipherOption);
    //LOG(INFO, "DataTransferSaslClientInternal::doHandshake End");
    return underlyingSocket;
}

DataTransferSaslClient::DataTransferSaslClient(const std::shared_ptr<Socket> s,
                                               const SessionConfig & c, 
                                               const DataEncryptionKey & k,
                                               const Token & t):
    SaslClient(s, c, t, c.getDatanodeKerberosPrincipal()),
    dataEncryptionKey(k),
    saslClient(std::make_shared<DataTransferSaslClientInternal>(s, c, k, t, c.getDatanodeKerberosPrincipal())) {

}

DataTransferSaslClient::~DataTransferSaslClient(){
    saslClient.reset();
    underlyingSocket.reset();
}

std::shared_ptr<Socket> DataTransferSaslClient::doHandshake(){
    //LOG(DEBUG1, "DataTransferSaslClient::doHandshake Begin");
    steady_clock::time_point t0 = steady_clock::now();
    if (saslClient->isComplete()) {
        THROW(SaslException, "Do not re handshake!");
    }
    std::shared_ptr<Socket> socket = saslClient->doHandshake();
    //LOG(DEBUG1, "DataTransferSaslClient::doHandshake->socket: [%d]", socket);
    complete = saslClient->isComplete();
    if (!complete) {
        LOG(LOG_ERROR, "DataTransferSaslClient::doHandshake->Handshake failed!");
        THROW(SaslException, "Handshake failed!");
    }

    CipherOptionProto cipherOption = saslClient->getCipherOption();
    const size_t expectedBytes =
        static_cast<size_t>(conf.getDfsEncryptDataTransferCipherKeyBitlength()) / 8;
    const bool validAes =
        cipherOption.has_suite() &&
        cipherOption.suite() == CipherSuiteProto::AES_CTR_NOPADDING &&
        cipherOption.outkey().size() == expectedBytes &&
        cipherOption.outiv().size() == 16 &&
        cipherOption.inkey().size() == expectedBytes &&
        cipherOption.iniv().size() == 16;

    const std::string qop = saslClient->getNegotiatedQop();

    steady_clock::time_point t1 = steady_clock::now();
    LOG(DEBUG1, "DataTransferSaslClient::doHandshake completed in %ld ms (qop=%s, aes=%s)",
        (long)ToMilliSeconds(t0, t1), qop.c_str(), validAes ? "true" : "false");

    if (!shouldWrapDataTransferSocket(qop, validAes)) {
        if (conf.isDfsEncryptDataTransfer()) {
            THROW(SaslException,
                  "dfs.encrypt.data.transfer is true but handshake produced no privacy layer");
        }
        return socket;
    }

    std::shared_ptr<SocketReader> socketReader;
    std::shared_ptr<SocketWriter> socketWriter;
    if (validAes) {
        socketReader = std::make_shared<CryptoSocketReader>(socket,
            dataEncryptionKey, cipherOption, conf.getDfsEncryptDataTransferCipherKeyBitlength());
        socketWriter = std::make_shared<CryptoSocketWriter>(socket,
            dataEncryptionKey, cipherOption, conf.getDfsEncryptDataTransferCipherKeyBitlength());
    } else {
        socketReader = std::make_shared<SaslSocketReader>(socket, saslClient);
        socketWriter = std::make_shared<SaslSocketWriter>(socket, saslClient);
    }
    return std::make_shared<WrapSocket>(socket, socketReader, socketWriter);
}

void DataTransferSaslClient::encrypt(std::string & dst, const std::string_view & src){
    saslClient->encrypt(dst, src);
}

void DataTransferSaslClient::decrypt(std::string & dst, const std::string_view & src){
    saslClient->decrypt(dst, src);
}



}
}

