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
#ifndef _HDFS_LIBHDFS3_DATATRANSFER_SASLCLIENT_H_
#define _HDFS_LIBHDFS3_DATATRANSFER_SASLCLIENT_H_

#include "common/Memory.h"
#include "common/SessionConfig.h"
#include "common/Exception.h"
#include "common/ExceptionInternal.h"
#include "client/Token.h"
#include "server/DataEncryptionKey.h"
#include "rpc/RpcAuth.h"
#include "network/Socket.h"
#include "network/TcpSocket.h"
#include "network/SaslClient.h"
#include "network/SocketReader.h"
#include "network/SocketWriter.h"
#include "datatransfer.pb.h"
#include "hdfs.pb.h"

#include <string_view>

namespace Hdfs {
namespace Internal {

// QOP policy helpers — declared at namespace scope so unit tests can reach them.
std::string chooseDataTransferQop(
    const std::string & clientProtection,
    bool encryptDataTransfer,
    bool serverAuth, bool serverInt, bool serverConf);

bool shouldWrapDataTransferSocket(
    const std::string & negotiatedGsaslQop,
    bool hasValidAesCtrCipher);

class Payload
{
public:
    static inline void Parse(const std::string & input, Payload & payload){
        std::string key, value;
        bool inQuotes = false;
        size_t start = 0;

        for (size_t end = 0; end <= input.size(); ++end) {
            const bool atEnd = (end == input.size());

            if (!atEnd && input[end] == '"' && (end == 0 || input[end - 1] != '\\')) {
                inQuotes = !inQuotes;
            }

            if (atEnd || (!inQuotes && input[end] == ',')) {
                std::string token = input.substr(start, end - start);
                size_t pos = token.find('=');
                if (pos != std::string::npos) {
                    key = token.substr(0, pos);
                    value = token.substr(pos + 1);

                    key.erase(key.find_last_not_of(" \n\r\t") + 1);
                    key.erase(0, key.find_first_not_of(" \n\r\t"));
                    value.erase(value.find_last_not_of(" \n\r\t\"") + 1);
                    value.erase(0, value.find_first_not_of(" \n\r\t\""));

                    if (key == "realm")
                    {
                        payload.realms.emplace_back(value);
                    } else if(key == "qop")
                    {
                        payload.qop = value;
                    } else if(key == "algorithm")
                    {
                        payload.algorithm = value;
                    } else if(key == "nonce")
                    {
                        payload.nonce = value;
                    } else if(key == "charset")
                    {
                        payload.charset = value;
                    } else if(key == "cipher")
                    {
                        std::istringstream tokenStream(value);
                        while (std::getline(tokenStream, token, ','))
                        {
                            payload.cipher.emplace_back(token);
                        }
                    } else if(key == "rspauth")
                    {
                        payload.rspauth = value;
                    }
                }
                start = end + 1;
            }
        }
    }

    inline std::string toString()
    {
        std::stringstream ss;
        ss.imbue(std::locale::classic());
        bool first = true;
        for(uint32_t index = 0; index < realms.size(); index++)
        {
            delimiter(&first, ss);
            ss<<"realm=\""<<realms[index]<<"\"";
        }
        
        if(!qop.empty()){
            delimiter(&first, ss);
            ss<<"qop=\""<<qop<<"\"";
        }

        delimiter(&first, ss);
        ss<<"algorithm="<<algorithm;
        ss<<",nonce=\""<<nonce<<"\"";
        ss<<",charset="<<charset;
        ss<<",cipher=\"";
        for(uint32_t index=0; index < cipher.size(); index++)
        {
            if(index>0)
            {
                ss<<",";
            }
            ss<<cipher[index];
        }
        ss<<"\"";
        if(!rspauth.empty())
        {
            ss<<",rspauth=\""<<rspauth<<"\"";
        }
        return ss.str();
    }

    std::vector<std::string> realms;
    std::string algorithm;
    std::string nonce;
    uint32_t maxbuf;
    std::string qop;
    std::string charset;
    std::vector<std::string> cipher;
    std::string rspauth;

private:
    inline void delimiter(bool *first, std::stringstream &ss)
    {
        if (*first){
            *first = false;
        } else {
            ss<<",";
        }
    }
};

class DataTransferSaslClientInternal: public GSaslClient {
public:

    DataTransferSaslClientInternal(
        const std::shared_ptr<Socket> s, 
        const SessionConfig & c, 
        const DataEncryptionKey & k,
        const Token & t, 
        const std::string & p);

    ~DataTransferSaslClientInternal() override;

    std::shared_ptr<Socket> doHandshake() override;

    CipherOptionProto getCipherOption() const {
        return cipherOption;
    }

    std::string getNegotiatedQop() const {
        return negotiatedQop;
    }
private:
    void readAndPrint();
    void sendSaslMessage();
    void sendSaslMessage(const bool handshakeMagic, 
                         const DataTransferEncryptorMessageProto::DataTransferEncryptorStatus status,
                         const std::string & payload, 
                         const std::string & message, 
                         const CipherOptionProto * inCipherOption);
    void sendSaslMessage(const bool handshakeMagic, 
                         const DataTransferEncryptorMessageProto &dataTransferEncryptorMessage);
    void readSaslMessage(DataTransferEncryptorMessageProto &dataTransferEncryptorMessage);
    void selectPayloadCipher(Payload & payload);
    void selectSaslQop(Payload & payload);
    void selectCipherOption(DataTransferEncryptorMessageProto & dataTransferEncryptorMessage, CipherOptionProto & cipherOption);

private:
    int readTimeout;
    int writeTimeout;
    std::string clientId;
    AuthMethod authMethod;
    UserInfo user;
    DataEncryptionKey dataEncryptionKey;
    CipherOptionProto cipherOption;
    std::string negotiatedQop;
};


class DataTransferSaslClient: public SaslClient {
public:

    DataTransferSaslClient(const std::shared_ptr<Socket> s,
                           const SessionConfig & c, 
                           const DataEncryptionKey & k,
                           const Token & t);

    ~DataTransferSaslClient();

    std::shared_ptr<Socket> doHandshake();

    std::string evaluateChallenge(const std::string & chanllege){
        return saslClient->evaluateChallenge(chanllege);
    }

    bool isComplete(){
        return saslClient->isComplete();
    }

    void encrypt(std::string & dst, const std::string_view & src);

    void decrypt(std::string & dst, const std::string_view & src);


private:
    std::shared_ptr<DataTransferSaslClientInternal> saslClient;
    DataEncryptionKey dataEncryptionKey;
};



}
}

#endif /* _HDFS_LIBHDFS3_RPC_SASLCLIENT_H_ */
