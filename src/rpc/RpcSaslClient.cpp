/********************************************************************
 * Copyright (c) 2013 - 2014, Pivotal Inc.
 * All rights reserved.
 *
 * Author: Zhanwei Wang
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

#include "common/Memory.h"
#include "common/SessionConfig.h"
#include "common/Logger.h"

#include "common/Exception.h"
#include "common/ExceptionInternal.h"
#include "network/Socket.h"
#include "network/SocketReader.h"
#include "network/SocketWriter.h"
#include "network/SaslClient.h"
#include "RpcSaslClient.h"
#include "IpcConnectionContext.pb.h"
#include "RpcChannel.h"
#include "RpcChannelKey.h"
#include "RpcClient.h"
#include "RpcContentWrapper.h"
#include "RpcHeader.pb.h"
#include "server/RpcHelper.h"
#include "common/Thread.h"
#include "common/WriteBuffer.h"

#include <algorithm>
#include <cctype>

#include <google/protobuf/io/coded_stream.h>

#define SASL_SUCCESS 0
#define RPC_HEADER_MAGIC "hrpc"
#define RPC_HEADER_VERSION 9
#define SERIALIZATION_TYPE_PROTOBUF 0
#define CONNECTION_CONTEXT_CALL_ID -3

using namespace ::google::protobuf;
using namespace google::protobuf::io;

namespace Hdfs {
namespace Internal {

static exception_ptr HandlerRpcResponseException(exception_ptr e) {
    exception_ptr retval = e;

    try {
        rethrow_exception(e);
    } catch (const HdfsRpcServerException & e) {
        UnWrapper < NameNodeStandbyException, RpcNoSuchMethodException, UnsupportedOperationException,
                  AccessControlException, SafeModeException, SaslException > unwrapper(e);

        try {
            unwrapper.unwrap(__FILE__, __LINE__);
        } catch (const NameNodeStandbyException & e) {
            retval = current_exception();
        } catch (const UnsupportedOperationException & e) {
            retval = current_exception();
        } catch (const AccessControlException & e) {
            retval = current_exception();
        } catch (const SafeModeException & e) {
            retval = current_exception();
        } catch (const SaslException & e) {
            retval = current_exception();
        } catch (const RpcNoSuchMethodException & e) {
            retval = current_exception();
        } catch (const HdfsIOException & e) {
        }
    }

    return retval;
}

RpcSaslClient::RpcSaslClient(const std::shared_ptr<Socket> s, 
                             const RpcChannelKey & k,
                             RpcClient & cli,
                             const SessionConfig & c): 
                             GSaslClient(s, c, Token(), k.getAuth().getUser().getPrincipal()), 
    rpcClient(cli), rpcChannelKey(k), rpcConfig(k.getConf()), rpcServer(k.getServer()) {
    rpcAuth = k.getAuth();
}

const RpcAuth &RpcSaslClient::getAuth() const {
    return rpcAuth;
}

RpcRemoteCallPtr RpcSaslClient::getPendingCall(int32_t id) {
    unordered_map<int32_t, RpcRemoteCallPtr>::iterator it;
    it = pendingCalls.find(id);

    if (it == pendingCalls.end()) {
        THROW(HdfsRpcException,
              "RPC channel to \"%s:%s\" got protocol mismatch: RPC channel cannot find pending call: id = %d.",
              rpcChannelKey.getServer().getHost().c_str(), rpcChannelKey.getServer().getPort().c_str(), static_cast<int>(id));
    }

    RpcRemoteCallPtr rc = it->second;
    pendingCalls.erase(it);
    return rc;
}

std::string RpcSaslClient::saslEvaluateToken(RpcSaslProto & response, bool serverIsDone) {
    std::string token;
    LOG(DEBUG1, "RpcSaslClient::saslEvaluateToken Begin");
    if (response.has_token()) {
        LOG(DEBUG1, "RpcSaslClient::saslEvaluateToken->token From: [%s]", response.token().c_str());
        token = evaluateChallenge(response.token());
        LOG(DEBUG1, "RpcSaslClient::saslEvaluateToken->token To: [%s]", token.c_str());
    } else if (!serverIsDone) {
        THROW(SaslException, "Server challenge contains no token");
    }

    if (serverIsDone) {
        if (!isComplete()) {
            THROW(SaslException, "Client is out of sync with server");
        }
        if (!token.empty()) {
            THROW(SaslException, "Client generated spurious response");
        }
    }
    LOG(DEBUG1, "RpcSaslClient::saslEvaluateToken End");
    return token;
}

/**
 * Write the connection header - this is sent when connection is established
 * +----------------------------------+
 * |  "hrpc" 4 bytes                  |
 * +----------------------------------+
 * |  Version (1 byte)                |
 * +----------------------------------+
 * |  Service Class (1 byte)          |
 * +----------------------------------+
 * |  AuthProtocol (1 byte)           |
 * +----------------------------------+
 */
void RpcSaslClient::sendConnectionHeader(const RpcAuth &auth) {
    LOG(DEBUG1, "RpcSaslClient::sendConnectionHeader Begin.");
    WriteBuffer buffer;
    buffer.write(RPC_HEADER_MAGIC, strlen(RPC_HEADER_MAGIC));
    buffer.write(static_cast<char>(RPC_HEADER_VERSION));
    buffer.write(static_cast<char>(0));  //for future feature
    buffer.write(static_cast<char>(auth.getProtocol()));
    underlyingSocketWriter->writeFully(
        buffer.getBuffer(0), buffer.getDataSize(0), rpcChannelKey.getConf().getWriteTimeout());
    LOG(DEBUG1, "RpcSaslClient::sendConnectionHeader End.");
}

void RpcSaslClient::sendSaslMessage(RpcSaslProto * msg, Message * resp) {
    LOG(DEBUG1, "RpcSaslClient::sendSaslMessage Begin");
    WriteBuffer buffer;
    RpcRequestHeaderProto rpcHeader;
    rpcHeader.set_callid(AuthProtocol::SASL);
    rpcHeader.set_clientid(rpcClient.getClientId());
    rpcHeader.set_retrycount(INVALID_RETRY_COUNT);
    rpcHeader.set_rpckind(RPC_PROTOCOL_BUFFER);
    rpcHeader.set_rpcop(RpcRequestHeaderProto_OperationProto_RPC_FINAL_PACKET);
    RpcContentWrapper wrapper(&rpcHeader, msg);
    const int totalLen = wrapper.getLength();
    buffer.writeBigEndian(totalLen);
    wrapper.writeTo(buffer);
    underlyingSocketWriter->writeFully(buffer.getBuffer(0), buffer.getDataSize(0), rpcChannelKey.getConf().getWriteTimeout());
    RpcRemoteCallPtr call(
        new RpcRemoteCall(RpcCall(false, "sasl message", NULL, resp),
                          AuthProtocol::SASL, rpcClient.getClientId()));
    pendingCalls[AuthProtocol::SASL] = call;
    LOG(DEBUG1, "RpcSaslClient::sendSaslMessage End");
}

void RpcSaslClient::readSaslResponse(bool writeLock) {
    LOG(DEBUG1, "RpcSaslClient::readSaslResponse Begin");
    int readTimeout = rpcChannelKey.getConf().getReadTimeout();
    std::vector<char> buffer(128);
    RpcResponseHeaderProto curRespHeader;
    RpcResponseHeaderProto::RpcStatusProto status;

    uint32_t headerSize = 0;
    std::shared_ptr<BufferedSocketReader> reader = std::static_pointer_cast<BufferedSocketReader>(underlyingSocketReader);
    uint32_t totalen = reader->readBigEndianInt32(readTimeout);
    /*
     * read response header
     */
    headerSize = reader->readVarint32(readTimeout);
    buffer.resize(headerSize);
    reader->readFully(&buffer[0], headerSize, readTimeout);

    if (!curRespHeader.ParseFromArray(&buffer[0], headerSize)) {
        THROW(HdfsRpcException,
              "RPC channel to \"%s:%s\" got protocol mismatch: RPC channel cannot parse response header.",
              rpcChannelKey.getServer().getHost().c_str(), rpcChannelKey.getServer().getPort().c_str())
    }

    //lastActivity = steady_clock::now();
    status = curRespHeader.status();

    if (RpcResponseHeaderProto_RpcStatusProto_SUCCESS == status) {
        uint32_t bodySize = 0;
        //LOG(DEBUG1, "RpcSaslClient::readSaslResponse->status: [SUCCESS]");
        /*
         * on success, read response body
         */
        RpcRemoteCallPtr rc;

        if (writeLock) {
            lock_guard<mutex> lock(writeMut);
            rc = getPendingCall(curRespHeader.callid());
        } else {
            rc = getPendingCall(curRespHeader.callid());
        }

        bodySize = reader->readVarint32(readTimeout);
        buffer.resize(bodySize);

        if (bodySize > 0) {
            reader->readFully(&buffer[0], bodySize, readTimeout);
        }

        Message * response = rc->getCall().getResponse();

        if (!response->ParseFromArray(&buffer[0], bodySize)) {
            THROW(HdfsRpcException,
                  "RPC channel to \"%s:%s\" got protocol mismatch: rpc channel cannot parse response.",
                  rpcChannelKey.getServer().getHost().c_str(), rpcChannelKey.getServer().getPort().c_str())
        }

        rc->done();

        //LOG(DEBUG1, "RpcSaslClient::readSaslResponse-response: [%s]", response->SerializeAsString().c_str());

    } else {
        /*
         * on error, read error class and message
         */
        std::string errClass, errMessage;
        errClass = curRespHeader.exceptionclassname();
        errMessage = curRespHeader.errormsg();

        //LOG(DEBUG1, "RpcSaslClient::readSaslResponse->errClass: [%s]", errClass.c_str());
        //LOG(DEBUG1, "RpcSaslClient::readSaslResponse->errMessage: [%s]", errMessage.c_str());

        if (RpcResponseHeaderProto_RpcStatusProto_ERROR == status) {
            //LOG(DEBUG1, "RpcSaslClient::readSaslResponse->status: [ERROR]");
            RpcRemoteCallPtr rc;
            {
                lock_guard<mutex> lock(writeMut);
                rc = getPendingCall(curRespHeader.callid());
            }

            try {
                THROW(HdfsRpcServerException, "%s: %s",
                      errClass.c_str(), errMessage.c_str());
            } catch (HdfsRpcServerException & e) {
                e.setErrClass(errClass);
                e.setErrMsg(errMessage);
                rc->cancel(HandlerRpcResponseException(current_exception()));
            }
        } else { /*fatal*/
            //LOG(DEBUG1, "RpcSaslClient::readSaslResponse->status: [FATAL]");
            assert(RpcResponseHeaderProto_RpcStatusProto_FATAL == status);

            if (errClass.empty()) {
                THROW(HdfsRpcException, "%s: %s",
                      errClass.c_str(), errMessage.c_str());
            }

            try {
                THROW(HdfsRpcServerException, "%s: %s", errClass.c_str(),
                      errMessage.c_str());
            } catch (HdfsRpcServerException & e) {
                e.setErrClass(errClass);
                e.setErrMsg(errMessage);
                rethrow_exception(HandlerRpcResponseException(current_exception()));
            }
        }
    }
    LOG(DEBUG1, "RpcSaslClient::readSaslResponse End");
}

const RpcSaslProto_SaslAuth * RpcSaslClient::findSaslAuth(
    const RepeatedPtrField<RpcSaslProto_SaslAuth> * auths){
    const RpcSaslProto_SaslAuth * auth = NULL;

    for (int i = 0; i < auths->size(); ++i) {
        auth = &auths->Get(i);
        RpcAuth method(RpcAuth::ParseMethod(auth->method()));

        if (method.getMethod() == AuthMethod::TOKEN && rpcChannelKey.hasToken()) {
            break;
        }
        if (method.getMethod() == AuthMethod::KERBEROS) {
            break;
        }
        if (method.getMethod() == AuthMethod::SIMPLE) {
            return auth;
        }
        if (method.getMethod() == AuthMethod::UNKNOWN) {
            return auth;
        }
        auth = NULL;
    }

    if (!auth) {
        std::stringstream ss;
        ss.imbue(std::locale::classic());
        ss << "Client cannot authenticate via: ";

        for (int i = 0; i < auths->size(); ++i) {
            auth = &auths->Get(i);
            ss << auth->mechanism() << ", ";
        }

        THROW(AccessControlException, "%s", ss.str().c_str());
    }
    return auth;
}

std::shared_ptr<Socket> RpcSaslClient::doHandshake() {
    LOG(DEBUG1, "RpcSaslClient::doHandshake Begin");
    
    if (rpcChannelKey.hasToken()) {
        rpcAuth.setMethod(AuthMethod::TOKEN);
    }

    sendConnectionHeader(rpcAuth);
    if (rpcAuth.getProtocol() != AuthProtocol::SASL) {
        return underlyingSocket;
    }

    RpcSaslProto negotiateRequest, response, msg;
    negotiateRequest.set_state(RpcSaslProto_SaslState_NEGOTIATE);
    LOG(DEBUG1, "RpcSaslClient::doHandshake->response->state: [%d]", response.state());
    sendSaslMessage(&negotiateRequest, &response);
    bool done = false;
    do {
        msg.Clear();
        readSaslResponse(false);
        LOG(DEBUG1, "RpcSaslClient::doHandshake->response->state: [%d]", response.state());
        if (response.has_token()) {
            LOG(DEBUG1, "RpcSaslClient::doHandshake->response->token: [%s]", response.token().c_str());
        }
        switch (response.state()) {
        case RpcSaslProto_SaslState_NEGOTIATE: {
            LOG(DEBUG1, "RpcSaslClient::doHandshake->response->state: [NEGOTIATE]");
            const RpcSaslProto_SaslAuth * saslAuth = findSaslAuth(&response.auths());
            LOG(DEBUG1, "RpcSaslClient::doHandshake->saslAuth->challenge: [%s]", saslAuth->challenge().c_str());
            rpcAuth = RpcAuth(RpcAuth::ParseMethod(saslAuth->method()));
            LOG(DEBUG1, "RpcSaslClient::doHandshake->rpcAuth->method: [%d]", rpcAuth.getMethod());
            int rc = gsasl_init(&ctx);
            if (rc != GSASL_OK) {
                THROW(SaslException, "cannot initialize libgsasl");
            }
            switch (rpcAuth.getMethod()) {
            case AuthMethod::KERBEROS:
                initKerberos(*saslAuth);
                break;

            case AuthMethod::TOKEN:
                initDigestMd5(*saslAuth);
                break;

            default:
                THROW(SaslException, "unknown auth method.");
                break;
            }
            
            if (rpcAuth.getMethod() == AuthMethod::SIMPLE) {
                done = true;
            } else if (rpcAuth.getMethod() == AuthMethod::UNKNOWN) {
                THROW(SaslException, "Unknown auth mechanism");
            } else {
                std::string respToken;
                RpcSaslProto_SaslAuth * respAuth = msg.add_auths();
                respAuth->CopyFrom(*saslAuth);
                std::string challenge;

                if (saslAuth->has_challenge()) {
                    challenge = saslAuth->challenge();
                    respAuth->clear_challenge();
                }
                respToken = evaluateChallenge(challenge);
                if (!respToken.empty()) {
                    msg.set_token(respToken);
                }
                msg.set_state(RpcSaslProto_SaslState_INITIATE);
            }
            break;
        }

        case RpcSaslProto_SaslState_CHALLENGE: {
            LOG(DEBUG1, "RpcSaslClient::doHandshake->response->state: [CHALLENGE]");
            std::string token = saslEvaluateToken(response, false);
            msg.set_token(token);
            msg.set_state(RpcSaslProto_SaslState_RESPONSE);
            break;
        }

        case RpcSaslProto_SaslState_SUCCESS:
            LOG(DEBUG1, "RpcSaslClient::doHandshake->response->state: [SUCCESS]");
            complete = true;
            if (rpcAuth.getMethod() != AuthMethod::SIMPLE) {
                saslEvaluateToken(response, true);
            }
            done = true;
            break;

        default:
            break;
        }

        if (!done) {
            response.Clear();
            sendSaslMessage(&msg, &response);
        }
    } while (!done);
    
    LOG(DEBUG1, "RpcSaslClient::doHandshake End");
    return underlyingSocket;
}

RpcSaslClient::~RpcSaslClient() {
    LOG(DEBUG1, "RpcSaslClient::~RpcSaslClient");
}

void RpcSaslClient::initKerberos(const RpcSaslProto_SaslAuth & auth) {
    LOG(DEBUG1, "RpcSaslClient::initKerberos Begin");
    int rc;

    /* Create new authentication session. */
    if ((rc = gsasl_client_start(ctx, auth.mechanism().c_str(), &session)) != GSASL_OK) {
        THROW(SaslException, "Cannot initialize client (%d): %s", rc, gsasl_strerror(rc));
    }
    std::string keytab = conf.getNamenodeKerberosKeytabFile();
    if (keytab.empty()) {
        keytab = conf.getDatanodeKerberosKeytabFile();
    }
    if (!keytab.empty()) {
        setKRB5ClientKTName(keytab);
        kinitFromKeytab(principal, keytab, conf.getKerberosCachePath());
    }
    LOG(DEBUG1, "RpcSaslClient::initKerberos->PRINCIPAL: %s", principal.c_str());
    LOG(DEBUG1, "RpcSaslClient::initKerberos->GSASL_SERVICE: %s", auth.protocol().c_str());
    LOG(DEBUG1, "RpcSaslClient::initKerberos->GSASL_HOSTNAME: %s", auth.serverid().c_str());
    gsasl_property_set(session, GSASL_AUTHID, principal.c_str());
    gsasl_property_set(session, GSASL_SERVICE, auth.protocol().c_str());
    gsasl_property_set(session, GSASL_HOSTNAME, auth.serverid().c_str());

    LOG(DEBUG1, "RpcSaslClient::initKerberos End");
}

void RpcSaslClient::initDigestMd5(const RpcSaslProto_SaslAuth & auth) {
    LOG(DEBUG1, "RpcSaslClient::initDigestMd5 Begin");
    int rc;

    if ((rc = gsasl_client_start(ctx, auth.mechanism().c_str(), &session)) != GSASL_OK) {
        THROW(SaslException, "Cannot initialize client (%d): %s", rc, gsasl_strerror(rc));
    }
    //LOG(DEBUG1, "RpcSaslClient::initDigestMd5->PRINCIPAL: %s", principal.c_str());
    //gsasl_property_set(session, GSASL_AUTHZID, principal.c_str());
    if (rpcChannelKey.hasToken()) {
        Token token = rpcChannelKey.getToken();
        //std::string identifier = base64Encode(principal);
        std::string identifier = base64Encode(token.getIdentifier());
        std::string password = base64Encode(token.getPassword());
        LOG(DEBUG1, "RpcSaslClient::initDigestMd5->GSASL_AUTHID[Base64]: %s", identifier.c_str());
        LOG(DEBUG1, "RpcSaslClient::initDigestMd5->GSASL_PASSWORD[Base64]: %s", password.c_str());
        gsasl_property_set(session, GSASL_AUTHID, identifier.c_str());
        gsasl_property_set(session, GSASL_PASSWORD, password.c_str());
    }
    //LOG(DEBUG1, "RpcSaslClient::initKerberos->PRINCIPAL: %s", principal.c_str());
    //OG(DEBUG1, "RpcSaslClient::initDigestMd5->GSASL_SERVICE: %s", auth.protocol().c_str());
    //LOG(DEBUG1, "RpcSaslClient::initDigestMd5->GSASL_HOSTNAME: %s", auth.serverid().c_str());
    //gsasl_property_set(session, GSASL_AUTHID, base64Encode(principal).c_str());
    gsasl_property_set(session, GSASL_HOSTNAME, auth.serverid().c_str());
    gsasl_property_set(session, GSASL_SERVICE, auth.protocol().c_str());
    LOG(DEBUG1, "RpcSaslClient::initDigestMd5 End");
}

/*
std::string RpcSaslClient::evaluateChallenge(const std::string & challenge) {
    int rc;
    char * output = NULL;
    size_t outputSize;
    std::string retval;
    rc = gsasl_step(session, &challenge[0], challenge.size(), &output, &outputSize);

    if (rc == GSASL_NEEDS_MORE || rc == GSASL_OK) {
        retval.resize(outputSize);
        memcpy(&retval[0], output, outputSize);

        if (output) {
            free(output);
        }
    } else {
        if (output) {
            free(output);
        }

        THROW(SaslException, "Failed to evaluate challenge: %s", gsasl_strerror(rc));
    }

    if (rc == GSASL_OK) {
        complete = true;
    }

    return retval;
}*/

}
}

