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

#include "RpcChannel.h"
#include "common/Memory.h"
#include "common/Thread.h"
#include "common/Logger.h"
#include "common/WriteBuffer.h"
#include "common/Exception.h"
#include "common/ExceptionInternal.h"
#include "network/TcpSocket.h"
#include "RpcClient.h"
#include "RpcSaslClient.h"
#include "RpcContentWrapper.h"
#include "server/RpcHelper.h"
#include "RpcHeader.pb.h"
#include "IpcConnectionContext.pb.h"

#include <chrono>
#include <google/protobuf/io/coded_stream.h>

#define RPC_HEADER_MAGIC "hrpc"
#define RPC_HEADER_VERSION 9
#define SERIALIZATION_TYPE_PROTOBUF 0
#define CONNECTION_CONTEXT_CALL_ID -3

using namespace ::google::protobuf;
using namespace google::protobuf::io;

namespace Hdfs {
namespace Internal {

static std::mutex firstSaslExceptionMutex;

RpcChannelImpl::RpcChannelImpl(const RpcChannelKey & k, RpcClient & c) :
    refs(0), available(false), key(k), client(c) {
    socket = std::make_shared<TcpSocketImpl>();
    socket->setLingerTimeout(k.getConf().getLingerTimeout());
    in = std::make_shared<BufferedSocketReader>(socket);
    lastActivity = lastIdle = steady_clock::now();
}

RpcChannelImpl::RpcChannelImpl(const RpcChannelKey & k, 
                               std::shared_ptr<Socket> s,
                               std::shared_ptr<BufferedSocketReader> r,
                               RpcClient & c) :
    refs(0), available(false), key(k), client(c), socket(s), in(r) {
    lastActivity = lastIdle = steady_clock::now();
}

RpcChannelImpl::~RpcChannelImpl() {
    assert(pendingCalls.empty());
    assert(refs == 0);

    if (available) {
        socket->close();
    }
}

void RpcChannelImpl::close(bool immediate) {
    lock_guard<mutex> lock(writeMut);
    --refs;
    assert(refs >= 0);

    if (immediate && !refs) {
        assert(pendingCalls.empty());
        available = false;
        socket->close();
    }
}

void RpcChannelImpl::connect() {
    LOG(DEBUG1, "RpcChannelImpl::connect Begin");
    int sleep = 1;
    exception_ptr lastError = nullptr;
    const RpcConfig & rpcConfig = key.getConf();
    const RpcServerInfo & server = key.getServer();
    RpcAuth rpcAuth = key.getAuth();
    bool firstSaslException = true;
    for (int i = 0; i < rpcConfig.getMaxRetryOnConnect(); ++i) {
        try {
            LOG(DEBUG1, "RpcChannelImpl::connect->IP: %s, Port %s ", server.getHost().c_str(), server.getPort().c_str());
            socket->connect(server.getHost().c_str(), server.getPort().c_str(), rpcConfig.getConnectTimeout());
            socket->setNoDelay(rpcConfig.isTcpNoDelay());
            if (rpcAuth.getProtocol() == AuthProtocol::SASL) {
                RpcSaslClient rpcSaslClient(socket, key, client, rpcConfig.getSessionConfig());
                socket = rpcSaslClient.doHandshake();
                rpcAuth = rpcSaslClient.getAuth();
            } else {
                sendConnectionHeader(rpcAuth);
            }
            rpcAuth.setUser(key.getAuth().getUser());
            LOG(DEBUG1, "RpcChannelImpl::connect->sendConnectionContent");
            sendConnectionContent(rpcAuth);
            
            available = true;
            lastActivity = lastIdle = steady_clock::now();
            LOG(DEBUG1, "RpcChannelImpl::connect End");
            return;
        } catch (const SaslException & e) {
            /*
             * Namenode may treat this connect as replay, retry later
             */
            if (firstSaslException) {
                std::lock_guard<std::mutex> lock(firstSaslExceptionMutex);
                if (firstSaslException) {
                    firstSaslException = false;
                    socket->close();
                    const std::string & nnPrincipal = rpcConfig.getSessionConfig().getNamenodeKerberosPrincipal();
                    const std::string & nnKeytab = rpcConfig.getSessionConfig().getNamenodeKerberosKeytabFile();
                    if (!nnKeytab.empty()) {
                        LOG(DEBUG1, "RpcChannelImpl::connect: Attempting in-process kinitFromKeytab for \"%s\" using \"%s\"",
                            nnPrincipal.c_str(), nnKeytab.c_str());
                        bool kinitOk = GSaslClient::kinitFromKeytab(nnPrincipal, nnKeytab, rpcConfig.getSessionConfig().getKerberosCachePath());
                        if (!kinitOk) {
                            std::stringstream ss;
                            ss << "kinit -kt " << nnKeytab << " " << nnPrincipal;
                            std::string command = ss.str();
                            LOG(DEBUG1, "In-process kinit failed, attempting fallback command: [%s]", command.c_str());
                            int cmdRes = system(command.c_str());
                            if (cmdRes != 0) {
                                LOG(LOG_ERROR, "Fallback command [%s] failed with code %d", command.c_str(), cmdRes);
                            }
                        }
                        sleep_for(milliseconds(100));
                        continue;
                    }
                }
            } 
            sleep = (rand() % 5) + 1;
            lastError = current_exception();
            LOG(LOG_ERROR,
                "Failed to setup RPC connection to \"%s:%s\" caused by:\n%s",
                server.getHost().c_str(), server.getPort().c_str(), GetExceptionDetail(e));
        } catch (const HdfsFailoverException & e) {
            sleep = 1;
            lastError = current_exception();
        } catch (const HdfsNetworkConnectException & e) {
            sleep = 1;
            lastError = current_exception();
            //LOG(LOG_ERROR,
            //    "Failed to setup RPC connection to \"%s:%s\" caused by:\n%s",
            //    server.getHost().c_str(), server.getPort().c_str(), GetExceptionDetail(e));
            //socket->close();
            //break;
        } catch (const HdfsNetworkException & e) {
            sleep = 1;
            lastError = current_exception();
            LOG(LOG_ERROR,
                "Failed to setup RPC connection to \"%s:%s\" caused by:\n%s",
                server.getHost().c_str(), server.getPort().c_str(), GetExceptionDetail(e));
        } catch (const HdfsTimeoutException & e) {
            sleep = 1;
            lastError = current_exception();
            LOG(LOG_ERROR,
                "Failed to setup RPC connection to \"%s:%s\" caused by:\n%s",
                server.getHost().c_str(), server.getPort().c_str(), GetExceptionDetail(e));
        } catch (const HdfsIOException & e) {
            sleep = 1;
            lastError = current_exception();
            LOG(LOG_ERROR, "HdfsIOException: %s", e.msg());
        } catch (const HdfsException & e) {
            lastError = current_exception();
            LOG(LOG_ERROR, "HdfsException: %s", e.msg());
            socket->close();
            break;
        }

        if (i + 1 < rpcConfig.getMaxRetryOnConnect()) {
            LOG(INFO,
                "Retrying connect to server: \"%s:%s\". Already tried %d time(s)",
                server.getHost().c_str(), server.getPort().c_str(), i + 1);
        }

        socket->close();
        CheckOperationCanceled();
        sleep_for(seconds(sleep));
    }
    if (!lastError) {
        try {
            NESTED_THROW(HdfsRpcException,
                        "Failed to connect server: \"%s:%s\"",
                        server.getHost().c_str(), server.getPort().c_str());
        } catch (const HdfsRpcException & e) {
            lastError = current_exception();
        }
    }
    rethrow_exception(lastError);
}

exception_ptr RpcChannelImpl::invokeInternal(RpcRemoteCallPtr remote) {
    const RpcCall & call = remote->getCall();
    exception_ptr lastError;

    try {
        if (client.isRunning()) {
            lock_guard<mutex> lock(writeMut);

            if (!available) {
                LOG(DEBUG1, "RpcChannelImpl::invokeInternal->connect Begin");
                connect();
                LOG(DEBUG1, "RpcChannelImpl::invokeInternal->connect End");
            }
            LOG(DEBUG1, "RpcChannelImpl::invokeInternal->sendRequest Begin");
            sendRequest(remote);
            LOG(DEBUG1, "RpcChannelImpl::invokeInternal->sendRequest End");
        }

        /*
         * We use one call thread to check response,
         * other thread will wait on RPC call complete.
         */
        while (client.isRunning()) {
            if (remote->finished()) {
                /*
                 * Current RPC call has finished.
                 * Wake up another thread to check response.
                 */
                wakeupOneCaller(remote->getIdentity());
                break;
            }

            unique_lock<mutex> lock(readMut, defer_lock_t());

            if (lock.try_lock()) {
                /*
                 * Current thread will check response.
                 */
                checkOneResponse();
            } else {
                /*
                 * Another thread checks response, just wait.
                 */
                remote->wait();
            }
        }
    } catch (const HdfsNetworkConnectException & e) {
        try {
            NESTED_THROW(HdfsFailoverException,
                         "Failed to invoke RPC call \"%s\" on server \"%s:%s\"",
                         call.getName(), key.getServer().getHost().c_str(),
                         key.getServer().getPort().c_str());
        } catch (const HdfsFailoverException & e) {
            lastError = current_exception();
        }
    } catch (const HdfsNetworkException & e) {
        try {
            NESTED_THROW(HdfsRpcException,
                         "Failed to invoke RPC call \"%s\" on server \"%s:%s\"",
                         call.getName(), key.getServer().getHost().c_str(),
                         key.getServer().getPort().c_str());
        } catch (const HdfsRpcException & e) {
            lastError = current_exception();
        }
    } catch (const HdfsTimeoutException & e) {
        try {
            NESTED_THROW(HdfsFailoverException,
                         "Failed to invoke RPC call \"%s\" on server \"%s:%s\"",
                         call.getName(), key.getServer().getHost().c_str(),
                         key.getServer().getPort().c_str());
        } catch (const HdfsFailoverException & e) {
            lastError = current_exception();
        }
    } catch (const HdfsRpcException & e) {
        lastError = current_exception();
    } catch (const HdfsIOException & e) {
        try {
            NESTED_THROW(HdfsRpcException,
                         "Failed to invoke RPC call \"%s\" on server \"%s:%s\"",
                         call.getName(), key.getServer().getHost().c_str(),
                         key.getServer().getPort().c_str());
        } catch (const HdfsRpcException & e) {
            lastError = current_exception();
        }
    }

    return lastError;
}

void RpcChannelImpl::invoke(const RpcCall & call) {
    assert(refs > 0);
    RpcRemoteCallPtr remote;
    exception_ptr lastError;

    try {
        bool retry = false;

        do {
            int32_t id = client.getCallId();
            remote = RpcRemoteCallPtr(new RpcRemoteCall(call, id, client.getClientId()));
            lastError = exception_ptr();
            lastError = invokeInternal(remote);

            if (lastError) {
                lock_guard<mutex> lock(writeMut);
                shutdown(lastError);
                try {
                    rethrow_exception(lastError);
                } catch(const HdfsFailoverException & e){
                    
                    rethrow_exception(lastError);
                } catch(...) {
                    if (!retry && call.isIdempotent()) {
                        retry = true;
                        LOG(LOG_ERROR,
                            "Failed to invoke RPC call \"%s\" on server \"%s:%s\": \n%s",
                            call.getName(), key.getServer().getHost().c_str(),
                            key.getServer().getPort().c_str(),
                            GetExceptionDetail(lastError));
                        LOG(INFO,
                            "Retry idempotent RPC call \"%s\" on server \"%s:%s\"",
                            call.getName(), key.getServer().getHost().c_str(),
                            key.getServer().getPort().c_str());
                    } else {
                        rethrow_exception(lastError);
                    }
                }
            } else {
                break;
            }
        } while (retry);
    } catch (const HdfsRpcServerException & e) {
        if (!remote->finished()) {
            /*
             * a fatal error happened, the caller will unwrap it.
             */
            lock_guard<mutex> lock(writeMut);
            lastError = current_exception();
            shutdown(lastError);
        }

        /*
         * else not a fatal error, check again at the end of this function.
         */
    } catch (const HdfsException & e) {
        lock_guard<mutex> lock(writeMut);
        lastError = current_exception();
        shutdown(lastError);
    }

    /*
     * if the call is not finished, either failed to setup connection,
     * or client is closing.
     */
    if (!remote->finished() || !client.isRunning()) {
        lock_guard<mutex> lock(writeMut);

        if (lastError == exception_ptr()) {
            try {
                THROW(Hdfs::HdfsRpcException,
                      "Failed to invoke RPC call \"%s\", RPC channel to \"%s:%s\" is to be closed since RpcClient is closing",
                      call.getName(), key.getServer().getHost().c_str(), key.getServer().getPort().c_str());
            } catch (...) {
                lastError = current_exception();
            }
        }

        /*
         * wake up all.
         */
        shutdown(lastError);
        rethrow_exception(lastError);
    }

    remote->check();
}

void RpcChannelImpl::shutdown(exception_ptr reason) {
    assert(reason != exception_ptr());
    available = false;
    cleanupPendingCalls(reason);
    socket->close();
}

void RpcChannelImpl::wakeupOneCaller(int32_t id) {
    lock_guard<mutex> lock(writeMut);
    unordered_map<int32_t, RpcRemoteCallPtr>::iterator s, e;
    e = pendingCalls.end();

    for (s = pendingCalls.begin(); s != e; ++s) {
        if (s->first != id) {
            s->second->wakeup();
            return;
        }
    }
}

void RpcChannelImpl::sendRequest(RpcRemoteCallPtr remote) {
    LOG(DEBUG1, "RpcChannelImpl::sendRequest Begin");
    WriteBuffer buffer;
    assert(true == available);
    remote->serialize(key.getProtocol(), buffer);
    socket->writeFully(buffer.getBuffer(0), buffer.getDataSize(0),
                     key.getConf().getWriteTimeout());
    uint32_t id = remote->getIdentity();
    pendingCalls[id] = remote;
    lastActivity = lastIdle = steady_clock::now();
    LOG(DEBUG1, "RpcChannelImpl::sendRequest End");
}

void RpcChannelImpl::cleanupPendingCalls(exception_ptr reason) {
    assert(!writeMut.try_lock());
    unordered_map<int32_t, RpcRemoteCallPtr>::iterator s, e;
    e = pendingCalls.end();

    for (s = pendingCalls.begin(); s != e; ++s) {
        s->second->cancel(reason);
    }

    pendingCalls.clear();
}

void RpcChannelImpl::checkOneResponse() {
    //LOG(INFO, "RpcChannelImpl::checkOneResponse Begin");
    int ping = key.getConf().getPingTimeout();
    int timeout = key.getConf().getRpcTimeout();
    steady_clock::time_point start = steady_clock::now();

    while (client.isRunning()) {
        if (getResponse()) {
            readOneResponse(true);
            return;
        } else {
            if (ping > 0 && ToMilliSeconds(lastActivity, steady_clock::now()) >= ping) {
                lock_guard<mutex> lock(writeMut);
                sendPing();
            }
        }

        if (timeout > 0 && ToMilliSeconds(start, steady_clock::now()) >= timeout) {
            try {
                THROW(Hdfs::HdfsTimeoutException, "Timeout when wait for response from RPC channel \"%s:%s\"",
                      key.getServer().getHost().c_str(), key.getServer().getPort().c_str());
            } catch (...) {
                NESTED_THROW(Hdfs::HdfsRpcException, "Timeout when wait for response from RPC channel \"%s:%s\"",
                             key.getServer().getHost().c_str(), key.getServer().getPort().c_str());
            }
        }
    }
    //LOG(INFO, "RpcChannelImpl::checkOneResponse End");
}

void RpcChannelImpl::sendPing() {
    //LOG(INFO, "RpcChannelImpl::sendPing Begin");
    static const std::vector<char> pingRequest = RpcRemoteCall::GetPingRequest(client.getClientId());

    if (available) {
        //LOG(INFO, "RpcChannelImpl::sendPing->available Begin");
        LOG(INFO,
            "RPC channel to \"%s:%s\" got no response or idle for %d milliseconds, sending ping.",
            key.getServer().getHost().c_str(), key.getServer().getPort().c_str(), key.getConf().getPingTimeout());
        socket->writeFully(&pingRequest[0], pingRequest.size(), key.getConf().getWriteTimeout());
        lastActivity = steady_clock::now();
        //LOG(INFO, "RpcChannelImpl::sendPing->available End");
    }
    //LOG(INFO, "RpcChannelImpl::sendPing End");
}

bool RpcChannelImpl::checkIdle() {
    unique_lock<mutex> lock(writeMut, defer_lock_t());

    if (lock.try_lock()) {
        if (!pendingCalls.empty() || refs > 0) {
            lastIdle = steady_clock::now();
            return false;
        }

        int idle = key.getConf().getMaxIdleTime();
        int ping = key.getConf().getPingTimeout();

        try {
            //close the connection if idle timeout
            if (ToMilliSeconds(lastIdle, steady_clock::now()) >= idle) {
                socket->close();
                return true;
            }

            //send ping
            if (ping > 0 && ToMilliSeconds(lastActivity, steady_clock::now()) >= ping) {
                sendPing();
            }
        } catch (...) {
            LOG(LOG_ERROR,
                "Failed to send ping via idle RPC channel to server \"%s:%s\": \n%s",
                key.getServer().getHost().c_str(), key.getServer().getPort().c_str(), GetExceptionDetail(current_exception()));
            socket->close();
            return true;
        }
    }

    return false;
}

void RpcChannelImpl::waitForExit() {
    assert(!client.isRunning());

    while (refs != 0) {
        sleep_for(milliseconds(100));
    }

    assert(pendingCalls.empty());
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
void RpcChannelImpl::sendConnectionHeader(const RpcAuth &auth) {
    //LOG(INFO, "RpcChannelImpl::sendConnectionHeader Begin.");
    WriteBuffer buffer;
    buffer.write(RPC_HEADER_MAGIC, strlen(RPC_HEADER_MAGIC));
    buffer.write(static_cast<char>(RPC_HEADER_VERSION));
    buffer.write(static_cast<char>(0));  //for future feature
    buffer.write(static_cast<char>(auth.getProtocol()));
    socket->writeFully(buffer.getBuffer(0), buffer.getDataSize(0),
                     key.getConf().getWriteTimeout());
    //LOG(INFO, "RpcChannelImpl::sendConnectionHeader End.");
}

void RpcChannelImpl::buildConnectionContext(
    IpcConnectionContextProto & connectionContext, const RpcAuth & auth) {

    LOG(DEBUG1, "RpcChannelImpl::buildConnectionContext Begin.");
    connectionContext.set_protocol(key.getProtocol().getProtocol());
    LOG(DEBUG1, "RpcChannelImpl::buildConnectionContext euser: %s", key.getAuth().getUser().getPrincipal().c_str());
    LOG(DEBUG1, "RpcChannelImpl::buildConnectionContext ruser: %s", key.getAuth().getUser().getRealUser().c_str());
    std::string euser = key.getAuth().getUser().getPrincipal();
    std::string ruser = key.getAuth().getUser().getRealUser();

    if (auth.getMethod() != AuthMethod::TOKEN) {
        UserInformationProto * user = connectionContext.mutable_userinfo();
        user->set_effectiveuser(euser);
        if (auth.getMethod() != AuthMethod::SIMPLE) {
            if (!ruser.empty() && ruser != euser) {
                user->set_realuser(ruser);
            }
        }
    }
    LOG(DEBUG1, "RpcChannelImpl::buildConnectionContext End.");
}

void RpcChannelImpl::sendConnectionContent(const RpcAuth & auth) {
    LOG(DEBUG1, "RpcChannelImpl::sendConnectionContent Begin.");
    WriteBuffer buffer;
    IpcConnectionContextProto connectionContext;
    RpcRequestHeaderProto rpcHeader;
    buildConnectionContext(connectionContext, auth);
    rpcHeader.set_callid(CONNECTION_CONTEXT_CALL_ID);
    rpcHeader.set_clientid(client.getClientId());
    rpcHeader.set_retrycount(INVALID_RETRY_COUNT);
    rpcHeader.set_rpckind(RPC_PROTOCOL_BUFFER);
    rpcHeader.set_rpcop(RpcRequestHeaderProto_OperationProto_RPC_FINAL_PACKET);
    RpcContentWrapper wrapper(&rpcHeader, &connectionContext);
    int size = wrapper.getLength();
    buffer.writeBigEndian(size);
    wrapper.writeTo(buffer);
    socket->writeFully(buffer.getBuffer(0), buffer.getDataSize(0),
                     key.getConf().getWriteTimeout());
    lastActivity = lastIdle = steady_clock::now();
    LOG(DEBUG1, "RpcChannelImpl::sendConnectionContent End.");
}

RpcRemoteCallPtr RpcChannelImpl::getPendingCall(int32_t id) {
    unordered_map<int32_t, RpcRemoteCallPtr>::iterator it;
    it = pendingCalls.find(id);

    if (it == pendingCalls.end()) {
        THROW(HdfsRpcException,
              "RPC channel to \"%s:%s\" got protocol mismatch: RPC channel cannot find pending call: id = %d.",
              key.getServer().getHost().c_str(), key.getServer().getPort().c_str(), static_cast<int>(id));
    }

    RpcRemoteCallPtr rc = it->second;
    pendingCalls.erase(it);
    return rc;
}

bool RpcChannelImpl::getResponse() {
    int idleTimeout = key.getConf().getMaxIdleTime();
    int pingTimeout = key.getConf().getPingTimeout();
    int timeout = key.getConf().getRpcTimeout();
    int interval = pingTimeout < idleTimeout ? pingTimeout : idleTimeout;
    interval /= 2;
    interval = interval < timeout ? interval : timeout;
    steady_clock::time_point s = steady_clock::now();

    while (client.isRunning()) {
        if (in->poll(500)) {
            return true;
        }

        if (ToMilliSeconds(s, steady_clock::now()) >= interval) {
            return false;
        }
    }

    return false;
}

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

void RpcChannelImpl::readOneResponse(bool writeLock) {
    //LOG(INFO, "RpcChannelImpl::readOneResponse Begin");
    int readTimeout = key.getConf().getReadTimeout();
    std::vector<char> buffer(128);
    RpcResponseHeaderProto curRespHeader;
    RpcResponseHeaderProto::RpcStatusProto status;
    uint32_t totalen, headerSize = 0, bodySize = 0;
    totalen = in->readBigEndianInt32(readTimeout);
    /*
     * read response header
     */
    headerSize = in->readVarint32(readTimeout);
    buffer.resize(headerSize);
    in->readFully(&buffer[0], headerSize, readTimeout);

    if (!curRespHeader.ParseFromArray(&buffer[0], headerSize)) {
        THROW(HdfsRpcException,
              "RPC channel to \"%s:%s\" got protocol mismatch: RPC channel cannot parse response header.",
              key.getServer().getHost().c_str(), key.getServer().getPort().c_str())
    }

    lastActivity = steady_clock::now();
    status = curRespHeader.status();

    if (RpcResponseHeaderProto_RpcStatusProto_SUCCESS == status) {
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

        bodySize = in->readVarint32(readTimeout);
        buffer.resize(bodySize);

        if (bodySize > 0) {
            in->readFully(&buffer[0], bodySize, readTimeout);
        }

        Message * response = rc->getCall().getResponse();

        if (!response->ParseFromArray(&buffer[0], bodySize)) {
            THROW(HdfsRpcException,
                  "RPC channel to \"%s:%s\" got protocol mismatch: rpc channel cannot parse response.",
                  key.getServer().getHost().c_str(), key.getServer().getPort().c_str())
        }

        rc->done();
    } else {
        /*
         * on error, read error class and message
         */
        std::string errClass, errMessage;
        errClass = curRespHeader.exceptionclassname();
        errMessage = curRespHeader.errormsg();

        if (RpcResponseHeaderProto_RpcStatusProto_ERROR == status) {
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
    //LOG(INFO, "RpcChannelImpl::readOneResponse End");
}

}
}
