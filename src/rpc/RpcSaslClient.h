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
#ifndef _HDFS_LIBHDFS3_RPC_RPCSASLCLIENT_H_
#define _HDFS_LIBHDFS3_RPC_RPCSASLCLIENT_H_

#include "common/Memory.h"
#include "client/Token.h"
#include "network/SaslClient.h"
#include "network/Socket.h"
#include "RpcAuth.h"
#include "RpcChannelKey.h"
#include "RpcClient.h"
#include "RpcHeader.pb.h"

#include <gsasl.h>
#include <google/protobuf/message.h>

namespace Hdfs {
namespace Internal {

class RpcSaslClient: public GSaslClient {
public:

    RpcSaslClient(const std::shared_ptr<Socket> s, 
                  const RpcChannelKey & k,
                  RpcClient & cli,
                  const SessionConfig & c);

    ~RpcSaslClient() override;

    std::shared_ptr<Socket> doHandshake() override;

    const RpcAuth & getAuth() const;

private:
    void sendConnectionHeader(const RpcAuth &auth);
    void sendSaslMessage(RpcSaslProto * msg, google::protobuf::Message * resp);
    void readSaslResponse(bool writeLock);
    const RpcSaslProto_SaslAuth * findSaslAuth(const google::protobuf::RepeatedPtrField<RpcSaslProto_SaslAuth> * auths);
    std::string saslEvaluateToken(RpcSaslProto & response, bool serverIsDone);

    void initKerberos(const RpcSaslProto_SaslAuth & auth);
    void initDigestMd5(const RpcSaslProto_SaslAuth & auth);

    RpcRemoteCallPtr getPendingCall(int32_t id);

private:
    const RpcChannelKey & rpcChannelKey;
    const RpcConfig  & rpcConfig;
    const RpcServerInfo & rpcServer;
    RpcClient & rpcClient;
    RpcAuth rpcAuth;
    mutex readMut;
    mutex writeMut;
    unordered_map<int32_t, RpcRemoteCallPtr> pendingCalls;

};

}
}

#endif /* _HDFS_LIBHDFS3_RPC_RPCSASLCLIENT_H_ */
