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
#ifndef _HDFS_LIBHDFS3_CLIENT_REMOTEBLOCKREADER_H_
#define _HDFS_LIBHDFS3_CLIENT_REMOTEBLOCKREADER_H_

#include "common/Memory.h"
#include "common/SessionConfig.h"
#include "common/Checksum.h"
#include "BlockReader.h"
#include "DataTransferProtocol.h"
#include "PacketHeader.h"
#include "PeerCache.h"
#include "Token.h"
#include "network/BufferedSocketReader.h"
#include "network/Socket.h"
#include "server/DatanodeInfo.h"
#include "server/LocatedBlocks.h"
#include "server/DataEncryptionKey.h"
#include "rpc/RpcRemoteCall.h"
#include "rpc/RpcAuth.h"
#include "rpc/RpcSaslClient.h"

#include <gsasl.h>
#include <sstream>

#include <google/protobuf/io/coded_stream.h>

namespace Hdfs {
namespace Internal {

class RemoteBlockReader: public BlockReader {
public:
    RemoteBlockReader(const ExtendedBlock& eb, DatanodeInfo& datanode,
                      PeerCache& peerCache, int64_t start, int64_t len,
                      const DataEncryptionKey& dataEncryptionKey,
                      const Token& token, const char* clientName, bool verify,
                      const SessionConfig& conf);

    ~RemoteBlockReader();

    /**
     * Get how many bytes can be read without blocking.
     * @return The number of bytes can be read without blocking.
     */
    virtual int64_t available();

    /**
     * To read data from block.
     * @param buf the buffer used to filled.
     * @param size the number of bytes to be read.
     * @return return the number of bytes filled in the buffer,
     *  it may less than size. Return 0 if reach the end of block.
     */
    virtual int32_t read(char * buf, int32_t len);

    /**
     * Move the cursor forward len bytes.
     * @param len The number of bytes to skip.
     */
    virtual void skip(int64_t len);

private:
    bool readTrailingEmptyPacket();
    shared_ptr<PacketHeader> readPacketHeader();
    shared_ptr<Socket> createNewPeer(const DatanodeInfo& dn, const RpcAuth & auth);

    void checkResponse();
    void readNextPacket();
    void sendStatus();
    void verifyChecksum(int chunks);
    void sendConnectionHeader(const RpcAuth &auth);
    void sendConnectionContent(const RpcAuth & auth);
    void buildConnectionContext(IpcConnectionContextProto & connectionContext, const RpcAuth & auth);
    RpcRemoteCallPtr getPendingCall(int32_t id);

private:
    bool sentStatus;
    bool verify; //verify checksum or not.
    const ExtendedBlock & binfo;
    DatanodeInfo & datanode;
    int checksumSize;
    int chunkSize;
    int connTimeout;
    int position; //point in buffer.
    int readTimeout;
    int size;  //data size in buffer.
    int writeTimeout;
    int maxRetryOnConnect;
    int64_t cursor; //point in block.
    int64_t endOffset; //offset in block requested to read to.
    int64_t lastSeqNo; //segno of the last chunk received
    PeerCache& peerCache;
    shared_ptr<BufferedSocketReader> in;
    shared_ptr<Checksum> checksum;
    shared_ptr<DataTransferProtocol> sender;
    shared_ptr<PacketHeader> lastHeader;
    shared_ptr<Socket> socket;
    bool isAvailable;
    bool tcpNoDelay;
    std::string currentDnAddress;
    AuthMethod authMethod;
    std::string principal;
    UserInfo user;
    RpcProtocolInfo rpcProtocolInfo;
    shared_ptr<SaslClient> saslClient;
    unordered_map<int32_t, RpcRemoteCallPtr> pendingCalls;
    std::string clientId;
    steady_clock::time_point lastActivity; // ping is a kind of activity, lastActivity will be updated after ping
    steady_clock::time_point lastIdle; // ping cannot change idle state. If there is still pending calls, lastIdle is always "NOW".
    std::vector<char> buffer;

    SessionConfig conf;
    Token token;
    DataEncryptionKey dataEncryptionKey;
    
};

}
}
#endif /* _HDFS_LIBHDFS3_CLIENT_REMOTEBLOCKREADER_H_ */
