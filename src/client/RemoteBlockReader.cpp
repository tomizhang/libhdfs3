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
#include "RemoteBlockReader.h"

#include "common/Memory.h"
#include "common/BigEndian.h"
#include "common/Logger.h"
#include "common/DateTime.h"
#include "common/DebugUtil.h"
#include "common/HWCrc32c.h"
#include "common/SWCrc32c.h"
#include "common/WriteBuffer.h"
#include "common/Exception.h"
#include "common/ExceptionInternal.h"
#include "DataTransferProtocolSender.h"
#include "DataTransferSaslClient.h"
#include "KerberosName.h"
#include "UserInfo.h"
#include "rpc/RpcContentWrapper.h"
#include "rpc/RpcRemoteCall.h"
#include "server/RpcHelper.h"
#include "network/Socket.h"
#include "IpcConnectionContext.pb.h"

#include <algorithm>
#include <cctype>

#include <inttypes.h>
#include <vector>
#include <krb5/krb5.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <gsasl.h>

#define RPC_HEADER_MAGIC "hrpc"
#define RPC_HEADER_VERSION 9
#define INVALID_RETRY_COUNT -1
#define CONNECTION_CONTEXT_CALL_ID -3

#define DATANODE_VERSION 1
#define DATANODE_PROTOCOL "org.apache.hadoop.hdfs.protocol.DataTransferProtos"
#define BLOCK_TOKEN_KIND "HDFS_BLOCK_TOKEN"

using namespace ::google::protobuf;
using namespace google::protobuf::io;

namespace Hdfs {
namespace Internal {

static exception_ptr HandlerRpcResponseException(exception_ptr e) {
    LOG(DEBUG1, "RemoteBlockReader::HandlerRpcResponseException");
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

RemoteBlockReader::RemoteBlockReader(const ExtendedBlock& eb,
                                     DatanodeInfo& datanode,
                                     PeerCache& peerCache, int64_t start, int64_t len, 
                                     const DataEncryptionKey& k,
                                     const Token& t,
                                     const char* clientName, bool verify,
                                     const SessionConfig& c)
    : sentStatus(false),
      verify(verify),
      binfo(eb),
      datanode(datanode),
      checksumSize(0),
      chunkSize(0),
      position(0),
      size(0),
      cursor(start),
      endOffset(len + start),
      lastSeqNo(-1),
      peerCache(peerCache), 
      rpcProtocolInfo(1,"org.apache.hadoop.hdfs.protocol.DataTransferProtocol", "HDFS_BLOCK_TOKEN"),
      dataEncryptionKey(k), token(t), conf(c) {

    assert(start >= 0);
    readTimeout = conf.getInputReadTimeout();
    writeTimeout = conf.getInputWriteTimeout();
    connTimeout = conf.getInputConnTimeout();
    tcpNoDelay = conf.isRpcTcpNoDelay();
    maxRetryOnConnect = conf.getRpcMaxRetryOnConnect();
    authMethod = RpcAuth::ParseMethod(conf.getRpcAuthMethod());

    LOG(DEBUG1, "RemoteBlockReader->DataEncryptionKey->KeyId: %u", this->dataEncryptionKey.getKeyId());
    LOG(DEBUG1, "RemoteBlockReader->DataEncryptionKey->BlockPoolId: %s", this->dataEncryptionKey.getBlockPoolId().c_str());
    LOG(DEBUG1, "RemoteBlockReader->DataEncryptionKey->Nonce: %s", stringToHex(this->dataEncryptionKey.getNonce()).c_str());
    LOG(DEBUG1, "RemoteBlockReader->DataEncryptionKey->EncryptionKey: [%s]", stringToHex(this->dataEncryptionKey.getEncryptionKey()).c_str());
    LOG(DEBUG1, "RemoteBlockReader->DataEncryptionKey->ExpiryDate: %llu", this->dataEncryptionKey.getExpiryDate());
    LOG(DEBUG1, "RemoteBlockReader->DataEncryptionKey->EncryptionAlgorithm: %s", this->dataEncryptionKey.getEncryptionAlgorithm().c_str());

    RpcAuth rpcAuth(user, authMethod);
    bool fromCache = false;
    socket = peerCache.getConnection(datanode);
    if (socket) {
        fromCache = true;
    } else {
        socket = createNewPeer(datanode, rpcAuth);
    }

    try {
        in = std::make_shared<BufferedSocketReader>(socket);
        sender = shared_ptr<DataTransferProtocol>(new DataTransferProtocolSender(
            socket, writeTimeout, datanode.formatAddress()));
        sender->readBlock(eb, token, clientName, start, len);
        checkResponse();
    } catch (const HdfsException &) {
        if (fromCache) {
            LOG(DEBUG1, "Cached connection to datanode %s failed or closed, retrying with fresh connection.",
                datanode.formatAddress().c_str());
            socket->close();
            socket = createNewPeer(datanode, rpcAuth);
            in = std::make_shared<BufferedSocketReader>(socket);
            sender = shared_ptr<DataTransferProtocol>(new DataTransferProtocolSender(
                socket, writeTimeout, datanode.formatAddress()));
            sender->readBlock(eb, token, clientName, start, len);
            checkResponse();
        } else {
            throw;
        }
    }
}

RemoteBlockReader::~RemoteBlockReader() {
    if (sentStatus) {
        peerCache.addConnection(socket, datanode);
    } else {
        socket->close();
    }
}

shared_ptr<Socket> RemoteBlockReader::createNewPeer(const DatanodeInfo& dn, const RpcAuth & auth) {
    steady_clock::time_point t0 = steady_clock::now();
    int sleep = 1;
    exception_ptr lastError = nullptr;
    for (int i = 0; i < maxRetryOnConnect; ++i) {
        std::shared_ptr<Socket> socket = std::make_shared<TcpSocketImpl>();
        try {
            if (auth.getProtocol() == AuthProtocol::SASL) {
                currentDnAddress = dn.formatAddress();
                //LOG(DEBUG1, "RemoteBlockReader::getNextPeer->Address: %s, ", currentDnAddress.c_str());
                std::string port = std::to_string(dn.getXferPort());
                //LOG(DEBUG1, "RemoteBlockReader::getNextPeer->IP: %s, Port %s ", dn.getIpAddr().c_str(), port.c_str());
                socket->connect(dn.getIpAddr().c_str(), port.c_str(), connTimeout);
                socket->setNoDelay(tcpNoDelay);
                DataTransferSaslClient saslClient(socket, conf, dataEncryptionKey, token);
                std::shared_ptr<Socket> res = saslClient.doHandshake();
                steady_clock::time_point t1 = steady_clock::now();
                LOG(DEBUG1, "RemoteBlockReader::createNewPeer to \"%s\" completed in %ld ms",
                    dn.formatAddress().c_str(), (long)ToMilliSeconds(t0, t1));
                return res;
            } else {
                socket->connect(dn.getIpAddr().c_str(), dn.getXferPort(), connTimeout);
                socket->setNoDelay(true);
                steady_clock::time_point t1 = steady_clock::now();
                LOG(DEBUG1, "RemoteBlockReader::createNewPeer to \"%s\" completed in %ld ms",
                    dn.formatAddress().c_str(), (long)ToMilliSeconds(t0, t1));
                return socket;
            }
        } catch (const SaslException & e) {
            // Datanode may treat this connect as replay, retry later
            sleep = (rand() % 5) + 1;
            lastError = current_exception();
            LOG(LOG_ERROR,
                "Failed to setup DataTransfer connection to \"%s\" caused by:\n%s",
                dn.formatAddress().c_str(), GetExceptionDetail(e));
        } catch (const HdfsNetworkException & e) {
            sleep = 1;
            lastError = current_exception();
            LOG(LOG_ERROR,
                "Failed to setup DataTransfer connection to \"%s\" caused by:\n%s",
                dn.formatAddress().c_str(), GetExceptionDetail(e));
        } catch (const HdfsTimeoutException & e) {
            sleep = 1;
            lastError = current_exception();
            LOG(LOG_ERROR,
                "Failed to setup DataTransfer connection to \"%s\" caused by:\n%s",
                dn.formatAddress().c_str(), GetExceptionDetail(e));
        }
        if (i + 1 < maxRetryOnConnect) {
            LOG(DEBUG1,
                "Retrying connect to server: \"%s\". Already tried %d time(s)",
                dn.formatAddress().c_str(), i + 1);
        }
        socket->close();
        CheckOperationCanceled();
        sleep_for(seconds(sleep));
    }
    if (!lastError) {
        try {
            NESTED_THROW(HdfsNetworkException,
                        "Failed to connect to datanode: \"%s:%d\"",
                        dn.getIpAddr().c_str(), dn.getXferPort());
        } catch (const HdfsNetworkException & e) {
            lastError = current_exception();
        }
    }
    rethrow_exception(lastError);
}

void RemoteBlockReader::sendConnectionHeader(const RpcAuth &auth) {
    //LOG(DEBUG1, "RemoteBlockReader::sendConnectionHeader Begin");
    WriteBuffer buffer;
    buffer.write(RPC_HEADER_MAGIC, strlen(RPC_HEADER_MAGIC));
    buffer.write(static_cast<char>(RPC_HEADER_VERSION));
    buffer.write(static_cast<char>(0));  //for future feature
    buffer.write(static_cast<char>(auth.getProtocol()));
    //LOG(DEBUG1, "RemoteBlockReader::sendConnectionHeader Socket writeFully...");
    socket->writeFully(buffer.getBuffer(0), buffer.getDataSize(0), writeTimeout);
    //LOG(DEBUG1, "RemoteBlockReader::sendConnectionHeader End");
}

void RemoteBlockReader::buildConnectionContext(
    IpcConnectionContextProto & connectionContext, const RpcAuth & auth) {
    //LOG(DEBUG1, "RemoteBlockReader::buildConnectionContext");
    connectionContext.set_protocol(rpcProtocolInfo.getProtocol());
    std::string euser = this->user.getEffectiveUser();
    std::string ruser = this->user.getRealUser();

    if (auth.getMethod() != AuthMethod::TOKEN) {
        UserInformationProto * user = connectionContext.mutable_userinfo();
        user->set_effectiveuser(principal);

        if (auth.getMethod() != AuthMethod::SIMPLE) {
            if (!ruser.empty() && ruser != euser) {
                user->set_realuser(ruser);
            }
        }
    }
}

void RemoteBlockReader::sendConnectionContent(const RpcAuth & auth) {
    //LOG(DEBUG1, "RemoteBlockReader::sendConnectionContent Begin");
    WriteBuffer buffer;
    IpcConnectionContextProto connectionContext;
    RpcRequestHeaderProto rpcHeader;
    buildConnectionContext(connectionContext, auth);
    rpcHeader.set_callid(CONNECTION_CONTEXT_CALL_ID);
    rpcHeader.set_clientid(clientId);
    rpcHeader.set_retrycount(INVALID_RETRY_COUNT);
    rpcHeader.set_rpckind(RPC_PROTOCOL_BUFFER);
    rpcHeader.set_rpcop(RpcRequestHeaderProto_OperationProto_RPC_FINAL_PACKET);
    RpcContentWrapper wrapper(&rpcHeader, &connectionContext);
    int size = wrapper.getLength();
    buffer.writeBigEndian(size);
    wrapper.writeTo(buffer);
    socket->writeFully(buffer.getBuffer(0), buffer.getDataSize(0), writeTimeout);
    lastActivity = lastIdle = steady_clock::now();
    //LOG(DEBUG1, "RemoteBlockReader::sendConnectionContent End");
}

void RemoteBlockReader::checkResponse() {
    std::vector<char> respBuffer;
    int32_t respSize = in->readVarint32(readTimeout);

    if (respSize <= 0 || respSize > 10 * 1024 * 1024) {
        THROW(HdfsIOException, "RemoteBlockReader get a invalid response size: %d, Block: %s, from Datanode: %s",
              respSize, binfo.toString().c_str(), datanode.formatAddress().c_str());
    }

    respBuffer.resize(respSize);
    in->readFully(&respBuffer[0], respSize, readTimeout);
    BlockOpResponseProto resp;

    if (!resp.ParseFromArray(&respBuffer[0], respBuffer.size())) {
        THROW(HdfsIOException, "RemoteBlockReader cannot parse BlockOpResponseProto from Datanode response, "
              "Block: %s, from Datanode: %s", binfo.toString().c_str(), datanode.formatAddress().c_str());
    }

    if (resp.status() != Status::DT_PROTO_SUCCESS) {
        std::string msg;

        if (resp.has_message()) {
            msg = resp.message();
        }

        if (resp.status() == Status::DT_PROTO_ERROR_ACCESS_TOKEN) {
            THROW(HdfsInvalidBlockToken, "RemoteBlockReader: block's token is invalid. Datanode: %s, Block: %s",
                  datanode.formatAddress().c_str(), binfo.toString().c_str());
        } else {
            THROW(HdfsIOException,
                  "RemoteBlockReader: Datanode return an error when sending read request to Datanode: %s, Block: %s, %s.",
                  datanode.formatAddress().c_str(), binfo.toString().c_str(),
                  (msg.empty() ? "check Datanode's log for more information" : msg.c_str()));
        }
    }

    const ReadOpChecksumInfoProto & checksumInfo = resp.readopchecksuminfo();
    const ChecksumProto & cs = checksumInfo.checksum();
    chunkSize = cs.bytesperchecksum();

    if (chunkSize < 0) {
        THROW(HdfsIOException,
              "RemoteBlockReader invalid chunk size: %d, expected range[0, %" PRId64 "], Block: %s, from Datanode: %s",
              chunkSize, binfo.getNumBytes(), binfo.toString().c_str(), datanode.formatAddress().c_str());
    }

    switch (cs.type()) {
    case ChecksumTypeProto::CHECKSUM_NULL:
        verify = false;
        checksumSize = 0;
        break;

    case ChecksumTypeProto::CHECKSUM_CRC32:
        THROW(HdfsIOException, "RemoteBlockReader does not support CRC32 checksum, Block: %s, from Datanode: %s",
              binfo.toString().c_str(), datanode.formatAddress().c_str());
        break;

    case ChecksumTypeProto::CHECKSUM_CRC32C:
        if (HWCrc32c::available()) {
            checksum = shared_ptr<Checksum>(new HWCrc32c());
        } else {
            checksum = shared_ptr<Checksum>(new SWCrc32c());
        }

        checksumSize = sizeof(int32_t);
        break;

    default:
        THROW(HdfsIOException, "RemoteBlockReader cannot recognize checksum type: %d, Block: %s, from Datanode: %s",
              static_cast<int>(cs.type()), binfo.toString().c_str(), datanode.formatAddress().c_str());
    }

    /*
     * The offset into the block at which the first packet
     * will start. This is necessary since reads will align
     * backwards to a checksum chunk boundary.
     */
    int64_t firstChunkOffset = checksumInfo.chunkoffset();

    if (firstChunkOffset < 0 || firstChunkOffset > cursor || firstChunkOffset <= cursor - chunkSize) {
        THROW(HdfsIOException,
              "RemoteBlockReader invalid first chunk offset: %" PRId64 ", expected range[0, %" PRId64 "], " "Block: %s, from Datanode: %s",
              firstChunkOffset, cursor, binfo.toString().c_str(), datanode.formatAddress().c_str());
    }
}

shared_ptr<PacketHeader> RemoteBlockReader::readPacketHeader() {
    try {
        shared_ptr<PacketHeader> retval;
        static const int packetHeaderLen = PacketHeader::GetPkgHeaderSize();
        std::vector<char> buf(packetHeaderLen);

        if (lastHeader && lastHeader->isLastPacketInBlock()) {
            THROW(HdfsIOException, "RemoteBlockReader: read over block end from Datanode: %s, Block: %s.",
                  datanode.formatAddress().c_str(), binfo.toString().c_str());
        }

        in->readFully(&buf[0], packetHeaderLen, readTimeout);
        retval = shared_ptr<PacketHeader>(new PacketHeader);
        retval->readFields(&buf[0], packetHeaderLen);
        return retval;
    } catch (const HdfsIOException & e) {
        NESTED_THROW(HdfsIOException, "RemoteBlockReader: failed to read block header for Block: %s from Datanode: %s.",
                     binfo.toString().c_str(), datanode.formatAddress().c_str());
    }
}

void RemoteBlockReader::readNextPacket() {
    if (position < size) {
        THROW(HdfsIOException,
              "RemoteBlockReader: readNextPacket called with unread buffer state for Block: %s from Datanode: %s.",
              binfo.toString().c_str(), datanode.formatAddress().c_str());
    }
    lastHeader = readPacketHeader();
    int dataSize = lastHeader->getDataLen();
    int64_t pendingAhead = 0;

    if (!lastHeader->sanityCheck(lastSeqNo)) {
        THROW(HdfsIOException, "RemoteBlockReader: Packet failed on sanity check for block %s from Datanode %s.",
              binfo.toString().c_str(), datanode.formatAddress().c_str());
    }

    if (dataSize <= 0 && lastHeader->getPacketLen() != static_cast<int>(sizeof(int32_t))) {
        THROW(HdfsIOException,
              "RemoteBlockReader: invalid empty packet for Block: %s from Datanode: %s.",
              binfo.toString().c_str(), datanode.formatAddress().c_str());
    }

    if (dataSize > 0) {
        int chunks = (dataSize + chunkSize - 1) / chunkSize;
        int checksumLen = chunks * checksumSize;
        size = checksumLen + dataSize;
        assert(size == lastHeader->getPacketLen() - static_cast<int>(sizeof(int32_t)));
        buffer.resize(size);
        in->readFully(&buffer[0], size, readTimeout);
        lastSeqNo = lastHeader->getSeqno();

        if (lastHeader->getPacketLen() != static_cast<int>(sizeof(int32_t)) + dataSize + checksumLen) {
            THROW(HdfsIOException, "Invalid Packet, packetLen is %d, dataSize is %d, checksum size is %d",
                  lastHeader->getPacketLen(), dataSize, checksumLen);
        }

        if (verify) {
            verifyChecksum(chunks);
        }

        /*
         * skip checksum
         */
        position = checksumLen;
        /*
         * the first packet we get may start at the position before we required
         */
        pendingAhead = cursor - lastHeader->getOffsetInBlock();
        pendingAhead = pendingAhead > 0 ? pendingAhead : 0;
        position += pendingAhead;
    }

    /*
     * we reach the end of the range we required, send status to datanode
     * if datanode do not sending data anymore.
     */

    if (cursor + dataSize - pendingAhead >= endOffset && readTrailingEmptyPacket()) {
        sendStatus();
    }
}

bool RemoteBlockReader::readTrailingEmptyPacket() {
    try {
        shared_ptr<PacketHeader> trailingHeader = readPacketHeader();

        if (trailingHeader->getDataLen() != 0) {
            return false;
        }

        return true;
    } catch (...) {
        return false;
    }
}

void RemoteBlockReader::sendStatus() {
    ClientReadStatusProto status;

    if (verify) {
        status.set_status(Status::DT_PROTO_CHECKSUM_OK);
    } else {
        status.set_status(Status::DT_PROTO_SUCCESS);
    }

    WriteBuffer buffer;
    int size = status.ByteSize();
    buffer.writeVarint32(size);
    status.SerializeToArray(buffer.alloc(size), size);
    socket->writeFully(buffer.getBuffer(0), buffer.getDataSize(0), writeTimeout);
    sentStatus = true;
}

void RemoteBlockReader::verifyChecksum(int chunks) {
    int dataSize = lastHeader->getDataLen();
    char * pchecksum = &buffer[0];
    char * pdata = &buffer[0] + (chunks * checksumSize);

    for (int i = 0; i < chunks; ++i) {
        int size = chunkSize < dataSize ? chunkSize : dataSize;
        dataSize -= size;
        checksum->reset();
        checksum->update(pdata + (i * chunkSize), size);
        uint32_t result = checksum->getValue();
        uint32_t target = ReadBigEndian32FromArray(pchecksum + (i * checksumSize));

        if (result != target && size == chunkSize) {
            THROW(ChecksumException, "RemoteBlockReader: checksum not match for Block: %s, on Datanode: %s",
                  binfo.toString().c_str(), datanode.formatAddress().c_str());
        }
    }

    assert(0 == dataSize);
}

int64_t RemoteBlockReader::available() {
    return size - position > 0 ? size - position : 0;
}

int32_t RemoteBlockReader::read(char * buf, int32_t len) {
    assert(0 != len && NULL != buf);

    if (cursor >= endOffset) {
        THROW(HdfsIOException, "RemoteBlockReader: read over block end from Datanode: %s, Block: %s.",
              datanode.formatAddress().c_str(), binfo.toString().c_str());
    }

    try {
        if (position >= size) {
            readNextPacket();
        }

        int32_t todo = len < size - position ? len : size - position;
        memcpy(buf, &buffer[position], todo);
        position += todo;
        cursor += todo;
        return todo;
    } catch (const HdfsTimeoutException & e) {
        NESTED_THROW(HdfsIOException, "RemoteBlockReader: failed to read Block: %s from Datanode: %s.",
                     binfo.toString().c_str(), datanode.formatAddress().c_str());
    } catch (const HdfsNetworkException & e) {
        NESTED_THROW(HdfsIOException, "RemoteBlockReader: failed to read Block: %s from Datanode: %s.",
                     binfo.toString().c_str(), datanode.formatAddress().c_str());
    }
}

void RemoteBlockReader::skip(int64_t len) {
    int64_t todo = len;
    assert(cursor + len <= endOffset);

    try {
        while (todo > 0) {
            if (cursor >= endOffset) {
                THROW(HdfsIOException, "RemoteBlockReader: skip over block end from Datanode: %s, Block: %s.",
                      datanode.formatAddress().c_str(), binfo.toString().c_str());
            }

            if (position >= size) {
                readNextPacket();
            }

            int batch = size - position;
            batch = batch < todo ? batch : static_cast<int>(todo);
            position += batch;
            cursor += batch;
            todo -= batch;
        }
    } catch (const HdfsTimeoutException & e) {
        NESTED_THROW(HdfsIOException, "RemoteBlockReader: failed to read Block: %s from Datanode: %s.",
                     binfo.toString().c_str(), datanode.formatAddress().c_str());
    } catch (const HdfsNetworkException & e) {
        NESTED_THROW(HdfsIOException, "RemoteBlockReader: failed to read Block: %s from Datanode: %s.",
                     binfo.toString().c_str(), datanode.formatAddress().c_str());
    }
}

}
}
