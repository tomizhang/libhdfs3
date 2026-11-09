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
#include <inttypes.h>
#include <list>
#include <unordered_map>
#include <vector>

#include "client/PeerCache.h"
#include "common/Logger.h"
#include "common/Thread.h"

namespace Hdfs {
namespace Internal {

namespace {

struct PeerElement {
    shared_ptr<Socket> sock;
    steady_clock::time_point time;
    std::string key;
};

class PeerPool {
public:
    PeerPool() : currentCount(0), maxSize(64) {}

    void setMaxSize(size_t s) {
        lock_guard<mutex> lock(mut);
        maxSize = s;
        trimToSize(maxSize);
    }

    shared_ptr<Socket> get(const std::string & key, int64_t expireMs) {
        lock_guard<mutex> lock(mut);
        auto it = keyMap.find(key);
        if (it == keyMap.end() || it->second.empty()) {
            return shared_ptr<Socket>();
        }

        steady_clock::time_point now = steady_clock::now();
        while (!it->second.empty()) {
            auto elemIt = it->second.back();
            it->second.pop_back();

            shared_ptr<Socket> sock = elemIt->sock;
            steady_clock::time_point t = elemIt->time;
            lruList.erase(elemIt);
            --currentCount;

            int64_t elapsed = ToMilliSeconds(t, now);
            if (elapsed <= expireMs) {
                if (it->second.empty()) {
                    keyMap.erase(it);
                }
                return sock;
            } else {
                if (sock) {
                    sock->close();
                }
            }
        }

        keyMap.erase(it);
        return shared_ptr<Socket>();
    }

    void add(const std::string & key, shared_ptr<Socket> sock, int64_t expireMs) {
        if (!sock) {
            return;
        }

        lock_guard<mutex> lock(mut);
        if (maxSize == 0) {
            sock->close();
            return;
        }

        // If at capacity, trim the oldest idle connection
        if (currentCount >= maxSize) {
            trimToSize(maxSize - 1);
        }

        steady_clock::time_point now = steady_clock::now();
        PeerElement elem;
        elem.sock = sock;
        elem.time = now;
        elem.key = key;

        lruList.push_front(elem);
        keyMap[key].push_back(lruList.begin());
        ++currentCount;
    }

    void clear() {
        lock_guard<mutex> lock(mut);
        for (auto & item : lruList) {
            if (item.sock) {
                item.sock->close();
            }
        }
        lruList.clear();
        keyMap.clear();
        currentCount = 0;
    }

private:
    void trimToSize(size_t targetSize) {
        while (currentCount > targetSize && !lruList.empty()) {
            auto oldest = std::prev(lruList.end());
            std::string k = oldest->key;
            if (oldest->sock) {
                oldest->sock->close();
            }

            auto kit = keyMap.find(k);
            if (kit != keyMap.end()) {
                auto & vec = kit->second;
                for (auto vit = vec.begin(); vit != vec.end(); ++vit) {
                    if (*vit == oldest) {
                        vec.erase(vit);
                        break;
                    }
                }
                if (vec.empty()) {
                    keyMap.erase(kit);
                }
            }

            lruList.erase(oldest);
            --currentCount;
        }
    }

    mutex mut;
    size_t currentCount;
    size_t maxSize;
    std::list<PeerElement> lruList;
    std::unordered_map<std::string, std::vector<std::list<PeerElement>::iterator>> keyMap;
};

static PeerPool GlobalPeerPool;

} // namespace

PeerCache::PeerCache(const SessionConfig& conf)
    : cacheSize(conf.getSocketCacheCapacity()),
      expireTimeInterval(conf.getSocketCacheExpiry()) {
  GlobalPeerPool.setMaxSize(cacheSize);
}

std::string PeerCache::buildKey(const DatanodeInfo& datanode) {
  std::string key;
  key.reserve(datanode.getIpAddr().size() + 16 + datanode.getDatanodeId().size());
  key += datanode.getIpAddr();
  key += ':';
  key += std::to_string(datanode.getXferPort());
  key += ':';
  key += datanode.getDatanodeId();
  return key;
}

shared_ptr<Socket> PeerCache::getConnection(const DatanodeInfo& datanode) {
  std::string key = buildKey(datanode);
  shared_ptr<Socket> sock = GlobalPeerPool.get(key, expireTimeInterval);
  if (!sock) {
    LOG(DEBUG1, "PeerCache miss for datanode %s uuid(%s).",
        datanode.formatAddress().c_str(), datanode.getDatanodeId().c_str());
  } else {
    LOG(DEBUG1, "PeerCache hit for datanode %s uuid(%s).",
        datanode.formatAddress().c_str(), datanode.getDatanodeId().c_str());
  }
  return sock;
}

void PeerCache::addConnection(shared_ptr<Socket> peer,
                              const DatanodeInfo& datanode) {
  std::string key = buildKey(datanode);
  GlobalPeerPool.add(key, peer, expireTimeInterval);
  LOG(DEBUG1, "PeerCache add for datanode %s uuid(%s).",
      datanode.formatAddress().c_str(), datanode.getDatanodeId().c_str());
}

void PeerCache::clear() {
  GlobalPeerPool.clear();
}

}
}
