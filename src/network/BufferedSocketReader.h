/********************************************************************
 * Copyright (c) 2024 - 2025, Visionsky.
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
#ifndef _HDFS_LIBHDFS3_NETWORK_BUFFEREDSOCKETREADER_H_
#define _HDFS_LIBHDFS3_NETWORK_BUFFEREDSOCKETREADER_H_

#include "common/Memory.h"
#include "Socket.h"
#include "SocketReader.h"

#include <vector>
#include <stdint.h>
#include <cstdlib>

namespace Hdfs {
namespace Internal {

class BufferedSocketReader: public SocketReader {
public:
    BufferedSocketReader(std::shared_ptr<Socket> s);

    BufferedSocketReader(std::shared_ptr<Socket> s, size_t bufferSize);

    ~BufferedSocketReader();

    int32_t read(char * b, int32_t s);

    void readFully(char * b, int32_t s, int timeout);

    int32_t readBigEndianInt32(int timeout);

    int32_t readVarint32(int timeout);

    bool poll(int timeout);

private:
    int32_t readVarint32(int timeout, int32_t step);

    //for test
    BufferedSocketReader(std::shared_ptr<Socket> s, const std::vector<char> & buffer) :
        cursor(0), size(buffer.size()), socket(s), buffer(buffer) {
    }

private:
    int32_t cursor;
    int32_t size;
    std::shared_ptr<Socket> socket;
    std::vector<char> buffer;
};

}
}

#endif /* _HDFS_LIBHDFS3_NETWORK_BUFFEREDSOCKETREADER_H_ */
