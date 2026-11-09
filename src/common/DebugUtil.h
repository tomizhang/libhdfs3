/********************************************************************
 * Copyright (c) 2024 - 2025, Vincent.
 * All rights reserved.
 *
 * Author: Vincent
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
#ifndef _HDFS_LIBHDFS3_COMMON_DEBUGUTIL_H_
#define _HDFS_LIBHDFS3_COMMON_DEBUGUTIL_H_

#include <string>
#include <sstream>
#include <iomanip>

namespace Hdfs {
namespace Internal {

inline static std::string stringToHex(const std::string &input)
{
    std::stringstream hexStream;
    // 保证每个十六进制数以两个字符的形式表示，不足位用0填充
    hexStream << std::hex << std::setfill('0');
    bool first = true;
    for (unsigned char c : input) {
        if (first)
        {
            first = false;
        } else {
            hexStream << " ";
        }
        // std::setw(2) 确保输出是两个字符宽
        hexStream << std::setw(2) << static_cast<int>(c);
    }
    return hexStream.str();
}

inline static std::string dataToHex(const unsigned char * input, size_t size)
{
    std::stringstream hexStream;
    // 保证每个十六进制数以两个字符的形式表示，不足位用0填充
    hexStream << std::hex << std::setfill('0');
    bool first = true;
    for(size_t index = 0; index<size; index++){
        unsigned char c = input[index];
        if (first)
        {
            first = false;
        } else {
            hexStream << " ";
        }
        // std::setw(2) 确保输出是两个字符宽
        hexStream << std::setw(2) << static_cast<int>(c);
    }
    return hexStream.str();
}

}
}

#endif /* _HDFS_LIBHDFS3_COMMON_DEBUGUTIL_H_ */