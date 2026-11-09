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
#ifndef _HDFS_LIBHDFS3_COMMON_CLIENTID_H_
#define _HDFS_LIBHDFS3_COMMON_CLIENTID_H_

#include <cstddef>
#include <string>

namespace Hdfs {
namespace Internal {

/**
 * Length in bytes of a Hadoop RPC client id (must match ClientId.BYTE_LENGTH
 * on the Java side, otherwise the NameNode RetryCache ignores it).
 */
const size_t CLIENT_ID_LENGTH = 16;

/**
 * Generate a 16-byte binary RFC 4122 version 4 UUID used as Hadoop RPC
 * client id.
 *
 * Random source order: OpenSSL RAND_bytes, then /dev/urandom, then
 * std::random_device. Each fallback is logged as a warning.
 *
 * @throw HdfsIOException if no random source is available.
 */
std::string GenerateClientId();

/**
 * Individual random sources, exposed for testing.
 * Each fills exactly n bytes and returns true, or returns false on failure.
 */
bool FillRandomFromOpenSSL(unsigned char * buf, size_t n);
bool FillRandomFromUrandom(unsigned char * buf, size_t n);
bool FillRandomFromRandomDevice(unsigned char * buf, size_t n);

}
}

#endif /* _HDFS_LIBHDFS3_COMMON_CLIENTID_H_ */
