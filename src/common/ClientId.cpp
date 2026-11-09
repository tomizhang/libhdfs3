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
#include "ClientId.h"

#include "Exception.h"
#include "ExceptionInternal.h"
#include "Logger.h"

#include <cerrno>
#include <exception>
#include <random>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>

namespace Hdfs {
namespace Internal {

bool FillRandomFromOpenSSL(unsigned char * buf, size_t n) {
    if (RAND_bytes(buf, static_cast<int>(n)) == 1) {
        return true;
    }

    LOG(WARNING, "GenerateClientId: RAND_bytes failed (openssl error %lu), "
        "falling back to /dev/urandom", ERR_get_error());
    return false;
}

bool FillRandomFromUrandom(unsigned char * buf, size_t n) {
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);

    if (fd >= 0) {
        size_t got = 0;

        while (got < n) {
            ssize_t r = ::read(fd, buf + got, n - got);

            if (r < 0 && errno == EINTR) {
                continue;
            }

            if (r <= 0) {
                break;
            }

            got += static_cast<size_t>(r);
        }

        ::close(fd);

        if (got == n) {
            return true;
        }
    }

    LOG(WARNING, "GenerateClientId: cannot read /dev/urandom, "
        "falling back to std::random_device");
    return false;
}

bool FillRandomFromRandomDevice(unsigned char * buf, size_t n) {
    try {
        std::random_device rd;

        for (size_t i = 0; i < n; i += sizeof(unsigned int)) {
            unsigned int v = rd();

            for (size_t j = 0; j < sizeof(unsigned int) && i + j < n; ++j) {
                buf[i + j] = static_cast<unsigned char>(v >> (8 * j));
            }
        }

        return true;
    } catch (const std::exception & e) {
        LOG(WARNING, "GenerateClientId: std::random_device failed: %s",
            e.what());
        return false;
    }
}

std::string GenerateClientId() {
    unsigned char id[CLIENT_ID_LENGTH];

    if (!FillRandomFromOpenSSL(id, sizeof(id))
            && !FillRandomFromUrandom(id, sizeof(id))
            && !FillRandomFromRandomDevice(id, sizeof(id))) {
        THROW(HdfsIOException,
              "GenerateClientId: no random source is available");
    }

    id[6] = (id[6] & 0x0F) | 0x40;  // version 4
    id[8] = (id[8] & 0x3F) | 0x80;  // RFC 4122 variant
    return std::string(reinterpret_cast<const char *>(id), sizeof(id));
}

}
}
