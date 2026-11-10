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
#include "SaslClient.h"
#include "common/Memory.h"
#include "common/Logger.h"
#include "common/DebugUtil.h"
#include "common/SessionConfig.h"
#include "client/Token.h"
#include "Socket.h"
#include "SocketReader.h"
#include "SocketWriter.h"
#include "BufferedSocketReader.h"

#include <string>
#include <mutex>
#include <cstring>
#include <krb5/krb5.h>
#include <gsasl.h>


namespace Hdfs {
namespace Internal {

SaslClient::SaslClient(const std::shared_ptr<Socket> socket, 
                       const SessionConfig & conf, 
                       const Token & token, 
                       const std::string & principal): 
    underlyingSocket(socket), conf(conf), token(token), principal(principal), complete(false) {
    underlyingSocketReader = std::make_shared<BufferedSocketReader>(socket);
    underlyingSocketWriter = std::make_shared<SocketWriterImpl>(socket);
}

SaslClient::~SaslClient() {
    underlyingSocketReader.reset();
    underlyingSocketWriter.reset();
    underlyingSocket.reset();
}

bool SaslClient::isComplete(){
    return complete;
}



GSaslClient::GSaslClient(const std::shared_ptr<Socket> s,
                         const SessionConfig & c, 
                         const Token & t, 
                         const std::string & p): 
                         SaslClient(s, c, t, p), ctx(nullptr), session(nullptr) {
}

GSaslClient::~GSaslClient() {
    LOG(DEBUG1, "GSaslClient::~GSaslClient Begin");
    if (ctx != nullptr) {
        if (session != nullptr) {
            LOG(DEBUG1, "GSaslClient::~GSaslClient->gsasl_finish");
            gsasl_finish(session);
            session = nullptr;
        }
        LOG(DEBUG1, "GSaslClient::~GSaslClient->gsasl_done");
        gsasl_done(ctx);
        ctx = nullptr;
    }
    LOG(DEBUG1, "GSaslClient::~GSaslClient End");
}

std::string GSaslClient::evaluateChallenge(const std::string & challenge) {
    LOG(DEBUG1, "GSaslClient::evaluateChallenge From: [%s]", challenge.c_str());
    std::string retval;
    char * output = NULL;
    size_t outputSize;
    int rc = gsasl_step(session, challenge.c_str(), challenge.size(), &output, &outputSize);
    if (rc == GSASL_NEEDS_MORE || rc == GSASL_OK) {
        retval.resize(outputSize);
        memcpy(&retval[0], output, outputSize);
        if (output) {
            free(output);
        }
        LOG(DEBUG1, "GSaslClient::evaluateChallenge To: [%s]", retval.c_str());
        return retval;
    } else {
        const char * msg = gsasl_strerror(rc);
        LOG(LOG_ERROR, "GSaslClient::evaluateChallenge Error: %s", msg);
        THROW(SaslException, "GSaslClient sasl error: %s", msg);
    }
}

void GSaslClient::encrypt(std::string & dst, const std::string_view & src) {
    //LOG(DEBUG1, "GSaslClient::encrypt Begin");
    char * output = NULL;
    size_t outputSize;
    int rc = gsasl_encode(session, src.data(), src.size(), &output, &outputSize);
    if (rc == GSASL_OK) {
        dst.resize(outputSize);
        memcpy(dst.data(), output, outputSize);
        if (output) {
            free(output);
        }
    } else {
        const char * msg = gsasl_strerror(rc);
        LOG(LOG_ERROR, "GSaslClient::encrypt Error: %s", msg);
        THROW(SaslException, "Gsasl encrypt error: %s", msg);
    }
    //LOG(DEBUG1, "GSaslClient::encrypt End");
}

void GSaslClient::decrypt(std::string & dst, const std::string_view & src) {
    //LOG(DEBUG1, "GSaslClient::decrypt Begin");
    //LOG(DEBUG1, "GSaslClient::decrypt From: [%lu][%s]", 
    //    src.size(), dataToHex((unsigned char *)src.data(), src.size()).c_str());
    char * output = NULL;
    size_t outputSize;
    int rc = gsasl_decode(session, src.data(), src.size(), &output, &outputSize);
    if (rc == GSASL_OK) {
        //dst.reserve(outputSize);
        dst.resize(outputSize);
        memcpy(dst.data(), output, outputSize);
        if (output) {
            free(output);
        }
    } else {
        const char * msg = gsasl_strerror(rc);
        LOG(LOG_ERROR, "GSaslClient::decrypt Error: %s", msg);
        THROW(SaslException, "Gsasl decrypt error: %s", msg);
    }
    //LOG(DEBUG1, "GSaslClient::decrypt To: [%lu][%s]", outputSize, dataToHex((unsigned char *)output, outputSize).c_str());
    //LOG(DEBUG1, "GSaslClient::decrypt End");
}

bool GSaslClient::kinitFromKeytab(const std::string & principalName,
                                  const std::string & keytabFile,
                                  const std::string & ccachePath) {
    if (keytabFile.empty()) {
        return false;
    }

    static std::mutex s_kinitMutex;
    std::lock_guard<std::mutex> lock(s_kinitMutex);

    krb5_context ctx = NULL;
    krb5_principal principal = NULL;
    krb5_keytab keytab = NULL;
    krb5_ccache ccache = NULL;
    krb5_creds creds;
    memset(&creds, 0, sizeof(creds));
    krb5_error_code ec = 0;

    ec = krb5_init_context(&ctx);
    if (ec != 0) {
        LOG(LOG_ERROR, "kinitFromKeytab: Failed to init krb5 context (%d)", ec);
        return false;
    }

    do {
        ec = krb5_kt_resolve(ctx, keytabFile.c_str(), &keytab);
        if (ec != 0) {
            const char * msg = krb5_get_error_message(ctx, ec);
            LOG(LOG_ERROR, "kinitFromKeytab: Failed to resolve keytab \"%s\": %s",
                keytabFile.c_str(), msg ? msg : "");
            if (msg) krb5_free_error_message(ctx, msg);
            break;
        }

        if (!principalName.empty()) {
            ec = krb5_parse_name(ctx, principalName.c_str(), &principal);
            if (ec != 0) {
                const char * msg = krb5_get_error_message(ctx, ec);
                LOG(LOG_ERROR, "kinitFromKeytab: Failed to parse principal \"%s\": %s",
                    principalName.c_str(), msg ? msg : "");
                if (msg) krb5_free_error_message(ctx, msg);
                break;
            }
        } else {
            // Read first principal from keytab
            krb5_kt_cursor cursor = NULL;
            krb5_keytab_entry entry;
            ec = krb5_kt_start_seq_get(ctx, keytab, &cursor);
            if (ec == 0) {
                if ((ec = krb5_kt_next_entry(ctx, keytab, &entry, &cursor)) == 0) {
                    ec = krb5_copy_principal(ctx, entry.principal, &principal);
                    krb5_free_keytab_entry_contents(ctx, &entry);
                }
                krb5_kt_end_seq_get(ctx, keytab, &cursor);
            }
            if (ec != 0 || principal == NULL) {
                LOG(LOG_ERROR, "kinitFromKeytab: Failed to extract principal from keytab \"%s\"", keytabFile.c_str());
                break;
            }
        }

        ec = krb5_get_init_creds_keytab(ctx, &creds, principal, keytab, 0, NULL, NULL);
        if (ec != 0) {
            const char * msg = krb5_get_error_message(ctx, ec);
            char * parsedName = NULL;
            krb5_unparse_name(ctx, principal, &parsedName);
            LOG(LOG_ERROR, "kinitFromKeytab: Failed to acquire credentials from keytab \"%s\" for principal \"%s\": %s",
                keytabFile.c_str(), parsedName ? parsedName : principalName.c_str(), msg ? msg : "");
            if (parsedName) krb5_free_unparsed_name(ctx, parsedName);
            if (msg) krb5_free_error_message(ctx, msg);
            break;
        }

        if (!ccachePath.empty()) {
            ec = krb5_cc_resolve(ctx, ccachePath.c_str(), &ccache);
            setenv("KRB5CCNAME", ccachePath.c_str(), 1);
        } else {
            ec = krb5_cc_default(ctx, &ccache);
        }

        if (ec != 0) {
            const char * msg = krb5_get_error_message(ctx, ec);
            LOG(LOG_ERROR, "kinitFromKeytab: Failed to resolve ccache: %s", msg ? msg : "");
            if (msg) krb5_free_error_message(ctx, msg);
            break;
        }

        ec = krb5_cc_initialize(ctx, ccache, principal);
        if (ec != 0) {
            const char * msg = krb5_get_error_message(ctx, ec);
            LOG(LOG_ERROR, "kinitFromKeytab: Failed to initialize ccache: %s", msg ? msg : "");
            if (msg) krb5_free_error_message(ctx, msg);
            break;
        }

        ec = krb5_cc_store_cred(ctx, ccache, &creds);
        if (ec != 0) {
            const char * msg = krb5_get_error_message(ctx, ec);
            LOG(LOG_ERROR, "kinitFromKeytab: Failed to store credentials in ccache: %s", msg ? msg : "");
            if (msg) krb5_free_error_message(ctx, msg);
            break;
        }

        char * finalName = NULL;
        krb5_unparse_name(ctx, principal, &finalName);
        LOG(DEBUG1, "kinitFromKeytab: Successfully obtained and stored Kerberos ticket for %s using keytab %s",
            finalName ? finalName : principalName.c_str(), keytabFile.c_str());
        if (finalName) krb5_free_unparsed_name(ctx, finalName);
    } while (0);

    if (creds.client != NULL) {
        krb5_free_cred_contents(ctx, &creds);
    }
    if (ccache != NULL) {
        krb5_cc_close(ctx, ccache);
    }
    if (keytab != NULL) {
        krb5_kt_close(ctx, keytab);
    }
    if (principal != NULL) {
        krb5_free_principal(ctx, principal);
    }
    if (ctx != NULL) {
        krb5_free_context(ctx);
    }

    return (ec == 0);
}

}
}
