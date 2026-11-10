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
#ifndef _HDFS_LIBHDFS3_RPC_SASLCLIENT_H_
#define _HDFS_LIBHDFS3_RPC_SASLCLIENT_H_

#include "common/Memory.h"
#include "common/SessionConfig.h"
#include "client/Token.h"
#include "Socket.h"
#include "SocketReader.h"
#include "SocketWriter.h"
#include "BufferedSocketReader.h"

#include <string>
#include <string_view>
#include <gsasl.h>
#include <krb5/krb5.h>

namespace Hdfs {
namespace Internal {

class SaslClient {
public:
    SaslClient(const std::shared_ptr<Socket> socket, 
               const SessionConfig & conf, 
               const Token & token, 
               const std::string & principal);

    virtual ~SaslClient();

    virtual std::shared_ptr<Socket> doHandshake() = 0;

    virtual std::string evaluateChallenge(const std::string & chanllege) = 0;

    virtual bool isComplete();

    virtual void encrypt(std::string & dst, const std::string_view & src) = 0;

    virtual void decrypt(std::string & dst, const std::string_view & src) = 0;

protected:
    std::shared_ptr<Socket> underlyingSocket;
    bool complete;

    const SessionConfig & conf;
    Token token;
    std::string principal;

    std::shared_ptr<SocketReader> underlyingSocketReader;
    std::shared_ptr<SocketWriter> underlyingSocketWriter;
};

class GSaslClient: public SaslClient {

public:

    GSaslClient(const std::shared_ptr<Socket> s,
                const SessionConfig & c, 
                const Token & t, 
                const std::string & p);

    ~GSaslClient() override;

    std::shared_ptr<Socket> doHandshake() override = 0;

    std::string evaluateChallenge(const std::string & challenge) override;

    void encrypt(std::string & dst, const std::string_view & src) override;

    void decrypt(std::string & dst, const std::string_view & src) override;

    inline static void setKRB5ClientKTName(const std::string & keytab) {
        if (!keytab.empty()) {
            if (0 != setenv("KRB5_CLIENT_KTNAME", keytab.c_str(), 1)) {
                THROW(HdfsIOException, "Cannot set env parameter \"KRB5_CLIENT_KTNAME\"");
            }
        }
    }

    static bool kinitFromKeytab(const std::string & principalName,
                                const std::string & keytabFile,
                                const std::string & ccachePath = "");

protected:

    inline static std::string extractPrincipalFromTicketCache(const std::string &cachePath) {
        krb5_context cxt = NULL;
        krb5_ccache ccache = NULL;
        krb5_principal principal = NULL;
        krb5_error_code ec = 0;
        std::string errmsg, retval;
        char *priName = NULL;

        if (!cachePath.empty())
        {
            if (0 != setenv("KRB5CCNAME", cachePath.c_str(), 1))
            {
                THROW(HdfsIOException, "Cannot set env parameter \"KRB5CCNAME\"");
            }
        }

        do
        {
            if (0 != (ec = krb5_init_context(&cxt)))
            {
                break;
            }

            if (0 != (ec = krb5_cc_default(cxt, &ccache)))
            {
                break;
            }

            if (0 != (ec = krb5_cc_get_principal(cxt, ccache, &principal)))
            {
                break;
            }

            if (0 != (ec = krb5_unparse_name(cxt, principal, &priName)))
            {
                break;
            }
        } while (0);

        if (!ec)
        {
            retval = priName;
        }
        else
        {
            if (cxt)
            {
                errmsg = krb5_get_error_message(cxt, ec);
            }
            else
            {
                errmsg = "Cannot initialize kerberos context";
            }
        }

        if (priName != NULL)
        {
            krb5_free_unparsed_name(cxt, priName);
        }

        if (principal != NULL)
        {
            krb5_free_principal(cxt, principal);
        }

        if (ccache != NULL)
        {
            krb5_cc_close(cxt, ccache);
        }

        if (cxt != NULL)
        {
            krb5_free_context(cxt);
        }

        if (!errmsg.empty())
        {
            THROW(HdfsIOException,
                    "FileSystem: Filed to extract principal from ticket cache: %s",
                    errmsg.c_str());
        }

        return retval;
    }

    inline static std::string base64Encode(const std::string & in){
        char * temp;
        size_t len;
        std::string retval;
        int rc = gsasl_base64_to(in.c_str(), in.size(), &temp, &len);

        if (rc != GSASL_OK) {
            throw std::bad_alloc();
        }

        if (temp) {
            retval = temp;
            free(temp);
        }

        if (!temp || retval.length() != len) {
            THROW(HdfsIOException, "SaslClient: Failed to encode string to base64");
        }
        return retval;
    }

protected:
    Gsasl * ctx;
    Gsasl_session * session;
};


}
}

#endif /* _HDFS_LIBHDFS3_RPC_SASLCLIENT_H_ */
