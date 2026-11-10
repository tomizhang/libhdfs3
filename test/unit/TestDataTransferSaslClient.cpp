#include "gtest/gtest.h"
#include "client/DataTransferSaslClient.h"

using namespace Hdfs;
using namespace Hdfs::Internal;

TEST(TestPayloadParse, EmptyString) {
    Payload p;
    Payload::Parse("", p);
    EXPECT_TRUE(p.realms.empty());
    EXPECT_TRUE(p.qop.empty());
}

TEST(TestPayloadParse, QuotedCommaInCipher) {
    Payload p;
    Payload::Parse(
        "realm=\"foo\",qop=\"auth,auth-conf\",algorithm=md5-sess,"
        "nonce=\"abc\",charset=utf-8,cipher=\"3des,rc4\"", p);
    ASSERT_EQ(1u, p.realms.size());
    EXPECT_EQ("foo", p.realms[0]);
    EXPECT_EQ("auth,auth-conf", p.qop);
    ASSERT_EQ(2u, p.cipher.size());
    EXPECT_EQ("3des", p.cipher[0]);
    EXPECT_EQ("rc4", p.cipher[1]);
}

TEST(TestPayloadParse, TrailingComma) {
    Payload p;
    Payload::Parse("realm=\"x\",", p);
    ASSERT_EQ(1u, p.realms.size());
    EXPECT_EQ("x", p.realms[0]);
}

TEST(TestChooseQop, EmptyProtectionNoEncryptIsAuth) {
    EXPECT_EQ("qop-auth", chooseDataTransferQop("", false, true, true, true));
}

TEST(TestChooseQop, EmptyProtectionDoesNotUpgradeToConf) {
    EXPECT_EQ("qop-auth", chooseDataTransferQop("", false, true, true, true));
}

TEST(TestChooseQop, EncryptForcesConf) {
    EXPECT_EQ("qop-conf", chooseDataTransferQop("", true, true, true, true));
}

TEST(TestChooseQop, IntegrityWithoutServerIntThrows) {
    EXPECT_THROW(chooseDataTransferQop("integrity", false, true, false, true),
                 SaslException);
}

TEST(TestChooseQop, PrivacyRequiresConf) {
    EXPECT_EQ("qop-conf", chooseDataTransferQop("privacy", false, true, true, true));
}

TEST(TestShouldWrap, AuthWithoutAesDoesNotWrap) {
    EXPECT_FALSE(shouldWrapDataTransferSocket("qop-auth", false));
}

TEST(TestShouldWrap, ConfAlwaysWraps) {
    EXPECT_TRUE(shouldWrapDataTransferSocket("qop-conf", false));
}

TEST(TestShouldWrap, AesCtrWrapsEvenIfQopAuth) {
    EXPECT_TRUE(shouldWrapDataTransferSocket("qop-auth", true));
}

#include <gsasl.h>

TEST(TestDigestMd5Handshake, Step1WithRealDataNodeChallenge) {
    Gsasl *ctx = NULL;
    ASSERT_EQ(GSASL_OK, gsasl_init(&ctx));

    Gsasl_session *session = NULL;
    ASSERT_EQ(GSASL_OK, gsasl_client_start(ctx, "DIGEST-MD5", &session));

    // Valid DIGEST-MD5 credentials for Hadoop Block Token
    gsasl_property_set(session, GSASL_AUTHID, "dGVzdC10b2tlbi1pZGVudGlmaWVy");
    gsasl_property_set(session, GSASL_PASSWORD, "dGVzdC1wYXNzd29yZA==");
    gsasl_property_set(session, GSASL_REALM, "0");
    gsasl_property_set(session, GSASL_HOSTNAME, "0");
    gsasl_property_set(session, GSASL_SERVICE, "hdfs");
    gsasl_property_set(session, GSASL_QOP, "qop-auth");

    // Real DataNode challenge string
    const char *challenge =
        "realm=\"0\",nonce=\"0ljCKo2I4sUNP2SIwpryXfvoOS2Duk9FtMXGkHDO\","
        "qop=\"auth,auth-int,auth-conf\",charset=utf-8,"
        "cipher=\"3des,rc4,des,rc4-56,rc4-40\",algorithm=md5-sess";

    char *output = NULL;
    size_t outputSize = 0;
    int rc = gsasl_step(session, challenge, strlen(challenge), &output, &outputSize);

    // Step 1 must succeed and return GSASL_NEEDS_MORE (output has the DIGEST response)
    EXPECT_EQ(GSASL_NEEDS_MORE, rc);
    EXPECT_GT(outputSize, 0u);
    if (output) {
        free(output);
    }

    gsasl_finish(session);
    gsasl_done(ctx);
}
