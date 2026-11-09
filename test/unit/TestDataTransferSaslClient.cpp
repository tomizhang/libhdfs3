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
