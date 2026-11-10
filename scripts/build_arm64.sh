#!/usr/bin/env bash
set -ex

echo "=== System glibc version ==="
ldd --version | head -n 1

echo "=== Installing system dependencies ==="
for i in 1 2 3 4 5; do
    echo "Attempt $i: Installing epel-release and config-manager..."
    if dnf install -y epel-release 'dnf-command(config-manager)'; then
        break
    fi
    dnf clean all || true
    sleep 5
done

dnf config-manager --set-enabled powertools || dnf config-manager --set-enabled crb || true

for i in 1 2 3 4 5; do
    echo "Attempt $i: Installing core build dependencies..."
    if dnf install -y gcc gcc-c++ cmake make autoconf automake libtool wget tar xz diffutils \
        krb5-devel libuuid-devel openssl-devel boost-devel zlib-devel git file binutils which; then
        break
    fi
    dnf clean all || true
    sleep 5
done

echo "=== Building static libgsasl 1.8.0 with -fPIC and MIT Kerberos GSSAPI ==="
cd /tmp
curl -sSL --retry 3 --retry-delay 5 -o gsasl-1.8.0.tar.gz https://ftp.gnu.org/gnu/gsasl/gsasl-1.8.0.tar.gz || \
curl -sSL --retry 3 --retry-delay 5 -o gsasl-1.8.0.tar.gz https://ftp.osuosl.org/pub/gnu/gsasl/gsasl-1.8.0.tar.gz
tar -xzf gsasl-1.8.0.tar.gz
cd gsasl-1.8.0
./configure --prefix=/usr/local --libdir=/usr/local/lib --enable-static --disable-shared --with-pic CFLAGS="-fPIC" --disable-nls --without-libidn --without-libntlm --with-gssapi-impl=mit
make -j$(nproc)
make install
cd /tmp && rm -rf gsasl-1.8.0*

echo "=== Verifying GSASL client mechanisms in static libgsasl.a ==="
cat << 'EOF' > /tmp/check_gsasl.c
#include <gsasl.h>
#include <stdio.h>
#include <string.h>

int main() {
    Gsasl *ctx = NULL;
    if (gsasl_init(&ctx) != GSASL_OK) {
        fprintf(stderr, "ERROR: gsasl_init failed\n");
        return 1;
    }
    char *list = NULL;
    gsasl_client_mechlist(ctx, &list);
    printf("Client mechanisms supported: %s\n", list ? list : "(none)");
    int gssapi = gsasl_client_support_p(ctx, "GSSAPI");
    int digest_md5 = gsasl_client_support_p(ctx, "DIGEST-MD5");
    printf("GSSAPI support: %d\n", gssapi);
    printf("DIGEST-MD5 support: %d\n", digest_md5);
    if (list) gsasl_free(list);
    gsasl_done(ctx);
    if (!gssapi) {
        fprintf(stderr, "FATAL: GSSAPI mechanism NOT supported in libgsasl!\n");
        return 1;
    }
    if (!digest_md5) {
        fprintf(stderr, "FATAL: DIGEST-MD5 mechanism NOT supported in libgsasl!\n");
        return 1;
    }
    printf("SUCCESS: Required SASL mechanisms verified in libgsasl.a!\n");
    return 0;
}
EOF
gcc /tmp/check_gsasl.c -I/usr/local/include /usr/local/lib/libgsasl.a -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -o /tmp/check_gsasl
/tmp/check_gsasl
rm -f /tmp/check_gsasl*

echo "=== Building static libxml2 2.9.14 with -fPIC ==="
cd /tmp
curl -sSL --retry 3 --retry-delay 5 -o libxml2-2.9.14.tar.xz https://download.gnome.org/sources/libxml2/2.9/libxml2-2.9.14.tar.xz
tar -xf libxml2-2.9.14.tar.xz
cd libxml2-2.9.14
./configure --prefix=/usr/local --libdir=/usr/local/lib --enable-static --disable-shared --with-pic CFLAGS="-fPIC" --with-zlib --without-python --without-lzma
make -j$(nproc)
make install
cd /tmp && rm -rf libxml2-2.9.14*

echo "=== Building static protobuf 3.0.0 with -fPIC ==="
cd /tmp
curl -sSL --retry 3 --retry-delay 5 -o protobuf-cpp-3.0.0.tar.gz https://github.com/protocolbuffers/protobuf/releases/download/v3.0.0/protobuf-cpp-3.0.0.tar.gz
tar -xzf protobuf-cpp-3.0.0.tar.gz
cd protobuf-3.0.0
./configure --prefix=/usr/local --libdir=/usr/local/lib --enable-static --disable-shared --with-pic CFLAGS="-fPIC -w" CXXFLAGS="-fPIC -std=c++11 -w -O2"
make -j$(nproc)
make install
cd /tmp && rm -rf protobuf-3.0.0*

echo "=== Syncing /usr/local/lib to /usr/local/lib64 ==="
mkdir -p /usr/local/lib64
cp -rn /usr/local/lib/* /usr/local/lib64/ 2>/dev/null || true
ldconfig

echo "=== Verifying dependencies in /usr/local ==="
ls -la /usr/local/lib/*.a
/usr/local/bin/protoc --version

echo "=== Building libhdfs3 via bootstrap (matching original GitLab CI) ==="
cd /workspace
rm -rf build dist
mkdir -p build
cd build
../bootstrap --prefix=/usr/local
make -j$(nproc)
make install

echo "=== Packaging artifacts matching original distribution ==="
cd /workspace
mkdir -p dist/lib dist/include
cp /usr/local/lib/libhdfs3.so dist/lib/
cp /usr/local/lib/libhdfs3.a dist/lib/
cp -r /usr/local/include/hdfs dist/include/

echo "=== In-container verification ==="
ls -la dist/lib/libhdfs3.so
file dist/lib/libhdfs3.so
ldd dist/lib/libhdfs3.so

if ldd dist/lib/libhdfs3.so | grep -E "libgsasl\.so|libprotobuf\.so|libxml2\.so|liblzma\.so|not found"; then
    echo "ERROR: Invalid dynamic dependencies detected in ldd!"
    exit 1
fi

echo "=== Verifying libhdfs3.so embedded GSASL runtime mechanisms ==="
cat << 'EOF' > /tmp/check_hdfs3_sasl.c
#include <gsasl.h>
#include <stdio.h>
#include <string.h>

int main() {
    Gsasl *ctx = NULL;
    if (gsasl_init(&ctx) != GSASL_OK) {
        fprintf(stderr, "ERROR: gsasl_init failed via libhdfs3.so\n");
        return 1;
    }
    char *list = NULL;
    gsasl_client_mechlist(ctx, &list);
    printf("libhdfs3 embedded GSASL mechanisms: %s\n", list ? list : "(none)");
    int gssapi = gsasl_client_support_p(ctx, "GSSAPI");
    int digest_md5 = gsasl_client_support_p(ctx, "DIGEST-MD5");
    printf("libhdfs3 GSSAPI support: %d\n", gssapi);
    printf("libhdfs3 DIGEST-MD5 support: %d\n", digest_md5);
    if (list) gsasl_free(list);
    gsasl_done(ctx);
    if (!gssapi) {
        fprintf(stderr, "FATAL: libhdfs3.so missing GSSAPI mechanism!\n");
        return 1;
    }
    if (!digest_md5) {
        fprintf(stderr, "FATAL: libhdfs3.so missing DIGEST-MD5 mechanism!\n");
        return 1;
    }
    printf("SUCCESS: libhdfs3.so SASL mechanisms verified!\n");
    return 0;
}
EOF
gcc /tmp/check_hdfs3_sasl.c -I/usr/local/include -L/workspace/dist/lib -lhdfs3 -Wl,-rpath=/workspace/dist/lib -o /tmp/check_hdfs3_sasl
/tmp/check_hdfs3_sasl
rm -f /tmp/check_hdfs3_sasl*

echo "=== Build and validation finished successfully! ==="
