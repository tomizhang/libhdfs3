#!/usr/bin/env bash
set -ex

echo "=== System glibc version ==="
ldd --version | head -n 1

echo "=== Installing system dependencies ==="
dnf install -y epel-release 'dnf-command(config-manager)'
dnf config-manager --set-enabled powertools || dnf config-manager --set-enabled crb || true
dnf install -y gcc gcc-c++ cmake make autoconf automake libtool wget tar xz diffutils \
    krb5-devel libuuid-devel openssl-devel boost-devel zlib-devel git file binutils

echo "=== Building static libgsasl 1.8.0 with -fPIC ==="
cd /tmp
wget -q --tries=3 --timeout=30 https://ftp.gnu.org/gnu/gsasl/gsasl-1.8.0.tar.gz || \
wget -q --tries=3 --timeout=30 https://ftp.osuosl.org/pub/gnu/gsasl/gsasl-1.8.0.tar.gz
tar -xzf gsasl-1.8.0.tar.gz
cd gsasl-1.8.0
./configure --prefix=/usr/local --libdir=/usr/local/lib --enable-static --disable-shared --with-pic CFLAGS="-fPIC" --disable-nls --without-libidn --without-libntlm
make -j$(nproc)
make install
cd /tmp && rm -rf gsasl-1.8.0*

echo "=== Building static libxml2 2.9.14 with -fPIC ==="
cd /tmp
wget -q --tries=3 --timeout=30 https://download.gnome.org/sources/libxml2/2.9/libxml2-2.9.14.tar.xz
tar -xf libxml2-2.9.14.tar.xz
cd libxml2-2.9.14
./configure --prefix=/usr/local --libdir=/usr/local/lib --enable-static --disable-shared --with-pic CFLAGS="-fPIC" --with-zlib --without-python --without-lzma
make -j$(nproc)
make install
cd /tmp && rm -rf libxml2-2.9.14*

echo "=== Building static protobuf 3.0.0 with -fPIC ==="
cd /tmp
wget -q --tries=3 --timeout=30 https://github.com/protocolbuffers/protobuf/releases/download/v3.0.0/protobuf-cpp-3.0.0.tar.gz
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

echo "=== Build and validation finished successfully! ==="
