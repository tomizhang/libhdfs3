#!/usr/bin/env bash
set -ex

echo "=== System glibc version ==="
ldd --version | head -n 1

echo "=== Installing system dependencies ==="
dnf install -y epel-release 'dnf-command(config-manager)'
dnf config-manager --set-enabled powertools || dnf config-manager --set-enabled crb || true
dnf install -y gcc gcc-c++ cmake make autoconf automake libtool wget tar xz diffutils \
    krb5-devel libuuid-devel openssl-devel boost-devel zlib-devel

echo "=== Building static libgsasl with -fPIC ==="
cd /tmp
wget -q https://ftp.gnu.org/gnu/gsasl/gsasl-1.8.0.tar.gz
tar -xzf gsasl-1.8.0.tar.gz
cd gsasl-1.8.0
./configure --prefix=/usr/local --libdir=/usr/local/lib --enable-static --disable-shared --with-pic CFLAGS="-fPIC" --disable-nls --without-libidn --without-libntlm
make -j$(nproc)
make install
cd /tmp && rm -rf gsasl-1.8.0*

echo "=== Building static libxml2 with -fPIC ==="
cd /tmp
wget -q https://download.gnome.org/sources/libxml2/2.9/libxml2-2.9.12.tar.xz
tar -xf libxml2-2.9.12.tar.xz
cd libxml2-2.9.12
./configure --prefix=/usr/local --libdir=/usr/local/lib --enable-static --disable-shared --without-python --without-lzma --without-zlib --with-pic CFLAGS="-fPIC"
make -j$(nproc)
make install
cd /tmp && rm -rf libxml2-2.9.12*

echo "=== Building static protobuf 3.5.1 with -fPIC ==="
cd /tmp
wget -q https://github.com/protocolbuffers/protobuf/releases/download/v3.5.1/protobuf-cpp-3.5.1.tar.gz
tar -xzf protobuf-cpp-3.5.1.tar.gz
cd protobuf-3.5.1
./configure --prefix=/usr/local --libdir=/usr/local/lib --enable-static --disable-shared --with-pic CFLAGS="-fPIC" CXXFLAGS="-fPIC -std=c++11"
make -j$(nproc)
make install
cd /tmp && rm -rf protobuf-3.5.1*

echo "=== Verifying static libraries in /usr/local/lib ==="
mkdir -p /usr/local/lib64
cp -rn /usr/local/lib/* /usr/local/lib64/ 2>/dev/null || true
ls -la /usr/local/lib/*.a
protoc --version
ldconfig

echo "=== Configuring libhdfs3 ==="
cd /workspace
rm -rf build-glibc228
mkdir -p build-glibc228
cd build-glibc228
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="/usr/local"

echo "=== Building libhdfs3.so ==="
make -j$(nproc) libhdfs3-shared

echo "=== Inspecting dependencies in AlmaLinux 8 container ==="
ldd src/libhdfs3.so

echo "=== Verifying no missing libraries ==="
if ldd src/libhdfs3.so | grep -q "not found"; then
    echo "ERROR: Missing runtime shared libraries found in ldd output!"
    exit 1
fi

echo "=== Verifying static linkage of gsasl, protobuf, libxml2 ==="
if ldd src/libhdfs3.so | grep -E "libgsasl\.so|libprotobuf\.so|libxml2\.so|liblzma\.so"; then
    echo "ERROR: libgsasl, libprotobuf, libxml2, or liblzma was dynamically linked instead of statically linked!"
    exit 1
fi

echo "SUCCESS: All libhdfs3.so dependencies verified against baseline!"
