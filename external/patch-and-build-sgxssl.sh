#!/bin/bash
set +x

# Download OpenSSL
pushd intel-sgx-ssl/openssl_source
wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1k.tar.gz
popd

# Enable TLS
P_DIR="./seng-patches"
pushd intel-sgx-ssl && \
    patch -p1 < ../${P_DIR}/sgxssl/sgxssl_seng.patch && \
    popd || exit 1
popd
cp ${P_DIR}/sgxssl/libsgx_tsgxssl/* intel-sgx-ssl/Linux/sgx/libsgx_tsgxssl/ || exit 1

# Build
pushd intel-sgx-ssl/Linux
make all || exit 1
popd
