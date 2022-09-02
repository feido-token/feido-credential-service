#!/bin/bash
TCBOR_PATCH=`pwd`/external/patches/tinycbor.patch

# Ensure you have created the ra_tls_options.c file (see bootstrap 2)

# 2. Patch and build sgx-tinycbor and sgx-ca
echo "***********************"
echo "Patch and build sgx-tinycbor and sgx-ca"
echo "***********************"
pushd server

pushd sgx-tinycbor
#ln -s ../misc/Tinycbor_SGXMakefile SGXMakefile && \
patch -p1 < ${TCBOR_PATCH} && \
ln -s ../../server/misc/Tinycbor_SGXMakefile SGXMakefile && \
make -f SGXMakefile || exit 1
popd

pushd sgx-ca
make -f SGXMakefile || exit 1
popd

popd

# 3. Build the server enclave
echo "***********************"
echo "Build the server enclave"
echo "***********************"
pushd server
make || exit 1
popd

exit 0
