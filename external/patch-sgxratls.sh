#!/bin/bash
set +x

P_DIR="./patches"
pushd sgx-ra-tls && \
    patch -p1 < ../${P_DIR}/sgx-ra-tls.patch && \
popd || exit 1

echo "Please generate your individual ra_tls_options.c file based on your Intel developer account using the following command within the external/sgx-ra-tls directory:"

echo 'SPID=xxx EPID_SUBSCRIPTION_KEY=yyy QUOTE_TYPE=SGX_(UN)LINKABLE_SIGNATURE ./ra_tls_options.c.sh > ra_tls_options.c'
