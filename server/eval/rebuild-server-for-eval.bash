#!/bin/bash

# Warning: assumes bootstrap process has been successfully finished before

# as mentioned in EVAL.md
export SGX_DEBUG=0 SGX_PRERELEASE=1

cd sgx-tinycbor && make -f SGXMakefile clean && make -f SGXMakefile && cd .. || exit 1
cd sgx-ca && make -f SGXMakefile clean  && make -f SGXMakefile && cd .. || exit 1
make clean && make || exit 1

exit 0
