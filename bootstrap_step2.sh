#!/bin/bash

# continue: 1. patch and build of external modules
# note: ensure that you followed the steps of bootstrap 1 regarding the
#       installation of the SGX SDK/PSW from the local deb repo
pushd external
./patch-and-build-sgxssl.sh && \
./build-driver.sh || exit 1

./patch-sgxratls.sh || exit 1
popd

exit 0