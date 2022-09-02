#!/bin/bash

# 0. Fetch submodules
echo "***********************"
echo "Fetching submodules"
echo "***********************"
git submodule update --init || exit 1 #--recursive

# 1. Patch and build external git submodules
echo "***********************"
echo "Patch and build submodules"
echo "***********************"
pushd external
./prepare-sdk-psw-with-openssl.sh && \
./build-sdk-psw-with-openssl.sh  || exit 1
popd

exit 0
