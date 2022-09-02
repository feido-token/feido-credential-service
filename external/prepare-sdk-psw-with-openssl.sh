#!/bin/bash
DCAP_PATCH=`pwd`/patches/sdk-dcap_source.patch
SMPL_PATCH=`pwd`/patches/samplecode-fixes.patch

# Assumes Ubuntu 18.04 LTS
sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev git cmake perl
sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip

pushd linux-sgx
make clean

# Patch SampleCode build errors
patch -p1 < ${SMPL_PATCH} || exit 1

# Patch dcap_source tool to prevent build errors
git submodule update --init --recursive external/dcap_source || exit 1
pushd external/dcap_source
patch -p1 < ${DCAP_PATCH} || exit 1
popd

make preparation || exit 1
# Assumes Ubuntu 18.04 LTS
sudo cp external/toolset/ubuntu18.04/{as,ld,objdump} /usr/local/bin
popd

