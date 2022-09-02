#!/bin/bash

pushd linux-sgx
## SDK
make sdk USE_OPT_LIBS=0 || exit 1
make sdk_install_pkg USE_OPT_LIBS=0 || exit 1

# As we don't run the install script below as root atm (caused some problems in
# the past)
sudo mkdir -p /opt/intel/sgxsdk &&
sudo chown `users` /opt/intel/sgxsdk || exit 1

printf 'no\n/opt/intel\n' | ./linux/installer/bin/sgx_linux_x64_sdk_2.15.100.1.bin || exit 1
## PSW
make psw && \
make deb_psw_pkg && \
make deb_local_repo || exit 1

echo "Add to /etc/apt/sources.list:"
echo "deb [trusted=yes arch=amd64] file:/PATH_TO_LOCAL_REPO bionic main"

echo "Then:"
echo "sudo apt-get install libsgx-launch libsgx-urts libsgx-launch-dev libsgx-epid libsgx-epid-dev libsgx-quote-ex libsgx-quote-ex-dev libsgx-enclave-common-dev libsgx-uae-service"

echo "PATH_TO_LOCAL_REPO is probably: `pwd`/linux-sgx/linux/installer/deb/sgx_debian_local_repo"
popd

