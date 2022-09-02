#!/bin/bash

# Driver
sudo apt-get install linux-headers-$(uname -r)

## optional (unused atm)
sudo apt-get install dkms

pushd SGXDataCenterAttestationPrimitives/driver/linux
make clean && \
make || exit 1
sudo insmod intel_sgx.ko
## udev /dev permissions
sudo cp  10-sgx.rules /etc/udev/rules.d
sudo groupadd sgx_prv
sudo udevadm trigger
popd

