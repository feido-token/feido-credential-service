# FeIDo Credential Service, Intel SGX version
Prototype of FeIDo's Credential Service implemented as an RA-TLS network service
protected via Intel SGX.
The Credential Service performs the attribute-based KDF of FIDO WebAuthn credentials.


## Repo Structure
* `server/`: SGX enclave performing the eID CA/PA protocols and the FIDO2 key derivation and challenge signing

* `protobuf/`: includes symlink to enclave-client shared protobuf file (see umbrella repo)

* `external/`: external submodules and patches + build scripts for them

## Bootstrap Instructions
**Note:** Please fetch this repo as a submodule of the umbrella repo: https://github.com/feido-token/feido.
Otherwise, the symoblic links to the FeIDo protobuf files will not resolve.

The bootstrap process requires a combination of semi-automatic scripts and manual efforts.
The process builds and installs the Intel SGX SDK, PSW, and kernel driver, as well as the required libraries for building the SGX enclave.
Consider commenting out some install steps in the build scripts of `external/` when you need to rerun the whole bootstrap process and have certain parts already installed.

**Warning**: the following bootstrap scripts have been tested with `Ubuntu 18.04.6 LTS`, and a generic 4.15.0-166 Linux kernel.
When running with a different Ubuntu version / Linux distro, you will probably have to adjust the following part in `external/prepare-sdk-psw-with-openssl.sh:21`:
```
# replace the following line:
sudo cp external/toolset/ubuntu18.04/{as,ld,objdump} /usr/local/bin

# e.g., for Ubuntu 20.04, with:
sudo cp external/toolset/ubuntu20.04/{as,ld,objdump} /usr/local/bin
```
Also note that you might have to change the packet names that are getting installed from the `apt` repos (e.g., for the SGX SDK/PSW in the mentioned prepare script).

**Warning**: the SGX kernel driver build and install currently uses the DCAP driver, i.e., it assumes that your CPU supports flexible launch control (check if `cpuid | grep -i SGX_LC` shows true).
If your CPU does not have that support, you have to build the non-DCAP kernel driver.
It also assumes that you do not have upstream, builtin SGX Linux kernel support.

The bootstrap process then works in the following way:
```
# start from root directory of the SGX enclave git repo

./bootstrap_step1.sh

# (!) SGX SDK package installation:  perform the manual steps shown after successful bootstrap step 1 in the console

# only call after finishing the previous manual steps!
./bootstrap_step2.sh

# (!) Generate ra_tls_options.c using your Intel Account data:  perform the manual steps shown after successful bootstrap step 2 in the console

# only call after finishing the previous manual steps!
./bootstrap_step3.sh

# you're ready to run the enclave if everything was successful
```

**Warning**: the process does currently *not* install the kernel driver permanently, i.e., you have to reload it currently after every system reboot. This can be done the following way:
```
cd external/SGXDataCenterAttestationPrimitives/driver/linux
sudo insmod intel_sgx.ko

# restart Intel SGX service
sudo service aesmd restart
```


## Server Enclave Build and Run (after Bootstrap)
Perform the following steps **only after a successful bootstrap process**.

**Important:** By default, the enclave is build in hardware *debug* mode.
To build in prerelease build (more optimized), check the below instruction E.

```
# A. Running the SGX enclave
cd server
./credservice-sgx

# B. Rebuild the SGX enclave
cd server
make clean && make

# C. Recommended: more extensive enclave rebuild (enclave + sgx-ca)
cd server
cd sgx-ca && make -f SGXMakefile clean  && make -f SGXMakefile && cd .. && make clean && make

## Note: you might also need to recompile sgx-tinycbor, e.g., when changing to non-debug build

# D. Most extensive rebuild (enclave + sgx-ca + tinycbor)
cd server
cd sgx-tinycbor && make -f SGXMakefile clean && make -f SGXMakefile && cd .. && \
cd sgx-ca && make -f SGXMakefile clean  && make -f SGXMakefile && cd .. && \
make clean && make

# E. For eval non-debug rebuild: cf. server/EVAL.md
cd server
./eval/rebuild-server-for-eval.bash
```

*Tip: If you see a direct enclave loading error when trying to run the server enclave,
check if you remembered to reload the kernel driver and to restart the SGX service after a system reboot.*

*Tip: If your generation of the `ra_tls_options.c` file went wrong, the enclave might
seg.fault shortly after start.*


## Server Enclave Configuration
By default the enclave listens on `TCP` port `4433` on `all IPs` with blocking socket for an incoming `TLS` connection.
See `server/Server/Server.cpp` main function for that.

The feature support, IP, and port of the demo eID database service is currently hardcoded in the `Makefile` via the `ENABLE_ICHECKIT`, `CONF_ICHECKIT_ADDRESS`, and `CONF_ICHECKIT_PORT` variables.


## Limitations / Todos
As this is a proof of concept research type, some features are missing or limited:
* CSCA certificates are currently hardcoded rather than being dynamically loaded
* no check of eID's issuing country code against CSCA
* no certificate verification of eID database service
* no support for anonymous credentials yet
