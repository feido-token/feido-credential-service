# Eval Prepare
The eval is different from the develop build in that it disables debug prints and uses non-debug compiler options.

0. bootstrap and get everything up as usual

1. comment out the `FEIDO_GLOBAL_DEBUG` define in `Enclave/Enclave_debug.h` and the `FIDO_SGX_CA_GLOBAL_DEBUG` define in `sgx-ca/fido_sgx_ca_debug.h`

2. rebuild the server libs and enclave:
```
./eval/rebuild-server-for-eval.bash
```

3. check that it says `The project has been built in pre-release hardware mode.` in the compilation output


## CLOC Measurement
Use the following command to measure the lines of C/C++ code and headers:
```
cloc --exclude-list-file=eval/cloc-exclude.txt Enclave Server Include
```
