# Intel SGX Credential Service
The SGX Credential Service enclave that will communicate with the ePassport and
client middleware.

Please follow the bootstrap, build, and run instructions in the **root README file**.


## Build
Compile (and patch if required) `sgx-ca` and `sgx-tinycbor` before compiling the server.
Use the SGXMakefile in sgx-ca and misc for compilation, not the plain makefiles.

You currently have to build SGX SSL on your own before compiling the server.
You also have to build + install the SGX driver, SDK, and PSW before (cf. external/ scripts).

## Misc
Generation of `ra_tls_options.c` (in external/sgx-ra-tls/):
```
SPID=xxx EPID_SUBSCRIPTION_KEY=yyy QUOTE_TYPE=SGX_(UN)LINKABLE_SIGNATURE ./ra_tls_options.c.sh > ra_tls_options.c
```
