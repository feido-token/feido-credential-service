sdk-dcap_source.patch:
applied to external/linux-sgx/external/sgx-dcap/

Otherwise the build of dcap_source/tools/PCKRetrievalTool will fail with stuff
like undefined reference to `sgx_oc_cpuidex'
