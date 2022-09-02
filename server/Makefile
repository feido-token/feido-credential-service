######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH = x64
SGX_DEBUG ?= 1

# eval build
#SGX_DEBUG = 0
#SGX_PRERELEASE = 1

# demo I-Checkit service
ENABLE_ICHECKIT = 1
CONF_ICHECKIT_ADDRESS = '"127.0.0.1"'
CONF_ICHECKIT_PORT = 4711

EPASS_CA_PATH ?= sgx-ca
EPASS_CA_LIB ?= tsgx_epass_ca

CBOR_PATH ?= sgx-tinycbor
CBOR_LIB ?= tsgx_tinycbor

SSL_PATH ?= ../external/intel-sgx-ssl/Linux/package
SSL_INC ?= ${SSL_PATH}/include
SSL_LIB ?= ${SSL_PATH}/lib64

SSL_OPENSSL_LIB := sgx_tsgxssl_crypto
SSL_TRUSTED_LIB := sgx_tsgxssl
SSL_UNTRUSTED_LIB := sgx_usgxssl

SSL_TRUSTED_TLS_LIB := sgx_tsgxssl_tls

SgxSSL_Link_Libraries := -L$(SSL_LIB) -Wl,--whole-archive -l$(SSL_TRUSTED_LIB) -Wl,--no-whole-archive \
	-l$(SSL_TRUSTED_TLS_LIB) -l$(SSL_OPENSSL_LIB)

include $(SGX_SDK)/buildenv.mk

SGX_COMMON_FLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_PROTOC := $(SGX_SDK)/bin/x64/sgx_protoc

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## Server Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Server_Cpp_Files := Server/Server.cpp Server/seng/untrusted_seng.cpp

# demo I-Checkit service
Server_Cpp_Files += Server/RevocationSession.cpp

Server_C_Files := Server/ra-tls/ias-ra.c Server/ra-tls/sgxsdk-ra-attester_u.c
Server_Include_Paths := -IInclude -IInclude/ra-tls -IServer -I$(SGX_SDK)/include -IServer/seng

Server_C_Flags := -fPIC -Wno-attributes $(Server_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Server_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Server_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Server_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

# for sgx-ra-tls
Server_C_Flags += -DUSE_OPENSSL

Server_Cpp_Flags := $(Server_C_Flags)
Server_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -L$(SSL_LIB) -l$(SSL_UNTRUSTED_LIB) -lcrypto -lcurl -lsgx_uae_service

Server_Cpp_Objects := $(Server_Cpp_Files:.cpp=.o) $(Server_C_Files:.c=.o)

Server_Name := credservice-sgx




######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := Enclave/ra-tls/openssl-ra-attester.c Enclave/ra-tls/ra_tls_options.c Enclave/ra-tls/sgxsdk-ra-attester_t.c

Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Cpp_Files += Enclave/feido_kdf.cpp Enclave/feido_ctx.cpp
Enclave_Cpp_Files += Enclave/feido_ca_handling.cpp Enclave/feido_fido_handling.cpp

# demo I-Checkit service
Enclave_Cpp_Files += Enclave/eid-revoke/feido_revocation.cpp

Enclave_Include_Paths := -IInclude -IInclude/ra-tls -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(SSL_INC) -I$(SGX_SDK)/include/tprotobuf -I$(EPASS_CA_PATH) -I$(EPASS_CA_PATH)/openpace -I$(CBOR_PATH)/src

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS)
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags += -fstack-protector
else
	Enclave_C_Flags += -fstack-protector-strong
endif

# Seems that gcc transfers simple printf() calls to puts() calls, which causes the "undefined puts" issue! The following flag stops that behaviour.
Enclave_C_Flags += -fno-builtin-printf

# Required to make protobuf not include some standard system headers
Enclave_C_Flags += -DPB_ENABLE_SGX

# for sgx-ra-tls
Enclave_C_Flags += -DUSE_OPENSSL
Enclave_C_Flags += -Wno-undef # ignore MSC_VER

# for tinycbor
Enclave_C_Flags += -DTINYCBOR_FREESTANDING

# demo I-Checkit service
Enclave_C_Flags += -DQUERY_ICHECKIT_SERVICE=${ENABLE_ICHECKIT} \
				   -DICHECKIT_SVC_ADDRESS=${CONF_ICHECKIT_ADDRESS} \
				   -DICHECKIT_SVC_PORT=${CONF_ICHECKIT_PORT}

# ignore some protobuf/ra-tls warnings ... (TODO: might overlook others! better create separate compilation rules + flags for the source files!)
Enclave_C_Flags += -Wno-sign-conversion -Wno-conversion -Wno-cast-qual -Wno-redundant-decls

Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack



# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(MITIGATION_LDFLAGS) $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles $(SgxSSL_Link_Libraries) -L$(SGX_TRUSTED_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_tswitchless -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_protobuf -l$(Crypto_Library_Name) -l$(Service_Library_Name) -lsgx_pthread -L$(EPASS_CA_PATH) -l$(EPASS_CA_LIB) -L$(CBOR_PATH) -l$(CBOR_LIB) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(sort $(Enclave_Cpp_Files:.cpp=.o)) $(sort $(Enclave_C_Files:.c=.o))

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all target run
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target:  $(Server_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(Server_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."


else
target: $(Server_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif

endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(Server_Name)
	@echo "RUN  =>  $(Server_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(Server_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(Server_Cpp_Objects) Server/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)




######## Server Objects ########

Server/ra-tls/ra_tls_u.h:  $(SGX_EDGER8R) Include/ra-tls/ra_tls.edl
	@cd Server/ra-tls && $(SGX_EDGER8R) --untrusted ra-tls/ra_tls.edl --search-path ../../Enclave --search-path $(SGX_SDK)/include --search-path ../../$(SSL_INC) --search-path ../../Include
	@echo "GEN  =>  $@"	

Server/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Server && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include --search-path ../$(SSL_INC) --search-path ../Include
	@echo "GEN  =>  $@"

Server/Enclave_u.c: Server/Enclave_u.h

Server/Enclave_u.o: Server/Enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Server_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Server/ra-tls/%.o: Server/ra-tls/%.c Server/ra-tls/ra_tls_u.h
	@$(CC) $(SGX_COMMON_CFLAGS) $(Server_C_Flags) -Wno-sign-conversion -Wno-conversion -Wno-cast-qual -c $< -o $@
	@echo "CC   <=  $<"

Server/%.o: Server/%.cpp  Server/Enclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Server_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Server_Name): Server/Enclave_u.o $(Server_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Server_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########


Enclave/fido_sgx.pb.h: $(SGX_PROTOC) Enclave/fido_sgx.proto
	@$(SGX_PROTOC) --cpp_out Enclave/ -I Enclave/ Enclave/fido_sgx.proto
	@echo "GEN  =>  $@"

Enclave/fido_sgx.pb.cc: Enclave/fido_sgx.pb.h

Enclave/eid-revoke/feido-database.pb.h: $(SGX_PROTOC) Enclave/eid-revoke/feido-database.proto
	@$(SGX_PROTOC) --cpp_out Enclave/ -I Enclave/ Enclave/eid-revoke/feido-database.proto
	@echo "GEN  =>  $@"

Enclave/eid-revoke/feido-database.pb.cc: Enclave/eid-revoke/feido-database.pb.h

Enclave/ra-tls/ra_tls_t.h: $(SGX_EDGER8R) Include/ra-tls/ra_tls.edl
	@cd Enclave/ra-tls && $(SGX_EDGER8R) --trusted ../../Include/ra-tls/ra_tls.edl --search-path ../../Enclave --search-path $(SGX_SDK)/include --search-path ../../$(SSL_INC) --search-path ../../Include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include --search-path ../$(SSL_INC) --search-path ../Include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/ra-tls/%.o: Enclave/ra-tls/%.c Enclave/ra-tls/ra_tls_t.h
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -Wno-pointer-arith -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.h Enclave/fido_sgx.pb.h Enclave/eid-revoke/feido-database.pb.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Enclave/%.o: Enclave/%.cc Enclave/Enclave_t.h Enclave/fido_sgx.pb.h Enclave/eid-revoke/feido-database.pb.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects) Enclave/fido_sgx.pb.o Enclave/eid-revoke/feido-database.pb.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private_test.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* $(Server_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(Server_Cpp_Objects) Server/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* Enclave/ra-tls/ra_tls_t.h Server/ra-tls/ra_tls_t.h Enclave/fido_sgx.pb.* Enclave/eid-revoke/feido-database.pb.*
