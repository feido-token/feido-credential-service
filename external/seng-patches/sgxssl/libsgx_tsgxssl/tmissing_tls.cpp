#include <string.h>

#include "sgx_tsgxssl_t.h"
#include "tcommon.h"


extern "C" {

/* Add missing ones popping up because of SSL/TLS */
int sgxssl_shutdown(int sockfd, int how)
{
    FSTART;

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return -1;
}
}
