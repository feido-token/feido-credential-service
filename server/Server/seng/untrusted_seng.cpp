#include <unistd.h> // close
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>

#include <stdio.h> // printf

#include <sys/epoll.h>
#include <cerrno>

#include "Enclave_u.h"

//#define DEBUG_USENG

long u_direct_write(int fd, const void *buf, size_t count) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG write (%d, .., %ld)\n", fd, count);
    auto ret = write (fd, buf, count);
    auto tmp = errno;
    printf("write >> %ld\n", ret);
    errno = tmp;
    return ret;
#else
    return write (fd, buf, count);
#endif
}

long u_direct_read(int fd, void *buf, size_t count) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG read (%d, .., %ld)\n", fd, count);
#endif
    return u_direct_recv(fd, buf, count, 0);
}

int u_direct_setsockopt(int sockfd, int level, int optname, 
                        const void *optval, unsigned int optlen) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG setsockopt(%d, %d, %d)\n", sockfd, level, optname);
#endif
    return setsockopt(sockfd, level, optname, optval, optlen);
}

int u_hacky_direct_getsockopt(int sockfd, int level, int optname, void *optval, unsigned int optlen, unsigned int *res_optlen) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG getsockopt(%d, %d, %d, input optlen: %d | %d)\n", sockfd, level, optname, optlen, (res_optlen == nullptr ? -1 : *res_optlen));
#else
    (void) optlen;
#endif
    return getsockopt(sockfd, level, optname, optval, res_optlen);
}

int u_hacky_direct_getsockname(int sockfd, void *addr, unsigned int addrlen, unsigned int *res_addrlen) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG getsockname(%d, input addrlen: %d | %d)\n", sockfd, addrlen, (res_addrlen == nullptr ? -1 : *res_addrlen));
#else
    (void) addrlen;
#endif
    return getsockname(sockfd, (struct sockaddr *)addr, res_addrlen);
}

long u_direct_recv(int fd, void *buf, size_t count, int flags) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG recv (%d, .., %ld, %d)\n", fd, count, flags);
    long ret = -1;
    int tmp = EINTR;
    /*while (ret < 0 && tmp == EINTR) {
        ret = recv (fd, buf, count, flags);
        tmp = errno;
    }*/
    ret = recv (fd, buf, count, flags);
    tmp = errno;
    printf("recv << %ld (%d)\n", ret, tmp);
    errno = tmp;
    return ret;
#else
    return recv (fd, buf, count, flags);
#endif
}
