#include <unistd.h> // close
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C" {
    #include "Enclave_u.h"
}


// based on SENG-SDK
int ocall_setup_db_conn(short port, const char *dst_ip) {
    int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket < 0) return tcp_socket;

    struct sockaddr_in target {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {0}
    };

    if (inet_aton(dst_ip, &target.sin_addr) < 0) {
        close(tcp_socket);
        return -1;
    }

   if (connect(tcp_socket, (struct sockaddr *)&target, sizeof(target)) < 0) {
        close(tcp_socket);
        return -1;
    }

    return tcp_socket;   
}


void ocall_close_db_conn(int sock_fd) {
    close(sock_fd);
}