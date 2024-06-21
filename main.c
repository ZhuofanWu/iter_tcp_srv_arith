/* Created and modified by WuZhuofan.
 * All rights reserved.*/
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#define PDU_SIZE segment_size

const size_t segment_size = 20;
int signal_flag = 0;
void handle_sigint();
void server(int connect_socket);
int64_t hton64(int64_t host64);
int64_t ntoh64(int64_t net64);
int32_t hton32(int32_t host32);
int32_t ntoh32(int32_t net32);

int main(int argc, char *argv[]) {
    struct sigaction sa;
    sa.sa_flags = 0;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    char *ipAddress = argv[1];
    int port = atoi(argv[2]);
    int listen_tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_tcp_socket < 0) {
        perror("Error in socket");
        exit(1);
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port); // 设置监听的端口号
    if (inet_pton(AF_INET, ipAddress, &(server_addr.sin_addr)) <= 0) {
        perror("Error in inet_pton()");
        exit(1);
    }
    if (bind(listen_tcp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error in bind()");
        exit(1);
    }
    if (listen(listen_tcp_socket, 5) < 0) { // 允许最多5个连接请求
        perror("Error in listen()");
        exit(1);
    }
    printf("[srv] server[%s:%d] is initializing!\n", ipAddress, port);
    while (!signal_flag) {
        struct sockaddr_in client_addr;
        socklen_t client_addrlen = sizeof(client_addr);
        int connect_socket = accept(listen_tcp_socket, (struct sockaddr *)&client_addr, &client_addrlen);
        if (connect_socket < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                perror("Error in accept");
                exit(1);
            }
        }
        if (connect_socket > 0) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
            int client_port = ntohs(client_addr.sin_port);
            printf("[srv] client [%s:%d] is accepted!\n", client_ip, client_port);
            server(connect_socket);
            printf("[srv] client [%s:%d] is closed!\n", client_ip, client_port);
            close(connect_socket);
        }
    }
    close(listen_tcp_socket);
    printf("[srv] listenfd is closed!\n");
    printf("[srv] server is going to exit!\n");
    return 0;
}

void handle_sigint() {
    printf("[srv] SIGINT is coming!\n");
    signal_flag = 1;
}

void server(int connect_socket) {
    while (1) {
        unsigned char pdu[PDU_SIZE]={};
        ssize_t bytes_read = read(connect_socket, pdu, PDU_SIZE);
        if (bytes_read <= 0) {
            perror("Error in read");
            break;
        }

        int32_t operator; int64_t operator_1; int64_t operator_2;
        memcpy(&operator,pdu,sizeof(int32_t));
        memcpy(&operator_1,pdu+ sizeof(int32_t),sizeof(int64_t));
        memcpy(&operator_2,pdu+ sizeof(int32_t) + sizeof(int64_t),sizeof(int64_t));
        operator= ntoh32(operator);
        operator_1= ntoh64(operator_1);
        operator_2= ntoh64(operator_2);

        int64_t result;
        switch (operator) {
            case 0x00000001:
                result = operator_1 + operator_2;
                printf("[rqt_res] %ld + %ld = %ld\n", operator_1, operator_2, result);
                break;
            case 0x00000002:
                result = operator_1 - operator_2;
                printf("[rqt_res] %ld - %ld = %ld\n", operator_1, operator_2, result);
                break;
            case 0x00000004:
                result = operator_1 * operator_2;
                printf("[rqt_res] %ld * %ld = %ld\n", operator_1, operator_2, result);
                break;
            case 0x00000008:
                if (operator_2 == 0) {
                    fprintf(stderr, "Error: Division by zero\n");
                    continue;
                }
                result = operator_1 / operator_2;
                printf("[rqt_res] %ld / %ld = %ld\n", operator_1, operator_2, result);
                break;
            case 0x00000010:
                if (operator_2 == 0) {
                    fprintf(stderr, "Error: Division by zero\n");
                    continue;
                }
                result = operator_1 % operator_2;
                printf("[rqt_res] %ld %% %ld = %ld\n", operator_1, operator_2, result);
                break;
            default:
                fprintf(stderr, "Unknown operator: %u\n", operator);
                continue;
        }

        int64_t network_result = hton64(result);
        ssize_t bytes_written = write(connect_socket, &network_result, sizeof(network_result));
        if (bytes_written < 0) {
            perror("Error in write");
            exit(1);
        }
    }
}

int64_t hton64(int64_t host64) {
    union {
        int64_t i64;
        unsigned char bytes[8];
    } value;

    value.i64 = host64;

    unsigned char temp = value.bytes[0];
    value.bytes[0] = value.bytes[7];
    value.bytes[7] = temp;

    temp = value.bytes[1];
    value.bytes[1] = value.bytes[6];
    value.bytes[6] = temp;

    temp = value.bytes[2];
    value.bytes[2] = value.bytes[5];
    value.bytes[5] = temp;

    temp = value.bytes[3];
    value.bytes[3] = value.bytes[4];
    value.bytes[4] = temp;

    return value.i64;
}

int64_t ntoh64(int64_t net64) {
    return hton64(net64);
}

int32_t hton32(int32_t host32) {
    union {
        int32_t i32;
        unsigned char bytes[4];
    } value;
    value.i32=host32;
    unsigned char temp = value.bytes[0];
    value.bytes[0] = value.bytes[3];
    value.bytes[3] = temp;

    temp = value.bytes[1];
    value.bytes[1] = value.bytes[2];
    value.bytes[2] = temp;

    return value.i32;
}

int32_t ntoh32(int32_t net32) {
    return hton32(net32);
}