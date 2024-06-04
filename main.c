/* Created and modified by WuZhuofan.
 * All rights reserved.*/
#define _XOPEN_SOURCE
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
uint64_t htobe64(uint64_t host_64bits);
uint64_t be64toh(uint64_t big_endian_64bits);

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
        char *pdu = (char *)malloc(PDU_SIZE);
        if (!pdu) {
            perror("Error in malloc");
            exit(1);
        }
        ssize_t bytes_read = read(connect_socket, pdu, PDU_SIZE);
        if (bytes_read == 0) {
            free(pdu);
            break;
        } else if (bytes_read < 0) {
            perror("Error in read");
            free(pdu);
            break;
        }

        char *pdu_ptr = pdu; // 保留原始指针以便释放内存
//        uint32_t operator = ntohl(*(int32_t *)pdu_ptr);
//        pdu_ptr += sizeof(int32_t);
//        int64_t operator_1 = be64toh(*(int64_t *)pdu_ptr);
//        pdu_ptr += sizeof(int64_t);
//        int64_t operator_2 = be64toh(*(int64_t *)pdu_ptr);

        uint32_t operator;
        memcpy(&operator, pdu_ptr, sizeof(operator));
        operator = ntohl(operator);
        pdu_ptr += sizeof(uint32_t);

        int64_t operator_1;
        memcpy(&operator_1, pdu_ptr, sizeof(operator_1));
        operator_1 = be64toh(operator_1);
        pdu_ptr += sizeof(int64_t);

        int64_t operator_2;
        memcpy(&operator_2, pdu_ptr, sizeof(operator_2));
        operator_2 = be64toh(operator_2);


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
                    free(pdu);
                    continue;
                }
                result = operator_1 / operator_2;
                printf("[rqt_res] %ld / %ld = %ld\n", operator_1, operator_2, result);
                break;
            case 0x00000010:
                if (operator_2 == 0) {
                    fprintf(stderr, "Error: Division by zero\n");
                    free(pdu);
                    continue;
                }
                result = operator_1 % operator_2;
                printf("[rqt_res] %ld %% %ld = %ld\n", operator_1, operator_2, result);
                break;
            default:
                fprintf(stderr, "Unknown operator: %u\n", operator);
                free(pdu);
                continue;
        }

        free(pdu);

        int64_t network_result = htobe64(result);
        ssize_t bytes_written = write(connect_socket, &network_result, sizeof(network_result));
        if (bytes_written < 0) {
            perror("Error in write");
            exit(1);
        }
    }
}

uint64_t htobe64(uint64_t host_64bits) {
    uint64_t result = 0;
    unsigned char *ptr = (unsigned char *)&result;
    ptr[0] = (host_64bits >> 56) & 0xFF;
    ptr[1] = (host_64bits >> 48) & 0xFF;
    ptr[2] = (host_64bits >> 40) & 0xFF;
    ptr[3] = (host_64bits >> 32) & 0xFF;
    ptr[4] = (host_64bits >> 24) & 0xFF;
    ptr[5] = (host_64bits >> 16) & 0xFF;
    ptr[6] = (host_64bits >> 8) & 0xFF;
    ptr[7] = host_64bits & 0xFF;
    return result;
}

uint64_t be64toh(uint64_t big_endian_64bits) {
    uint64_t result = 0;
    unsigned char *ptr = (unsigned char *)&big_endian_64bits;
    result = ((uint64_t)ptr[0] << 56) |
             ((uint64_t)ptr[1] << 48) |
             ((uint64_t)ptr[2] << 40) |
             ((uint64_t)ptr[3] << 32) |
             ((uint64_t)ptr[4] << 24) |
             ((uint64_t)ptr[5] << 16) |
             ((uint64_t)ptr[6] << 8) |
             (uint64_t)ptr[7];
    return result;
}