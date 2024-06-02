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

int signal_flag=0;
void handle_sigint();
void server();

int main(int argc, char *argv[]) {
    struct sigaction sa;
    sa.sa_flags=0;
    sa.sa_handler=handle_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL);

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

    while(!signal_flag){
        struct sockaddr_in client_addr;
        socklen_t client_addrlen = sizeof(client_addr);
        int connect_socket = accept(listen_tcp_socket, (struct sockaddr *)&client_addr, &client_addrlen);
    }


    return 0;
}

void handle_sigint(){
    printf("[srv] SIGINT is coming!");
    signal_flag=1;
}

void server(){

}