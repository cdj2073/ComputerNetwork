#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/msg.h>
#include <sys/ipc.h>

#define BUFFER_SIZE 1024
#define SERVER_TCP_PORT 45000

int main() {
    int n, idx;
    int sockfd, new_sd, client_len;
    struct sockaddr_in6 server, client;
    char buf[BUFFER_SIZE], *random[5];

    // Create socket
    if ((sockfd = socket(PF_INET6, SOCK_STREAM, 0)) == -1) { 
        fprintf(stderr, "Fail to create a socket\n");
        exit(1);
    }

    // Bind an address to socket
    memset(&server, 0x00, sizeof(struct sockaddr_in));
    server.sin6_family = AF_INET6;
    server.sin6_flowinfo = 0;
    server.sin6_port = htons(SERVER_TCP_PORT);
    server.sin6_addr = in6addr_any;
    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
        fprintf(stderr, "Bind Error\n");
        exit(1);
    }

    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "Listen Error\n");
    }
    printf("Listening..\n");

    idx = 0;
    for (int i = 0; i < 5; i++) {
        client_len = sizeof(client);
        //printf("clientlen : %d\n", client_len);
        if ((new_sd = accept(sockfd, (struct sockaddr *)&client, (socklen_t *)&client_len)) == -1) {
            fprintf(stderr, "Accept Error\n");
            exit(1);
        }
        printf("Accept Client\n");
        bzero(buf, BUFFER_SIZE);
        if ((n = read(new_sd, buf, BUFFER_SIZE)) > 0) {
            buf[strlen(buf) - 2] = '\0';
            printf("Receive : %s\n", buf);
            random[idx++] = strdup(buf);
        }
        close(new_sd);
        printf("close\n");
    }

    // send token to IPv4 client - message queue
    typedef struct message {
        long msg_type;
        char data[BUFFER_SIZE];
    } message;
    int msqid;

    message msg;
    msg.msg_type = 1;
    idx = 0;
    for (int i = 0; i < 5; i++) {
        if (i != 0)
            msg.data[idx++] = ',';
        for (int j = 0; random[i][j]; j++) {
            msg.data[idx++] = random[i][j];
        }
    }
    msg.data[idx] = '\0';

    if ((msqid = msgget(1234, IPC_CREAT|0666)) == -1) {
        fprintf(stderr, "Error msgget\n");
        exit(1);
    }
    if (msgsnd(msqid, &msg, sizeof(msg), 0) == -1) {
        fprintf(stderr, "Error msgsnd\n");
        exit(1);
    }
    printf("message sent : %s..\n", msg.data);
  
    close(sockfd);
    return (0);
}