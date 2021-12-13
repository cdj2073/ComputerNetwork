#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024
#define SERVER_TCP_PORT 50000

void ipv6_conn(char *server_ipv6, int port);

int main() {
    int sockfd, n, port_v6;
    char *server_ip, *server_ipv6;
    struct sockaddr_in server_addr;
    char buf[BUFFER_SIZE], tokens[BUFFER_SIZE];
 
    server_ip = "3.17.53.130";
    memset(&server_addr, 0x00, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_TCP_PORT);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // create client socket (IPv4, TCP)
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "Fail to create a socket\n");
        exit(1);
    }

    // connect
    if ((connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr))) == -1) {
        fprintf(stderr, "Connection Error\n");
        exit(1);
    }

    // read / write
    printf("Connected\n");

    bzero(buf, BUFFER_SIZE);
    while ((n = read(sockfd, buf, BUFFER_SIZE)) > 0) {
        printf("%s", buf);
        bzero(buf, BUFFER_SIZE);
        if ((n = read(sockfd, buf, BUFFER_SIZE)) > 0) {
            printf("%s", buf);
            bzero(buf, BUFFER_SIZE);
        }
        read(0, buf, BUFFER_SIZE);
        write(sockfd, buf, strlen(buf));
        if (strcmp(buf, "OK\n") == 0) {
            sleep(10);
            
            typedef struct message {
                long msg_type;
                char data[BUFFER_SIZE];
            } message;
            
            int msqid;
            message msg;

            if ((msqid = msgget(1234, IPC_CREAT|0666)) == -1) {
                fprintf(stderr, "Error msgget\n");
                exit(1);
            }
            if (msgrcv(msqid, &msg, sizeof(msg), 0, 0) == -1) {
                fprintf(stderr, "Error msgrcv\n");
                exit(1);
            }
            strcpy(tokens, msg.data);
            tokens[strlen(tokens)] = 0x0a;
            //printf("token : %s\n", tokens);
            write(sockfd, tokens, strlen(tokens));
            
            if (msgctl(msqid, IPC_RMID, NULL) == -1) {
                fprintf(stderr, "Error msgctl\n");
                exit(1);
            }
            else {
                //printf("success to get token!\n");
                break;
            }
        }
        
        bzero(buf, BUFFER_SIZE);
    }
    
    if ((n = read(sockfd, buf, BUFFER_SIZE)) > 0) {
        printf("%s", buf);
        bzero(buf, BUFFER_SIZE);
    }
    if ((n = read(sockfd, buf, BUFFER_SIZE)) > 0) {
        printf("%s", buf);
        bzero(buf, BUFFER_SIZE);
    }
    // close
    close(sockfd);
    return (0);
}