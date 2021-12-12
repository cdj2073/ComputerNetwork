#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024
#define SERVER_TCP_PORT 45000
#define IPV4_TCP_PORT 50000

int main() {
    int n;
    int sockfd, new_sd, client_len;
    struct sockaddr_in6 server, client;

    int ipv4_sd;
    struct sockaddr_in ipv4_client;
    char buf[BUFFER_SIZE];

    // Create socket
    if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) { 
        fprintf(stderr, "Fail to create a socket\n");
        exit(1);
    }

    // Bind an address to socket
    memset(&server, 0x00, sizeof(struct sockaddr_in));
    server.sin6_family = AF_INET6;
    server.sin6_port = htons(SERVER_TCP_PORT);
    server.sin6_addr = in6addr_any;     // in6addr_any == htonl(INADDR_ANY)
    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
        fprintf(stderr, "Bind Error\n");
        exit(1);
    }

    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "Listen Error\n");
    }

    for (int i = 0; i < 5; i++) {
        client_len = sizeof(client);
        printf("clientlen : %d\n", client_len);
        if ((new_sd = accept(sockfd, (struct sockaddr *)&client, (socklen_t *)&client_len)) == -1) {
            fprintf(stderr, "Accept Error\n");
            exit(1);
        }
        printf("Accept Client\n");
        bzero(buf, BUFFER_SIZE);
        while ((n = read(new_sd, buf, BUFFER_SIZE)) > 0) {
            buf[strlen(buf) - 2] = '\0';
            printf("new_sd : %d => %s..\n", new_sd, buf);
            
        }
        close(new_sd);
    }

    // IPv4 client
    /*
    // Create socket
    if ((ipv4_sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) { 
        fprintf(stderr, "Fail to create a socket\n");
        exit(1);
    }

    // Bind an address to socket
    memset(&server, 0x00, sizeof(struct sockaddr_in));
    server.sin6_family = AF_INET6;
    server.sin6_port = htons(SERVER_TCP_PORT);
    server.sin6_addr = in6addr_any;     // in6addr_any == htonl(INADDR_ANY)
    
	//printf("ipv6 : %s\n", (char *)server.sin6_addr);
    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
        fprintf(stderr, "Bind Error\n");
        exit(1);
    }

    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "Listen Error\n");
    }
*/
    if ((ipv4_sd = accept(sockfd, (struct sockaddr *)&client, (socklen_t *)&client_len)) == -1) {
        fprintf(stderr, "Accept Error\n");
        exit(1);
    }
    printf("Accept IPv4 Client\n");
    bzero(buf, BUFFER_SIZE);
    while ((n = read(ipv4_sd, buf, BUFFER_SIZE)) > 0) {
        buf[strlen(buf) - 2] = '\0';
        printf("ipv4_sd : %d => %s..\n", ipv4_sd, buf);
    }
    close(ipv4_sd);
    printf("Close client\n");
    close(sockfd);

    return (0);
}