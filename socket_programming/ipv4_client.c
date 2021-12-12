#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <netdb.h>  // gethostbyname()

#define BUFFER_SIZE 1024
#define SERVER_TCP_PORT 50000
#define IPV6_TCP_PORT 45000

// ipv6 주소 --------------------------------------------나중에 지우기
// inet6 2001:0:c38c:c38c:84a:36d5:f1d9:337b

int main() {
    int sockfd, n;
    char *server_ip;//, *bp, sbuf[BUFFER_SIZE], rbuf[BUFFER_SIZE];
    struct sockaddr_in server_addr;
    //struct sockaddr_in6 ipv6_server;
    // char *dns = "ec2-3-17-53-130.us-east-2.compute.amazonaws.com";
    
    server_ip = "3.17.53.130";
    memset(&server_addr, 0x00, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_TCP_PORT);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // create client socket (IPv4, TCP)
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
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

    char buf[BUFFER_SIZE];
    bzero(buf, BUFFER_SIZE);

    while ((n = read(sockfd, buf, BUFFER_SIZE)) > 0) {
        printf("%s", buf);
        bzero(buf, BUFFER_SIZE);

        fgets(buf, BUFFER_SIZE, stdin);
        write(sockfd, buf, strlen(buf));
        bzero(buf, BUFFER_SIZE);
    }
    
    /*
    fgets(buf, BUFFER_SIZE, stdin);
    //gets(buf);
    write(sockfd, buf, strlen(buf));
    bzero(buf, BUFFER_SIZE);

    while ((n = read(sockfd, buf, BUFFER_SIZE - 1)) > 0) {
        printf("%s", buf);
        bzero(buf, BUFFER_SIZE);
    }
    */

    // close
    close(sockfd);
    return (0);
}