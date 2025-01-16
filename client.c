#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>    
#include <sys/time.h>      
#include <sys/types.h>     

#define BUFFER_SIZE 1024
#define TIMEOUT_SEC 5

void print_usage() {
    printf("Usage: ./client <server_ip> <port> <command> [<ip_address> <port>]\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4 && argc != 6) {
        print_usage();
        return 1;
    }


    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    const char *command = argv[3];
    if (strcmp(server_ip, "localhost") == 0) {
        server_ip = "127.0.0.1";
    }



    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Failed to create socket");
        return 1;
    }




    int flags = fcntl(client_socket, F_GETFL, 0);
    fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(client_socket);
        return 1;
    }


    int result = connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (result < 0 && errno != EINPROGRESS) {
        perror("Connection failed");
        close(client_socket);
        return 1;
    }


    if (result < 0) {
        fd_set writefd;
        struct timeval timeout;
        FD_ZERO(&writefd);
        FD_SET(client_socket, &writefd);
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = 0;




        result = select(client_socket + 1, NULL, &writefd, NULL, &timeout);
        if (result <= 0) {
            perror("Connection timed out");
            close(client_socket);
            return 1;
        }

        int optval;
        socklen_t optlen = sizeof(optval);
        if (getsockopt(client_socket, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0 || optval != 0) {
            fprintf(stderr, "Connection failed: %s\n", strerror(optval));
            close(client_socket);
            return 1;
        }


    }
    fcntl(client_socket, F_SETFL, flags);
    char message[BUFFER_SIZE];
    if (argc == 6) {
        snprintf(message, sizeof(message), "%s %s %s", command, argv[4], argv[5]);
    } else {
        snprintf(message, sizeof(message), "%s", command);
    }

    if (send(client_socket, message, strlen(message), 0) < 0) {
        perror("Failed to send command");
        close(client_socket);
        return 1;
    }
    char response[BUFFER_SIZE];
    ssize_t bytes_received = recv(client_socket, response, sizeof(response) - 1, 0);
    if (bytes_received < 0) {
        perror("Failed to receive response");
        close(client_socket);
        return 1;
    }

    response[bytes_received] = '\0';
    printf("%s\n", response);
    close(client_socket);
    return 0;
}
