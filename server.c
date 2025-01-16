#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>

#define MAX_RULES 100
#define MAX_REQUESTS 100
#define MAX_QUERY 100


typedef struct
{
    struct in_addr start_ip;
    struct in_addr end_ip;
    int start_port;
    int end_port;
    char queries[MAX_REQUESTS][MAX_QUERY];
    int query_count;
} Firewall;

Firewall rules[MAX_RULES];
int rule_count = 0;
char requests[MAX_REQUESTS][100];
int request_count = 0;

pthread_mutex_t lock;


int is_numeric(const char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i])) {
            return 0;
        }
    }
    return 1; 
}


void strip_leading_zeros(char *ip) {
    char cleaned_ip[20] = {0};
    char *token = strtok(ip, ".");
    int first = 1;

    while (token != NULL) {
        while (*token == '0' && *(token + 1) != '\0') {
            token++;
        }

        if (!first) {
            strcat(cleaned_ip, ".");
        }
        strcat(cleaned_ip, token);
        first = 0;
        token = strtok(NULL, ".");
    }

    strncpy(ip, cleaned_ip, 20);
}


int is_valid_ip(const char *ip) {
    struct sockaddr_in socket;
    if (inet_pton(AF_INET, ip, &(socket.sin_addr)) == 0) {
        return 0;
    }
    char ip_copy[20];
    strncpy(ip_copy, ip, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';

    char *token = strtok(ip_copy, ".");
    int octet_count = 0;
    while (token != NULL) {
        if (!is_numeric(token) || atoi(token) < 0 || atoi(token) > 255) {
            return 0;
        }
        token = strtok(NULL, ".");
        octet_count++;
    }


    return octet_count == 4;
}


int is_valid_port(int port)
{
    return port >= 0 && port <= 65535;
}

int ip_in_range(struct in_addr ip, struct in_addr start, struct in_addr end)
{
    return (ntohl(ip.s_addr) >= ntohl(start.s_addr)) && (ntohl(ip.s_addr) <= ntohl(end.s_addr));
}


int add_rule(const char *rule_str) {
    pthread_mutex_lock(&lock);

    if (rule_count >= MAX_RULES) {
        pthread_mutex_unlock(&lock);
        return 0; 
    }

    char ip_part[50], port_part[50];
    if (sscanf(rule_str, "%s %s", ip_part, port_part) != 2) {
        pthread_mutex_unlock(&lock);
        return -1; 
    }

    strip_leading_zeros(ip_part);

    struct in_addr start_ip, end_ip;
    char *dash_ip = strchr(ip_part, '-');
    if (dash_ip) {
        *dash_ip = '\0';
        strip_leading_zeros(dash_ip + 1);
        if (!is_valid_ip(ip_part) || !is_valid_ip(dash_ip + 1)) {
            pthread_mutex_unlock(&lock);
            return -1; 
        }
        inet_pton(AF_INET, ip_part, &start_ip);
        inet_pton(AF_INET, dash_ip + 1, &end_ip);

        if (ntohl(start_ip.s_addr) > ntohl(end_ip.s_addr)) {
            pthread_mutex_unlock(&lock);
            return -1; 
        }
    } else {
        
        if (!is_valid_ip(ip_part)) {
            pthread_mutex_unlock(&lock);
            return -1; 
        }
        inet_pton(AF_INET, ip_part, &start_ip);
        end_ip = start_ip;
    }
    int start_port, end_port;
    char *dash_port = strchr(port_part, '-');
    if (dash_port) {
        *dash_port = '\0';
        start_port = atoi(port_part);
        end_port = atoi(dash_port + 1);

        if (!is_valid_port(start_port) || !is_valid_port(end_port) || start_port > end_port) {
            pthread_mutex_unlock(&lock);
            return -1; 
        }
    } else {
        start_port = atoi(port_part);
        end_port = start_port;
        if (!is_valid_port(start_port)) {
            pthread_mutex_unlock(&lock);
            return -1; 
        }
    }

   
    rules[rule_count].start_ip = start_ip;
    rules[rule_count].end_ip = end_ip;
    rules[rule_count].start_port = start_port;
    rules[rule_count].end_port = end_port;
    rules[rule_count].query_count = 0;
    rule_count++;
    pthread_mutex_unlock(&lock);
    return 1; 



}

int check_connection(const char *ip, int port, char *response) {
    pthread_mutex_lock(&lock);
    char ip_copy[20];
    strncpy(ip_copy, ip, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';
    strip_leading_zeros(ip_copy);

    if (!is_valid_ip(ip_copy) || !is_valid_port(port)) {
        pthread_mutex_unlock(&lock);
        strcpy(response, "Illegal IP address or port specified");
        return 0;
    }

    struct in_addr ip_addr;
    inet_pton(AF_INET, ip_copy, &ip_addr);
    for (int i = 0; i < rule_count; i++) {
        if (ip_in_range(ip_addr, rules[i].start_ip, rules[i].end_ip) &&
            (port >= rules[i].start_port && port <= rules[i].end_port)) {
            if (rules[i].query_count < MAX_REQUESTS) {
                snprintf(rules[i].queries[rules[i].query_count], MAX_QUERY, "%s %d", ip_copy, port);
                rules[i].query_count++;
            }

            pthread_mutex_unlock(&lock);
            strcpy(response, "Connection accepted");
            return 1;


        }



    }

    pthread_mutex_unlock(&lock);
    strcpy(response, "Connection rejected");
    return 0;


}


int delete_rule(const char *rule_str) {
    pthread_mutex_lock(&lock);

    char input_ip_part[50], input_port_part[50];
    if (sscanf(rule_str, "%s %s", input_ip_part, input_port_part) != 2) {
        pthread_mutex_unlock(&lock);
        return -1; 
    }

    struct in_addr input_start_ip, input_end_ip;
    int input_start_port, input_end_port;
    char *dash_ip = strchr(input_ip_part, '-');

    if (dash_ip) {
        *dash_ip = '\0';
        if (inet_pton(AF_INET, input_ip_part, &input_start_ip) == 0 || inet_pton(AF_INET, dash_ip + 1, &input_end_ip) == 0) {
            pthread_mutex_unlock(&lock);
            return -1; 
        }
    } else {
        if (inet_pton(AF_INET, input_ip_part, &input_start_ip) == 0) {
            pthread_mutex_unlock(&lock);
            return -1; 
        }
        input_end_ip = input_start_ip;
    }

    char *dash_port = strchr(input_port_part, '-');
    if (dash_port) {
        *dash_port = '\0';
        input_start_port = atoi(input_port_part);
        input_end_port = atoi(dash_port + 1);
    } else {
        input_start_port = atoi(input_port_part);
        input_end_port = input_start_port;
    }
    if (!is_valid_port(input_start_port) || !is_valid_port(input_end_port)) {
        pthread_mutex_unlock(&lock);
        return -1; 
    }
    for (int i = 0; i < rule_count; i++) {
        if (ntohl(input_start_ip.s_addr) == ntohl(rules[i].start_ip.s_addr) &&
            ntohl(input_end_ip.s_addr) == ntohl(rules[i].end_ip.s_addr) &&
            input_start_port == rules[i].start_port &&
            input_end_port == rules[i].end_port) {
            for (int j = i; j < rule_count - 1; j++) {
                rules[j] = rules[j + 1];
            }
            rule_count--;
            pthread_mutex_unlock(&lock);
            return 1; 
        }
    }
    pthread_mutex_unlock(&lock);
    return 0; 
}

void list_requests(char *response) {
    pthread_mutex_lock(&lock);
    response[0] = '\0'; 
    if (request_count == 0) {
        strcpy(response, "No commands have been entered yet.");
    } else {
        for (int i = 0; i < request_count; i++) {
            if (i > 0) {
                strcat(response, "\n");
            }
            strcat(response, requests[i]);
        }
    }
    pthread_mutex_unlock(&lock);


}

void list_rules(char *response) {
    pthread_mutex_lock(&lock);
    response[0] = '\0'; 

    if (rule_count == 0) {
        strcpy(response, "No rules stored");
    } else {
        for (int i = 0; i < rule_count; i++) {
            char start_ip[INET_ADDRSTRLEN], end_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &rules[i].start_ip, start_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &rules[i].end_ip, end_ip, INET_ADDRSTRLEN);
            if (strcmp(start_ip, end_ip) == 0) {
                if (rules[i].start_port == rules[i].end_port) {
                    snprintf(response + strlen(response), 1024, "Rule: %s %d\n", start_ip, rules[i].start_port);
                } else {
                    snprintf(response + strlen(response), 1024, "Rule: %s %d-%d\n", start_ip, rules[i].start_port, rules[i].end_port);
                }
            } else {
                if (rules[i].start_port == rules[i].end_port) {
                    snprintf(response + strlen(response), 1024, "Rule: %s-%s %d\n", start_ip, end_ip, rules[i].start_port);
                } else {
                    snprintf(response + strlen(response), 1024, "Rule: %s-%s %d-%d\n", start_ip, end_ip, rules[i].start_port, rules[i].end_port);
                }
            }
            for (int j = 0; j < rules[i].query_count; j++) {
                snprintf(response + strlen(response), 1024, "Query: %s\n", rules[i].queries[j]);
            }
        }
    }
    pthread_mutex_unlock(&lock);


}


void process_command(const char *command, char *response) {
    char cmd[10], rule[100], ip[20], port_str[20];
    int port;

    if (sscanf(command, "%s", cmd) != 1) {
        strcpy(response, "Illegal request");
        return;
    }

    if (strcmp(cmd, "R") != 0 && strcmp(cmd, "A") != 0 &&
        strcmp(cmd, "C") != 0 && strcmp(cmd, "D") != 0 &&
        strcmp(cmd, "L") != 0 && strcmp(cmd, "E") != 0) 
    {
        strcpy(response, "Illegal request");
        return;
    }

    pthread_mutex_lock(&lock);
    if (request_count < MAX_REQUESTS) {
        strcpy(requests[request_count], command);
        request_count++;
    }
    pthread_mutex_unlock(&lock);

   
    if (strcmp(cmd, "R") == 0) {
        list_requests(response);
    } else if (strcmp(cmd, "A") == 0) {
        sscanf(command, "A %[^\n]", rule);
        if (add_rule(rule) == 1) {
            strcpy(response, "Rule added");
        } else {
            strcpy(response, "Invalid rule");
        }
    } else if (strcmp(cmd, "C") == 0) {
        if (sscanf(command, "C %s %s", ip, port_str) != 2) {
            strcpy(response, "Illegal IP address or port specified");
            return;
        }
        if (!is_numeric(port_str)) {
            strcpy(response, "Illegal IP address or port specified");
            return;
        }
        port = atoi(port_str);
        check_connection(ip, port, response);
    } else if (strcmp(cmd, "D") == 0) {
        sscanf(command, "D %[^\n]", rule);
        if (delete_rule(rule) == 1) {
            strcpy(response, "Rule deleted");
        } else {
            strcpy(response, "Rule not found");
        }
    } else if (strcmp(cmd, "L") == 0) {
        list_rules(response);
    } else if (strcmp(cmd, "E") == 0) {
        strcpy(response, "Server will shut down.");
        exit(-1);
        return;
    }
}



void *handle_client(void *client) {
    int sock = *((int *)client);
    free(client);
    char buffer[1024];
    char response[1024];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(response, 0, sizeof(response));
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            close(sock);
            break;
        }
        buffer[bytes] = '\0';
        process_command(buffer, response);
        if (send(sock, response, strlen(response), 0) < 0) {
            perror("Send failed");
            break;
        }
    }
    close(sock);
    return NULL;
}


int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    pthread_mutex_init(&lock, NULL);
    if (argc == 2) {
        if (strcmp(argv[1], "-i") == 0) {
            char command[1024];
            char response[1024];
            while (1) {
                memset(command, 0, sizeof(command));
                memset(response, 0, sizeof(response));
                if (fgets(command, sizeof(command), stdin) == NULL) {
                    break;
                }
                command[strcspn(command, "\n")] = 0; 
                process_command(command, response);
                printf("%s\n", response);
            }
        } else {
            int port = atoi(argv[1]);
            if (port < 1024 || port > 65535) {
                fprintf(stderr, "Invalid port number.\n");
                exit(EXIT_FAILURE);
            }
            int server_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (server_fd < 0) {
                perror("Socket creation failed");
                exit(EXIT_FAILURE);
            }
            struct sockaddr_in server_addr;
            server_addr.sin_family = AF_INET;
            server_addr.sin_addr.s_addr = INADDR_ANY;
            server_addr.sin_port = htons(port);
            if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("Binding failed");
                close(server_fd);
                exit(EXIT_FAILURE);
            }
            if (listen(server_fd, 3) < 0) {
                perror("Listening failed");
                close(server_fd);
                exit(EXIT_FAILURE);
            }
            printf("Server listening on port %d\n", port);
            while (1) {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
                if (client_sock < 0) {
                    perror("Accept failed");
                    continue;
                }
                int *new_sock = malloc(sizeof(int));
                *new_sock = client_sock;
                pthread_t client_thread;
                if (pthread_create(&client_thread, NULL, handle_client, (void *)new_sock) != 0) {
                    perror("Threading failed");
                    free(new_sock);
                    close(client_sock);
                    continue;
                }
                pthread_detach(client_thread);

            }
            close(server_fd);
        }
    } else {
        printf("Usage: %s -i (for interactive mode) or %s <port> (for socket mode)\n", argv[0], argv[0]);
    }

    pthread_mutex_destroy(&lock);
    return 0;
}


