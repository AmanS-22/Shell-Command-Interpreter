#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <direct.h>
#include <sys/stat.h>

#pragma comment(lib, "ws2_32.lib")

#define CLEAR "cls"
#define MAX_COMMAND_LENGTH 1024
#define MAX_ARGS 64
#define MAX_VARIABLES 64
#define MAX_CONNECTIONS 5
#define NET_BUFFER_SIZE 4096
#define FILE_BUFFER_SIZE 8192
#define PROMPT "remote> "
#define FILE_TRANSFER_HEADER_SIZE 12

// Changed from macro to const variable for timeout
const DWORD FILE_TRANSFER_TIMEOUT = 30000; // 30 seconds

typedef struct {
    char *name;
    char *value;
} Variable;

typedef struct {
    SOCKET socket;
    struct sockaddr_in address;
} ClientInfo;

typedef struct {
    char magic[4];       // "FTRF"
    long file_size;      // File size in bytes
    char filename[256];  // Original filename
} FileHeader;

Variable variables[MAX_VARIABLES];
int num_variables = 0;
WSADATA wsaData;
volatile int server_running = 0;
SOCKET server_socket = INVALID_SOCKET;

/* Signal handler for Ctrl+C */
void handle_signal(int sig) {
    if (sig == SIGINT) {
        if (server_running) {
            printf("\nStopping server...\n");
            closesocket(server_socket);
            server_running = 0;
        } else {
            printf("\n");
        }
    }
}

/* Variable management functions */
int set_variable(const char *name, const char *value) {
    for (int i = 0; i < num_variables; i++) {
        if (strcmp(variables[i].name, name) == 0) {
            free(variables[i].value);
            variables[i].value = _strdup(value);
            return 0;
        }
    }

    if (num_variables < MAX_VARIABLES) {
        variables[num_variables].name = _strdup(name);
        variables[num_variables].value = _strdup(value);
        num_variables++;
        return 0;
    }
    return 1;
}

char *get_variable(const char *name) {
    for (int i = 0; i < num_variables; i++) {
        if (strcmp(variables[i].name, name) == 0) {
            return variables[i].value;
        }
    }
    return NULL;
}

/* Network helper functions */
SOCKET create_server_socket(int port) {
    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == INVALID_SOCKET) {
        perror("socket");
        return INVALID_SOCKET;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) == SOCKET_ERROR) {
        perror("setsockopt");
        closesocket(sockfd);
        return INVALID_SOCKET;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        perror("bind");
        closesocket(sockfd);
        return INVALID_SOCKET;
    }

    if (listen(sockfd, MAX_CONNECTIONS) == SOCKET_ERROR) {
        perror("listen");
        closesocket(sockfd);
        return INVALID_SOCKET;
    }

    return sockfd;
}

SOCKET connect_to_server(const char *host, int port) {
    SOCKET sockfd = INVALID_SOCKET;
    struct addrinfo hints, *result = NULL, *ptr = NULL;
    char port_str[16];
    
    sprintf(port_str, "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", ret);
        return INVALID_SOCKET;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd == INVALID_SOCKET) {
            perror("socket");
            continue;
        }

        if (connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
            closesocket(sockfd);
            sockfd = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (sockfd == INVALID_SOCKET) {
        perror("connect");
    }

    return sockfd;
}

/* File transfer functions */
int send_file(SOCKET sockfd, const char *filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("fopen");
        return -1;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Prepare file header
    FileHeader header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "FTRF", 4);
    header.file_size = file_size;
    
    // Extract just the filename from path
    const char *filename = strrchr(filepath, '\\');
    if (!filename) filename = strrchr(filepath, '/');
    if (filename) filename++;
    else filename = filepath;
    
    strncpy(header.filename, filename, sizeof(header.filename) - 1);

    // Send header
    if (send(sockfd, (char*)&header, sizeof(header), 0) != sizeof(header)) {
        perror("send header");
        fclose(file);
        return -1;
    }

    // Send file data
    char buffer[FILE_BUFFER_SIZE];
    long total_sent = 0;
    int bytes_read;

    // Fixed timeout setting - using the const variable
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&FILE_TRANSFER_TIMEOUT, sizeof(FILE_TRANSFER_TIMEOUT)) == SOCKET_ERROR) {
        perror("setsockopt");
        fclose(file);
        return -1;
    }

    while (total_sent < file_size) {
        bytes_read = fread(buffer, 1, FILE_BUFFER_SIZE, file);
        if (bytes_read <= 0) {
            perror("fread");
            fclose(file);
            return -1;
        }

        int bytes_sent = send(sockfd, buffer, bytes_read, 0);
        if (bytes_sent <= 0) {
            perror("send");
            fclose(file);
            return -1;
        }

        total_sent += bytes_sent;
    }

    fclose(file);
    return 0;
}

int receive_file(SOCKET sockfd) {
    // Receive file header
    FileHeader header;
    int bytes_received = recv(sockfd, (char*)&header, sizeof(header), 0);
    if (bytes_received != sizeof(header)) {
        perror("recv header");
        return -1;
    }

    // Validate magic number
    if (memcmp(header.magic, "FTRF", 4) != 0) {
        fprintf(stderr, "Invalid file header\n");
        return -1;
    }

    // Create safe filename (replace any path characters)
    char safe_filename[256];
    strncpy(safe_filename, header.filename, sizeof(safe_filename));
    for (char *p = safe_filename; *p; p++) {
        if (*p == '\\' || *p == '/' || *p == ':' || *p == '*' || *p == '?' || 
            *p == '"' || *p == '<' || *p == '>' || *p == '|') {
            *p = '_';
        }
    }

    printf("Receiving file: %s (%ld bytes)\n", safe_filename, header.file_size);

    FILE *file = fopen(safe_filename, "wb");
    if (!file) {
        perror("fopen");
        return -1;
    }

    // Receive file data
    char buffer[FILE_BUFFER_SIZE];
    long total_received = 0;

    // Fixed timeout setting - using the const variable
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&FILE_TRANSFER_TIMEOUT, sizeof(FILE_TRANSFER_TIMEOUT)) == SOCKET_ERROR) {
        perror("setsockopt");
        fclose(file);
        return -1;
    }

    while (total_received < header.file_size) {
        int to_read = (header.file_size - total_received) > FILE_BUFFER_SIZE ? 
                     FILE_BUFFER_SIZE : (header.file_size - total_received);
        
        bytes_received = recv(sockfd, buffer, to_read, 0);
        if (bytes_received <= 0) {
            perror("recv");
            fclose(file);
            return -1;
        }

        if (fwrite(buffer, 1, bytes_received, file) != bytes_received) {
            perror("fwrite");
            fclose(file);
            return -1;
        }

        total_received += bytes_received;
    }

    fclose(file);
    return 0;
}

/* Client connection handler */
DWORD WINAPI handle_client_connection(LPVOID lpParam) {
    ClientInfo *client = (ClientInfo *)lpParam;
    SOCKET sockfd = client->socket;
    char buffer[NET_BUFFER_SIZE];
    int bytes_received;

    printf("Client connected from %s:%d\n", 
           inet_ntoa(client->address.sin_addr), 
           ntohs(client->address.sin_port));

    send(sockfd, PROMPT, strlen(PROMPT), 0);

    while (1) {
        memset(buffer, 0, NET_BUFFER_SIZE);
        bytes_received = recv(sockfd, buffer, NET_BUFFER_SIZE - 1, 0);

        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("Client disconnected\n");
            } else {
                perror("recv");
            }
            break;
        }

        buffer[bytes_received] = '\0';

        if (strcmp(buffer, "disconnect") == 0) {
            send(sockfd, "Goodbye!\n", 9, 0);
            break;
        }
        else if (strncmp(buffer, "download ", 9) == 0) {
            const char *filename = buffer + 9;
            if (send_file(sockfd, filename) == 0) {
                send(sockfd, "File sent successfully\n", 22, 0);
            } else {
                send(sockfd, "File send failed\n", 17, 0);
            }
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }
        else if (strncmp(buffer, "upload ", 7) == 0) {
            if (receive_file(sockfd) == 0) {
                send(sockfd, "File received successfully\n", 27, 0);
            } else {
                send(sockfd, "File receive failed\n", 20, 0);
            }
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }
        else if (strcmp(buffer, "rickroll") == 0) {
            system("start https://www.youtube.com/watch?v=dQw4w9WgXcQ");
            send(sockfd, "Never gonna give you up!\n", 25, 0);
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }
        else if (strcmp(buffer, "matrix") == 0) {
            system("color 0A && echo %RANDOM% %RANDOM% %RANDOM%");
            send(sockfd, "Entered the Matrix...\n", 22, 0);
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }
        else if (strcmp(buffer, "disco") == 0) {
            system("powershell -c (1..5) | % { [Console]::Beep(500,200); Start-Sleep -m 100 }");
            send(sockfd, "Disco time! 🎵\n", 15, 0);
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }
        else if (strcmp(buffer, "troll") == 0) {
            send(sockfd, "( ͡° ͜ʖ ͡°)\n", 10, 0);
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }

        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
        HANDLE hReadPipe, hWritePipe;
        
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            send(sockfd, "Error: Failed to create pipe\n", 28, 0);
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }

        STARTUPINFO si = { sizeof(STARTUPINFO) };
        PROCESS_INFORMATION pi;
        si.hStdError = hWritePipe;
        si.hStdOutput = hWritePipe;
        si.dwFlags |= STARTF_USESTDHANDLES;

        if (strncmp(buffer, "cd ", 3) == 0 || strcmp(buffer, "cd") == 0) {
            const char *path = (strlen(buffer) > 3) ? buffer + 3 : getenv("USERPROFILE");
            if (_chdir(path) != 0) {
                char error[256];
                sprintf(error, "cd: %s\n", strerror(errno));
                send(sockfd, error, strlen(error), 0);
            } else {
                char cwd[MAX_COMMAND_LENGTH];
                if (_getcwd(cwd, sizeof(cwd)) != NULL) {
                    strcat(cwd, "\n");
                    send(sockfd, cwd, strlen(cwd), 0);
                }
            }
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }

        char cmdLine[MAX_COMMAND_LENGTH + 20];
        sprintf(cmdLine, "cmd.exe /c %s", buffer);

        if (!CreateProcess(NULL, cmdLine, NULL, NULL, TRUE, 
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            char errorMsg[256];
            sprintf(errorMsg, "Error executing command (Code: %lu)\n", GetLastError());
            send(sockfd, errorMsg, strlen(errorMsg), 0);
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            send(sockfd, PROMPT, strlen(PROMPT), 0);
            continue;
        }

        CloseHandle(hWritePipe);

        char output[NET_BUFFER_SIZE];
        DWORD bytesRead;
        while (ReadFile(hReadPipe, output, NET_BUFFER_SIZE - 1, &bytesRead, NULL) && bytesRead > 0) {
            output[bytesRead] = '\0';
            send(sockfd, output, bytesRead, 0);
        }

        CloseHandle(hReadPipe);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        send(sockfd, PROMPT, strlen(PROMPT), 0);
    }

    closesocket(sockfd);
    free(client);
    
    // Signal the server to stop after client disconnects
    server_running = 0;
    if (server_socket != INVALID_SOCKET) {
        closesocket(server_socket);
        server_socket = INVALID_SOCKET;
    }
    
    return 0;
}

/* Remote command execution */
void execute_remote_command(SOCKET sockfd, char **args) {
    char buffer[NET_BUFFER_SIZE] = {0};
    
    for (int i = 0; args[i] != NULL; i++) {
        if (i > 0) strncat(buffer, " ", NET_BUFFER_SIZE - strlen(buffer) - 1);
        strncat(buffer, args[i], NET_BUFFER_SIZE - strlen(buffer) - 1);
    }

    // Handle file transfers specially
    if (strncmp(buffer, "download ", 9) == 0 || strncmp(buffer, "upload ", 7) == 0) {
        if (send(sockfd, buffer, (int)strlen(buffer), 0) == SOCKET_ERROR) {
            perror("send");
            return;
        }

        if (strncmp(buffer, "download ", 9) == 0) {
            if (receive_file(sockfd) != 0) {
                printf("File download failed\n");
            }
        } 
        else if (strncmp(buffer, "upload ", 7) == 0) {
            const char *filename = buffer + 7;
            if (send_file(sockfd, filename) != 0) {
                printf("File upload failed\n");
            }
        }
        return;
    }

    // Normal command execution
    if (send(sockfd, buffer, (int)strlen(buffer), 0) == SOCKET_ERROR) {
        perror("send");
        return;
    }

    while (1) {
        memset(buffer, 0, NET_BUFFER_SIZE);
        int bytes_received = recv(sockfd, buffer, NET_BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("Server closed connection\n");
            } else {
                perror("recv");
            }
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        char *prompt_pos = strstr(buffer, PROMPT);
        if (prompt_pos != NULL) {
            *prompt_pos = '\0';
            printf("%s", buffer);
            break;
        }
        
        printf("%s", buffer);
    }
}

/* Main command execution */
void execute_command(char **args, int input_fd, int output_fd) {
    if (args[0] == NULL) return;

    if (strcmp(args[0], "listen") == 0) {
        if (args[1] == NULL) {
            fprintf(stderr, "Usage: listen <port>\n");
            return;
        }

        int port = atoi(args[1]);
        server_socket = create_server_socket(port);
        if (server_socket == INVALID_SOCKET) return;

        printf("Server listening on port %d...\n", port);
        printf("Press Ctrl+C to stop server\n");

        server_running = 1;
        while (server_running) {
            ClientInfo *client = (ClientInfo *)malloc(sizeof(ClientInfo));
            int client_len = sizeof(client->address);
            
            client->socket = accept(server_socket, (struct sockaddr *)&client->address, &client_len);
            if (client->socket == INVALID_SOCKET) {
                if (!server_running) {
                    free(client);
                    break;
                }
                perror("accept");
                free(client);
                continue;
            }

            HANDLE hThread = CreateThread(NULL, 0, handle_client_connection, client, 0, NULL);
            if (hThread == NULL) {
                perror("CreateThread");
                free(client);
                continue;
            }
            
            // Wait for the client thread to finish
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            
            if (!server_running) {
                break;
            }
        }

        if (server_socket != INVALID_SOCKET) {
            closesocket(server_socket);
            server_socket = INVALID_SOCKET;
        }
        server_running = 0;
        printf("Server stopped. Returning to shell.\n");
    }
    else if (strcmp(args[0], "connect") == 0) {
        if (args[1] == NULL || args[2] == NULL) {
            fprintf(stderr, "Usage: connect <host> <port>\n");
            return;
        }

        int port = atoi(args[2]);
        SOCKET sockfd = connect_to_server(args[1], port);
        if (sockfd == INVALID_SOCKET) return;

        printf("Connected to %s:%d\n", args[1], port);
        printf("Type 'disconnect' to exit\n");

        while (1) {
            printf("remote> ");
            fflush(stdout);

            char line[MAX_COMMAND_LENGTH];
            if (!fgets(line, sizeof(line), stdin)) break;

            line[strcspn(line, "\n")] = '\0';
            if (strcmp(line, "disconnect") == 0) break;

            char *remote_args[MAX_ARGS];
            int arg_count = 0;
            char *token = strtok(line, " ");
            while (token && arg_count < MAX_ARGS - 1) {
                remote_args[arg_count++] = token;
                token = strtok(NULL, " ");
            }
            remote_args[arg_count] = NULL;

            execute_remote_command(sockfd, remote_args);
        }

        closesocket(sockfd);
    }
    else if (strcmp(args[0], "cd") == 0) {
        const char *path = args[1] ? args[1] : getenv("USERPROFILE");
        if (_chdir(path) != 0) {
            perror("cd");
        }
    }
    else if (strcmp(args[0], "exit") == 0) {
        exit(0);
    }
    else if (strcmp(args[0], "clear") == 0 || strcmp(args[0], "cls") == 0) {
        system(CLEAR);
    }
    else if (strcmp(args[0], "rickroll") == 0) {
        system("start https://www.youtube.com/watch?v=dQw4w9WgXcQ");
    }
    else if (strcmp(args[0], "matrix") == 0) {
        system("color 0A && echo %RANDOM% %RANDOM% %RANDOM%");
    }
    else if (strcmp(args[0], "disco") == 0) {
        system("powershell -c (1..5) | % { [Console]::Beep(500,200); Start-Sleep -m 100 }");
    }
    else if (strcmp(args[0], "troll") == 0) {
        printf("( ͡° ͜ʖ ͡°)\n");
    }
    else {
        char cmd[MAX_COMMAND_LENGTH] = {0};
        for (int i = 0; args[i] != NULL; i++) {
            if (i > 0) strncat(cmd, " ", MAX_COMMAND_LENGTH - strlen(cmd) - 1);
            strncat(cmd, args[i], MAX_COMMAND_LENGTH - strlen(cmd) - 1);
        }
        system(cmd);
    }
}

int main() {
    signal(SIGINT, handle_signal);
    
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    set_variable("PS1", "my_shell> ");

    char line[MAX_COMMAND_LENGTH];
    while (1) {
        printf("%s", get_variable("PS1") ? get_variable("PS1") : "my_shell> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            printf("\n");
            break;
        }

        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) == 0) continue;

        char *args[MAX_ARGS];
        int arg_count = 0;
        char *token = strtok(line, " ");
        while (token && arg_count < MAX_ARGS - 1) {
            args[arg_count++] = token;
            token = strtok(NULL, " ");
        }
        args[arg_count] = NULL;

        execute_command(args, _fileno(stdin), _fileno(stdout));
    }

    WSACleanup();
    return 0;
}