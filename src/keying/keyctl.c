#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct sockaddr_un address = {0};
    char command[512];
    char response[80];
    size_t used = 0;
    ssize_t count;
    int descriptor;

    if (argc != 2 || strlen(argv[1]) >= sizeof(address.sun_path)) {
        fprintf(stderr, "Usage: %s CONTROL_SOCKET < command\n", argv[0]);
        return EXIT_FAILURE;
    }
    while ((count = read(STDIN_FILENO, command + used,
                         sizeof(command) - 1U - used)) > 0) {
        used += (size_t)count;
        if (used == sizeof(command) - 1U) {
            fprintf(stderr, "control command is too long\n");
            return EXIT_FAILURE;
        }
    }
    if (count < 0 || used == 0U) {
        perror("read control command");
        return EXIT_FAILURE;
    }
    command[used] = '\0';
    descriptor = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (descriptor < 0) {
        perror("control socket");
        return EXIT_FAILURE;
    }
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, argv[1], strlen(argv[1]) + 1U);
    if (connect(descriptor, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        send(descriptor, command, used, MSG_NOSIGNAL) != (ssize_t)used) {
        perror("send control command");
        close(descriptor);
        return EXIT_FAILURE;
    }
    count = recv(descriptor, response, sizeof(response) - 1U, 0);
    close(descriptor);
    if (count <= 0) {
        perror("receive control response");
        return EXIT_FAILURE;
    }
    response[count] = '\0';
    fputs(response, stdout);
    return strcmp(response, "OK\n") == 0 || strncmp(response, "STATUS ", 7U) == 0
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
