/**
 * @file
 * Functionality for the inter process communication of the pwifi code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <signal.h>

#include "pwifi_ipc.h"

/* Timeouts for IPC communication in seconds and microseconds.
 * The actual timeout will be the sum of both.*/
#define PWIFI_IPC_TIMEOUT_SECS   0
#define PWIFI_IPC_TIMEOUT_MUSECS 200000

/**
 * Connect to the pwifi socket.
 *
 *@param socket_location The socket to connect to.
 *
 * @return Socket file descriptor on success.
 *         -1 on error
 */
int pwifi_connect_socket(const char *const socket_location)
{
    int sockfd, len;
    struct sockaddr_un remote;

    if ((sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, socket_location);
    len = sizeof(remote.sun_family) + strlen(socket_location);

    if (connect(sockfd, (struct sockaddr *) &remote, len) == -1) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * Bind to the pwifi socket.
 * Caller is responsible for closing the socket again.
 *
 * @param socket_location The socket to bind to.
 *
 * @return  Socket file descriptor on success
 *         -1 on error
 */
int pwifi_bind_socket(const char *const socket_location)
{
    struct sockaddr_un local;
    int sockfd, len;

    if ((sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, socket_location);
    len = sizeof(local.sun_family) + strlen(socket_location);

    unlink(local.sun_path);
    if (bind(sockfd, (struct sockaddr *) &local, len) == -1) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * Send a message on the given socket from the given buffer.
 * The socket has to be connected.
 *
 * @param sockfd  The socket file descriptor.
 * @param buf     The message buffer.
 * @param msg_len The length of the message.
 * @return Number of sent bytes on success
 *         -1 on error
 */
int pwifi_send_msg(int sockfd, const char *const buf, size_t msg_len)
{
    int numbytes;

    if ((numbytes = send(sockfd, buf, msg_len, 0)) == -1) {
        perror("send failed");
        return -1;
    }

    return numbytes;
}

/**
 * Receive a message on the given socket and buffer.
 * Message will be null-terminated.
 *
 * @param sockfd The socket file descriptor.
 * @param buf    Buffer on which received message is written.
 * @param buflen Size of the buffer.
 * @return Received bytes on success
 *         -1 on error
 */
int pwifi_recv_msg(int sockfd, char *buf, size_t buflen)
{
    struct timeval tv;
    fd_set rfds;
    int numbytes, res;

    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);

    tv.tv_sec  = PWIFI_IPC_TIMEOUT_SECS;
    tv.tv_usec = PWIFI_IPC_TIMEOUT_MUSECS;

    res = select(sockfd + 1, &rfds, NULL, NULL, &tv);
    if (res == -1) {
        perror("select");
    } else if (res == 0) {
        printf("Select timeout.\n");
        return -1;
    }

    if ((numbytes = recv(sockfd, buf, buflen - 1 , 0)) == -1) {
        perror("recvfrom failed");
        return -1;
    }

    buf[numbytes] = '\0';
    return numbytes;
}
