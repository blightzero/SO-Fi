#ifndef PWIFI_IPC_H_
#define PWIFI_IPC_H_

#include "../utils/common.h"

#define PWIFI_LISTENER_INTERFACE "/tmp/pwifi_listener.sock"
#define PWIFI_HOSTAPD_INTERFACE  "/tmp/pwifi_hostapd.sock"

/* pwifi port on which the listener expects messages from legacy clients. */
#define PWIFI_IPC_PORT 5555

/* The number of retries to be performed before sending the message or
 * establishment of the connection is deemed not possible. */
#define PWIFI_IPC_RETRIES 1
/* String used in replies reporting a success. */
#define PWIFI_IPC_ACK "OK"
#define PWIFI_IPC_ACK_LEN strlen(PWIFI_IPC_ACK)

#define PWIFI_IPC_PACK "PA"
#define PWIFI_IPC_PACK_LEN strlen(PWIFI_IPC_PACK)

#define PWIFI_IPC_NACK "NA"
#define PWIFI_IPC_NACK_LEN strlen(PWIFI_IPC_NACK)

/* Keyword to identify service requests to the backend. */
#define PWIFI_IPC_REQUEST "REQUEST"
/* Keyword to notify the backend about service disestablishments.
 * It is used to notify the backend when the BSS is disestablished, for example
 * when the client disconnects or times out. */
#define PWIFI_IPC_DISBAND "DISBAND"


int pwifi_connect_socket(const char *const socket_location);
int pwifi_bind_socket(const char *const socket_location);
int pwifi_send_msg(int sockfd, const char *const buf, size_t msg_len);
int pwifi_recv_msg(int sockfd, char *buf, size_t buflen);

#endif /* PWIFI_IPC_H_ */
