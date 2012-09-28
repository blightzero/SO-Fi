#ifndef PWIFI_COMMON_H_
#define PWIFI_COMMON_H_

#include <stdint.h>

#include "utils/common.h"

/* The default passphrase used for BSSs for legacy clients. */
#define PWIFI_LEGACY_PASSPHRASE "pwifi_network"

/* Current pwifi version. */
#define PWIFI_VERSION '1'
/* Length of PWIFI SSIDs. */
#define PWIFI_SSID_LEN 32
/* Index of Version tag in the SSID. */
#define PWIFI_SSID_INDEX_VERSION 2
/* Index of Native tag in the SSID. */
#define PWIFI_SSID_INDEX_NATIVE 3
/* Index of the Service type in the SSID. */
#define PWIFI_SSID_INDEX_SERVICE 4

/* Coding scheme related defines. */
/* Character representation for a legacy client. */
#define PWIFI_CS_LEGACY '0'
/* Character representation for a native client. */
#define PWIFI_CS_NATIVE '1'
/* Character representation for a simple connection request. */
#define PWIFI_CS_CONNECTION '0'
/* Character representation for a group network request. */
#define PWIFI_CS_GROUP '1'
/* Character representation for a file request. */
#define PWIFI_CS_FILE '2'
/* Character representation for a people search request. */
#define PWIFI_CS_PEOPLE '3'

/* pwifi Element ID for Information Elements in probe responses */
#define PWIFI_EID 222
/* Element ID for an IP assignment. */
#define PWIFI_EID_IP 1
/* Element ID for the URL where the offered service is available. */
#define PWIFI_EID_URL 2
/* Element ID for the password of the encrypted network. */
#define PWIFI_EID_PWD 3
/* Element ID for the number of stations allowed to access the network. */
#define PWIFI_EID_MAX_STA 4
/* Element ID for the load of the network. */
#define PWIFI_EID_LOAD 5
/* Element ID for the WPA psk. */
#define PWIFI_EID_PSK 6
/* Element ID for the SSID. */
#define PWIFI_EID_SSID 7
/* Element ID for the MAC. */
#define PWIFI_EID_MAC 8

#define MAXBUFLEN  255

int pwifi_ssid_is_pwifi_encoded(const uint8_t *const ssid, const uint8_t ssid_len);
int pwifi_is_native_client(const uint8_t* const ssid, const uint8_t ssid_len);
int pwifi_set_ip_address(const char *const iface, const char *const ip);
void pwifi_start_timer(struct os_time *const timer, const char *const msg);
void pwifi_elapsed_time(struct os_time *const timer, const char *const msg);

#endif /* PWIFI_COMMON_H_ */
