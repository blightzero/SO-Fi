/**
 * @file
 * Common pwifi functions that are used by both hostapd and wpa_supplicant.
 *
 *
 *   :copyright: (c) Copyright 2012 by David Martin and Benjamin Grap.
 *   :license: GPLv2, see COPYING for more details.
 *
 *   
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pwifi_common.h"

/* prefix for every pwifi SSID */
#define PWIFI_TOKEN         "#;"
#define PWIFI_TOKEN_LEN     (strlen(PWIFI_TOKEN))

/**
 * Check whether given SSID is pwifi encoded.
 *
 * @param ssid     The SSID to be checked.
 * @param ssid_len Length of the SSID.
 * @return 1, SSID is a pwifi code
 *         0, else
 */
int pwifi_ssid_is_pwifi_encoded(const uint8_t *const ssid, const uint8_t ssid_len) {
    if (!ssid || ssid_len < PWIFI_SSID_LEN) {
        return 0;
    }

    return memcmp(PWIFI_TOKEN, ssid, PWIFI_TOKEN_LEN) == 0;
}

/**
 * Check whether the requested SSID encoding is from a native or legacy client.
 * It simply checks the native flag in the SSID encoding.
 *
 * @param ssid     SSID to check.
 * @param ssid_len Length of the SSID.
 * @return 1 client is native
 *         0 else
 */
int pwifi_is_native_client(const uint8_t* const ssid, const uint8_t ssid_len)
{
    if (!pwifi_ssid_is_pwifi_encoded(ssid, ssid_len)) {
        return 0;
    }

    if (ssid[PWIFI_SSID_INDEX_NATIVE] == PWIFI_CS_LEGACY) {
        return 0;
    } else if (ssid[PWIFI_SSID_INDEX_NATIVE] == PWIFI_CS_NATIVE) {
        return 1;
    }

    return 0;
}

/**
 * Assign the given IP address to the given interface.
 *
 * @param iface The target interface.
 * @param ip    The IP address to be assigned.
 * @return  0 on success
 *         -1 on error
 */
int pwifi_set_ip_address(const char *const iface, const char *const ip)
{
    char syscall[MAXBUFLEN];

    sprintf(syscall, "ifconfig %s %s", iface, ip);
    if (system(syscall) == -1) {
        fprintf(stderr, "Setting IP address failed.");
        return -1;
    }
    return 0;
}

/**
 * Start measuring the elapsed time.
 * This means simply setting the given timeval struct to the current time.
 *
 * @param timer The timeval struct used to determine the passed time later on.
 * @param msg   The message to be printed when starting the timer.
 */
void pwifi_start_timer(struct os_time *const timer, const char *const msg)
{
    if (!timer) {
        return;
    }

    if (msg) {
        wpa_printf(MSG_DEBUG, "%s", msg);
    }
    os_get_time(timer);
}

/**
 * Print the elapsed time since the time in the given timeval struct.
 *
 * @param timer The timeval struct holding a time (ideally set by pwifi_start_timer()).
 * @param msg   The message to be printed with the elapsed time.
 */
void pwifi_elapsed_time(struct os_time *const timer, const char *const msg)
{
    struct os_time current_time;
    struct os_time result;

    if (!timer) {
        return;
    }

    os_get_time(&current_time);
    if (current_time.usec < timer->usec) {
         int nsec = (timer->usec - current_time.usec) / 1000000 + 1;
         timer->usec -= 1000000 * nsec;
         timer->sec += nsec;
    }
    if (current_time.sec - timer->sec > 1000000) {
        int nsec = (current_time.usec - timer->usec) / 1000000;
        current_time.usec += 1000000 * nsec;
        current_time.sec -= nsec;
    }

    /* Compute the time remaining to wait.
       usec is certainly positive. */
    result.sec = current_time.sec - timer->sec;
    result.usec = current_time.usec - timer->usec;

    wpa_printf(MSG_ERROR, "%s: %ds, %dms, %dus.", msg ? msg : "Elapsed time",
                                                  (int) result.sec,
                                                  (int) result.usec / 1000,
                                                  (int) result.usec);
}
