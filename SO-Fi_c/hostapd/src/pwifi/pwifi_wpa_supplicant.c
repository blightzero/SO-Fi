/**
 * @file
 * Functionality for the wpa_supplicant part of the pwifi code.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "ap/ap_config.h"
#include "pwifi_common.h"
#include "drivers/driver.h"
#include "../wpa_supplicant/wpa_supplicant_i.h"
#include "../wpa_supplicant/scan.h"
#include "../wpa_supplicant/config.h"
#include "pwifi_wpa_supplicant.h"


/**
 * Handle received Information Elements in a probe response.
 * This function has to be called with the scan result that will be connected to
 * as it will apply the settings provided in the PRES.
 *
 * @param bss  The scan results with the IEs.
 * @param ssid The network of the BSS.
 * @return  0 on success
 *         -1 on error
 */
int pwifi_handle_received_ies(struct wpa_scan_res *bss, struct wpa_ssid *ssid)
{
    const u8 *ie, *pwifi_ie;

    if (!bss || !ssid) {
        return -1;
    }
    if (!pwifi_is_native_client(ssid->ssid, ssid->ssid_len)) {
        return 0;
    }

    wpa_printf(MSG_ERROR, "Handling pwifi Information Elements.");
    if ((pwifi_ie = wpa_scan_get_ie(bss, PWIFI_EID)) == NULL) {
        wpa_printf(MSG_ERROR, "No pwifi Information Element found.");
        return -1;
    }
    wpa_hexdump(MSG_MSGDUMP, "pwifi IEs: ", pwifi_ie, pwifi_ie[1] + 1);

    if ((ie = wpa_scan_get_ie_after_pos(bss, pwifi_ie + 2, PWIFI_EID_IP))) {
        pwifi_set_ip_address("wlan0", (char *) &ie[2]);
    } else {
        wpa_printf(MSG_DEBUG, "No pwifi IP address assignment IE found.");
    }

    if ((ie = wpa_scan_get_ie_after_pos(bss, pwifi_ie + 2, PWIFI_EID_PSK))) {
        wpa_printf(MSG_DEBUG, "Got WPA psk in PRES.");
        os_free(ssid->passphrase);
        ssid->passphrase = NULL;
        ssid->psk_set    = 1;
        os_memcpy(ssid->psk, &ie[2], PMK_LEN);
    }
    if ((ie = wpa_scan_get_ie_after_pos(bss, pwifi_ie + 2, PWIFI_EID_PWD))) {
        wpa_printf(MSG_DEBUG, "Got password in PRES: %s", &ie[2]);
        os_free(ssid->passphrase);
        ssid->passphrase = os_strdup((char *) &ie[2]);
        wpa_config_update_psk(ssid);
    }

    if ((ie = wpa_scan_get_ie_after_pos(bss, pwifi_ie + 2, PWIFI_EID_URL))) {
        char syscall[MAXBUFLEN] = { 0 };
        wpa_printf(MSG_DEBUG, "Found pwifi URL IE: %s", &ie[2]);
        sprintf(syscall, "xdg-open %s & disown", &ie[2]);
        if (system(syscall) == -1) {
            wpa_printf(MSG_DEBUG, "Application call failed.");
        }
    } else {
        wpa_printf(MSG_DEBUG, "No pwifi APP IE found.");
    }

    return 0;
}

/**
 * Compare two wpa_supplicant scan results.
 *
 * @param a First scan result.
 * @param b Second scan result.
 *
 * @return Return  1 if b is considered better.
 *                -1 if a is considered better.
 *                 0 else.
 */
int pwifi_scan_result_compar(const struct wpa_scan_res *const a,
                             const struct wpa_scan_res *const b)
{
   const u8 *ie_a, *ie_b;
   int load_a, load_b;

   ie_a = wpa_scan_get_ie(a, PWIFI_EID);
   ie_b = wpa_scan_get_ie(b, PWIFI_EID);

   /* We only get a pwifi PRES when we actually requested a pwifi network,
    * therefore rate them higher than non-pwifi networks. */
   if (ie_a && !ie_b) {
       return -1;
   } else if (!ie_a && ie_b) {
       return 1;
   } else if (!ie_a && !ie_b) {
       return 0;
   }

   if ((ie_a = wpa_scan_get_ie_after_pos(a, &ie_a[2], PWIFI_EID_LOAD)) == NULL ||
       (ie_b = wpa_scan_get_ie_after_pos(b, &ie_b[2], PWIFI_EID_LOAD)) == NULL) {
       return 0;
   }

   load_a = ie_a[2];
   load_b = ie_b[2];
   wpa_printf(MSG_DEBUG, "pwifi load comparison:\n"
              " a): " MACSTR ": %d connected STA(s).\n"
              " b): " MACSTR ": %d connected STA(s).",
              MAC2STR(a->bssid), load_a, MAC2STR(b->bssid), load_b);

   if (load_a > load_b) {
       wpa_printf(MSG_DEBUG, " b) is better.");
       return 1;
   } else if (load_a < load_b) {
       wpa_printf(MSG_DEBUG, " a) is better.");
       return -1;
   }

   return 0;
}
