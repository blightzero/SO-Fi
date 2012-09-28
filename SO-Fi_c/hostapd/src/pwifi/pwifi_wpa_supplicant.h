#ifndef PWIFI_WPA_SUPPLICANT_H_
#define PWIFI_WPA_SUPPLICANT_H_

#include "utils/includes.h"
#include "utils/common.h"
#include "drivers/driver.h"
#include "../wpa_supplicant/config_ssid.h"

int pwifi_handle_received_ies(struct wpa_scan_res *bss, struct wpa_ssid *ssid);
int pwifi_scan_result_compar(const struct wpa_scan_res *const a,
                             const struct wpa_scan_res *const b);

#endif /* PWIFI_WPA_SUPPLICANT_H_ */
