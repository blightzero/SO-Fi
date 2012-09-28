#ifndef PWIFI_H_
#define PWIFI_H_

#include "utils/includes.h"
#include "utils/common.h"
#include "ap/ieee802_11.h"

struct hapd_interfaces;

/* maximum number of simultaneous BSSs to be set up */
#define PWIFI_MAX_BSS_COUNT 3

struct hostapd_data *pwifi_handle_probe_request(struct hostapd_data *const hapd,
                                                const u8 *const ssid, const u8 ssid_len, const u8 *const source_address);
int  pwifi_handle_deauth(struct hostapd_data *hapd);
u8 * pwifi_handle_ie_insertion(u8 *pos, size_t len, const u8 *const ssid,
                               const u8 ssid_len, const u8 sa[ETH_ALEN]);
void pwifi_handle_sta_timeout(void *eloop_ctx, void *timeout_ctx);
void pwifi_set_interfaces(struct hapd_interfaces *const interface);

#endif /* PWIFI_H_ */
