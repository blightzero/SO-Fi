/*
 * hostapd / IEEE 802.11 Management: Beacon and Probe Request/Response
 * Copyright (c) 2002-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef BEACON_H
#define BEACON_H

struct ieee80211_mgmt;

void handle_probe_req(struct hostapd_data *hapd,
		      const struct ieee80211_mgmt *mgmt, size_t len);
void ieee802_11_set_beacon(struct hostapd_data *hapd);
void ieee802_11_set_beacons(struct hostapd_iface *iface);

int pwifi_handle_offbandSending(struct hostapd_data *const hapd,const u8 *const ssid, const u8 ssid_len, const u8 *const dest_address);
#endif /* BEACON_H */