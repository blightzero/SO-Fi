/**
 * @file
 * All pwifi functionality which is restricted to hostapd only, i.e. the
 * setup of BSSs and dealing with probe requests and probe responses.
 *
 * @brief hostapd related part of the pwifi code
 */

#include <netinet/ether.h>
#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "ap/ap_config.h"
#include "utils/wpa_debug.h"
#include "ap/hostapd.h"
#include "ap/beacon.h"
#include "../hostapd/config_file.h"
#include "ap/sta_info.h"
#include "../common/ieee802_11_defs.h"
#include "pwifi_common.h"
#include "pwifi_ipc.h"
#include "pwifi_hostapd.h"


/* Timeout for our connected stations after which a BSS is shut down. */
#define PWIFI_STA_TIMEOUT 20
/* Timeout in seconds after which a BSS is disbanded when no STA connects. */
#define PWIFI_BSS_TIMEOUT 60
/* Maximum number of connected stations per BSS. */
#define PWIFI_MAX_STA 255
/* Maximum password length for WPA encrypted networks. */
#define MAX_PW_LEN 63

/* The different modes for beacons in BSSs. Numeric values are mapped as
 * expected by hostapd. */
enum beacon_mode {
    SEND_SSID        = 0, /* Send SSID in beacons and send PRES for broadcast PREQ. */
    SEND_EMPTY_SSID  = 1, /* Send empty SSID in beacons, ignore broadcast PREQ. */
    SEND_ZEROED_SSID = 2 /* Send clear SSID (zeroes) with original length, ignore
                            broadcast PREQ.*/
};

/**
 * Data structure for an IP address assignment.
 */
struct ip_assignment {
    u8 sta_addr[ETH_ALEN]; /**< MAC address of the station. */
    u8 is_assigned; /**< 0: Slot still free, 1: IP is assigned. */
};
/**
 * Data structure for the ether_ntoa(addr) function.
 */
//struct ether_addr {
//  u_int8_t ether_addr_octet[6];
//};



/** pwifi per BSS data */
struct pwifi_bss_data {
    unsigned int active; /**< BSS is currently active */
    char ssid[HOSTAPD_MAX_SSID_LEN]; /**< ssid of the BSS */
    unsigned int ssid_len; /**< length of the SSID. */
    struct hostapd_data *hapd; /**< Pointer to hostapd BSS data */
    /** Array of IP address assignments. */
    struct ip_assignment assigned_ips[PWIFI_MAX_STA];
    /** Additional info provided from the service backend. */
    u8 service_data[MAXBUFLEN];
    /** Length of the message in the service_data buffer. */
    u8 service_data_len;
    /** The password in use when the BSS is encrypted.
     *  password_is_psk marks whether it is a string or in binary. */
    union {
        char          string[MAX_PW_LEN];
        unsigned char binary[MAX_PW_LEN];
    } password;
    /** If set to 1 password does not contain the string password but the
     *  WPA psk as binary. */
    int password_is_psk;
};

/** Reference to hostapds internal interface data for pwifi to work on. */
static struct hapd_interfaces *interfaces;
/** First free BSS in our BSS array. */
static unsigned int free_bss_id = 0;
/** Array of our BSSs. */
static struct pwifi_bss_data bss_data[PWIFI_MAX_BSS_COUNT] = { { 0 } };
/** Socket file descriptor for our communication with the listener. */
static int sockfd_listener = 0;
/** Socket file descriptor we listen on. */
static int sockfd_hostapd = 0;

/**
 * Get the specified Information Element after the given position.
 * This allows to specify multiple IEs inside of a single IE and to reuse EIDs.
 *
 * Behaviour is undefined when there is no TLV at the provided position.
 *
 * @param pos The position after which should be looked for the IE.
 * @param len Size of the buffer.
 * @param ie  The IE to search for.
 *
 * @return The position of the IE when found.
 *         NULL on error or when IE does not exist.
 */
static u8 *get_ie_after_pos(u8 *pos, u8 len, u8 ie)
{
    u8 *cur, *end;

    if (!pos) {
        return NULL;
    }

    cur = pos;
    end = cur + len;
    while (cur + 1 < end) {
        if (cur + 2 + cur[1] > end)
            break;
        if (cur[0] == ie)
            return cur;
        cur += 2 + cur[1];
    }

    return NULL;
}

/**
 * Get the character defining the request type from the given SSID.
 *
 * Behaviour is undefined when no valid pwifi SSID is provided.
 *
 * @param ssid     The SSID from which the request type is returned.
 * @param ssid_len Length of the given SSID.
 *
 * @return The character representing the request type.
 */
static unsigned char request_type(const uint8_t *const ssid, const uint8_t ssid_len)
{
    return ssid[PWIFI_SSID_INDEX_SERVICE];
}

/**
 * Spawn another BSS with the given interface and SSID.
 * @param slot   The slot in our BSS array to be used.
 * @param ifname The interface to be used for the BSS.
 * @param ssid   The SSID to be used for the BSS.
 * @return  0 on success
 *         -1 on error
 */
static int add_bss(unsigned int slot, const char *const ifname, const char *const ssid, const u8 *const sa)
{
    struct hostapd_iface  *iface = interfaces->iface[0];
    struct hostapd_data   *hapd;
    struct pwifi_bss_data *bss;
    char   ip[MAXBUFLEN] = { 0 };
    enum beacon_mode mode;
    size_t i;
    u8     *ie;

    struct os_time hostapd_config_bss_timer, hostapd_alloc_bss_data_timer;
    struct os_time hostapd_setup_bss_timer;

    /* add another BSS to the config */
    pwifi_start_timer(&hostapd_config_bss_timer, NULL);
    hostapd_config_bss(iface->conf, ifname);
    pwifi_elapsed_time(&hostapd_config_bss_timer, "hostapd_config_bss:");

    /* BSS data gets reallocated in hostapd_config_bss(). Update existing references. */
    for (i = 0; i < iface->num_bss; i++) {
        iface->bss[i]->conf = &iface->conf->bss[i];
    }

    /* interface needs a reference to the new BSS */
    iface->bss = os_realloc(iface->bss,(iface->num_bss + 1) * sizeof(struct hostapd_data *));
    /* allocate and initialize the actual BSS data */
    pwifi_start_timer(&hostapd_alloc_bss_data_timer, NULL);
    hapd = hostapd_alloc_bss_data(iface, iface->conf, &iface->conf->bss[iface->conf->num_bss - 1]);
    pwifi_elapsed_time(&hostapd_alloc_bss_data_timer, "hostapd_alloc_bss_data:");
    iface->bss[iface->num_bss] = hapd;
    wpa_printf(MSG_DEBUG, "Successfully added hapd to Interface.\n");

    bss = &bss_data[slot];
    if ((ie = get_ie_after_pos(bss->service_data, bss->service_data_len, PWIFI_EID_MAC))) {
        os_memcpy(hapd->own_addr, &ie[2], ETH_ALEN);
        wpa_printf(MSG_DEBUG, "Using provided Ethernet Address: %s.\n", ether_ntoa(((struct ether_addr *) hapd->own_addr)));
    } else {
    	os_memcpy(hapd->own_addr, iface->bss[0]->own_addr, ETH_ALEN);
    	wpa_printf(MSG_DEBUG, "Using default Ethernet Address from Interface Id 0.\n");
    }

    os_strncpy(hapd->conf->ssid.ssid, ssid, os_strlen(ssid));
    hapd->conf->ssid.ssid_len = os_strlen(ssid);
    hapd->conf->ssid.ssid_set = 1;
    iface->num_bss++;
    wpa_printf(MSG_DEBUG, "Changed SSID successfully.\n");
    /* pwifi BSSs are hidden. */
    mode = SEND_EMPTY_SSID;
    hapd->conf->ignore_broadcast_ssid = mode;
    hapd->conf->ap_max_inactivity = PWIFI_STA_TIMEOUT;

    if ((ie = get_ie_after_pos(bss->service_data, bss->service_data_len, PWIFI_EID_MAX_STA))) {
        hapd->conf->max_num_sta = ie[2];
        wpa_printf(MSG_DEBUG, "Using provided max_num_sta of %d.\n",
                   hapd->conf->max_num_sta);
    } else {
        hapd->conf->max_num_sta = PWIFI_MAX_STA;
    }

    wpa_printf(MSG_DEBUG, "Setting up WPA encrypted BSS.");
    if (get_ie_after_pos(bss->service_data, bss->service_data_len, PWIFI_EID_PSK)) {
        if ((ie = get_ie_after_pos(bss->service_data, bss->service_data_len, PWIFI_EID_PSK))) {
            wpa_printf(MSG_DEBUG, "Using provided WPA psk.");
            os_memcpy(bss->password.binary, &ie[2], ie[1]);
            wpa_printf(MSG_DEBUG, "Using: %s", bss->password.binary);
            bss->password_is_psk = 1;
        } else if ((ie = get_ie_after_pos(bss->service_data, bss->service_data_len,
                                          PWIFI_EID_PWD))) {
            wpa_printf(MSG_DEBUG, "Using provided password '%s'.", bss->password.string);
            os_memcpy(bss->password.string, &ie[2], ie[1]);
        } else {
            wpa_printf(MSG_DEBUG, "Neither PSK nor PWD IE found. Using random psk.");
            os_get_random(bss->password.binary, MAX_PW_LEN);
            bss->password_is_psk = 1;
        }

        hapd->conf->wpa = 1;
        if (bss->password_is_psk) {
            struct hostapd_ssid *ssid = &hapd->conf->ssid;
            os_free(ssid->wpa_passphrase);
            ssid->wpa_passphrase = NULL;
            ssid->wpa_psk        = os_zalloc(sizeof(struct hostapd_wpa_psk));
            ssid->wpa_psk->group = 1;
            os_memcpy(ssid->wpa_psk->psk, bss->password.binary, PMK_LEN);
        } else {
            hapd->conf->ssid.wpa_passphrase = os_strdup(bss->password.string);
        }
        hapd->conf->wpa_key_mgmt  = 0;
        hapd->conf->wpa_key_mgmt |= WPA_KEY_MGMT_PSK;
        hapd->conf->wpa_pairwise  = 0;
        hapd->conf->wpa_pairwise |= WPA_CIPHER_CCMP;
        hapd->conf->wpa_pairwise |= WPA_CIPHER_TKIP;


    } else {
        hapd->conf->wpa = 0;
    	wpa_printf(MSG_DEBUG, "Open Network. NO WPA PSK given.");
    }



    pwifi_start_timer(&hostapd_setup_bss_timer, NULL);
    hostapd_setup_bss(hapd, 0);
    pwifi_elapsed_time(&hostapd_setup_bss_timer, "hostapd_setup_bss:");

    //wpa_printf(MSG_ERROR, "Sending PRES after setting up network.");
    //pwifi_handle_offbandSending(hapd,ssid,HOSTAPD_MAX_SSID_LEN,&sa[0]);

    os_strncpy(bss_data[slot].ssid, ssid, os_strlen(ssid));
    bss_data[slot].ssid_len = os_strlen(ssid);
    bss_data[slot].hapd     = hapd;
    /* Reserve broadcast and host IP address. */
    os_memcpy(bss_data[slot].assigned_ips[0].sta_addr, hapd->own_addr, ETH_ALEN);
    bss_data[slot].assigned_ips[0].is_assigned = 1;
    os_memcpy(bss_data[slot].assigned_ips[1].sta_addr, hapd->own_addr, ETH_ALEN);
    bss_data[slot].assigned_ips[1].is_assigned = 1;

    sprintf(ip, "10.0.%d.1/24", slot);
    if (pwifi_set_ip_address(ifname, ip) == -1) {
        wpa_printf(MSG_ERROR, "Setting IP address failed.");
        return -1;
    }

    return 0;
}

/**
 * Remove the BSS at the given slot in our array from hostapds internal data structures.
 * Caller is responsible for any additional cleanup, eg. freeing allocated memory.
 *
 * @param slot Slot of the BSS in our data structure.
 * @return  0 on success
 *         -1 on error
 */
static int remove_bss(const unsigned int slot)
{
    struct hostapd_iface *iface = interfaces->iface[0];
    struct hostapd_data **hapd;
    struct hostapd_bss_config *conf;
    size_t i, j;

    hapd = os_malloc((iface->num_bss - 1) * sizeof(struct hostapd_data *));
    conf = os_malloc((iface->num_bss - 1) * sizeof(struct hostapd_bss_config));
    if (!hapd || !conf) {
        wpa_printf(MSG_ERROR, "Malloc failed.");
        return -1;
    }

    /* copy BSS data minus the one to be removed to the new arrays */
    j = 0;
    for (i = 0; i < iface->num_bss - 1; i++) {
        if (bss_data[slot].hapd == iface->bss[j]) {
            j++;
        }
        hapd[i] = iface->bss[j];
        os_memcpy(&conf[i], &iface->conf->bss[j], sizeof(struct hostapd_bss_config));
        /* last added BSS has to point to new array, therefore at index i */
        iface->conf->last_bss = &conf[i];
        hapd[i]->conf         = &conf[i];
        j++;
    }

    os_free(iface->bss);
    os_free(iface->conf->bss);

    iface->bss = hapd;
    iface->num_bss--;
    iface->conf->bss = conf;
    iface->conf->num_bss--;

    return 0;
}

/**
 * Return the id of the given BSS in our bss_data array.
 * The BSS can be identified by its hapd data or SSID.
 * This function sets the static value free_bss_id for the first free BSS as well.
 *
 * @param hapd     The hostapd data structure to be looked for.
 * @param ssid     The SSID to be looked for.
 * @param ssid_len The length of the given SSID.
 * @return id >= 0 of the BSS in our array if found
 *         -1 else
 */
static int set_free_bss_id(const struct hostapd_data *const hapd, const u8 *const ssid, const u8 ssid_len)
{
    unsigned int i;

    for (i = 0; i < PWIFI_MAX_BSS_COUNT; i++) {
        /* find first free slot */
        if (!bss_data[i].active && i < PWIFI_MAX_BSS_COUNT) {
            free_bss_id = i;
            return 1;
        }
    }

    return 0;
}

static int check_bss_id(const struct hostapd_data *const hapd, const u8 *const ssid, const u8 ssid_len)
{
    unsigned int i;

    for (i = 0; i < PWIFI_MAX_BSS_COUNT; i++) {
        /* check for the requested SSID */
        if (bss_data[i].active && ssid && bss_data[i].ssid_len == ssid_len  && os_memcmp(ssid, bss_data[i].ssid, ssid_len) == 0) {
            return i;
        }
    }

    return -1;
}

static int check_hapd_id(const struct hostapd_data *const hapd, const u8 *const ssid, const u8 ssid_len)
{
    unsigned int i;

    for (i = 0; i < PWIFI_MAX_BSS_COUNT; i++) {
        /* check for the requested SSID */
    	if (bss_data[i].active && bss_data[i].hapd == hapd) {
    		return i;
    	}

    }

    return -1;
}

/**
 * Connect to the backend socket and send the given message.
 *
 * @param msg The message to be transmitted.
 * @return  0 on success
 *         -1 on error
 */
static int send_to_backend(const char *const msg)
{
    int  sent_request = 0, retries = PWIFI_IPC_RETRIES;

    /* When listener is restarted the connected socket is not valid anymore. In
     * this case reconnect it to be able to send the request. */
    while (!sent_request && retries >= 0) {
        if (!sockfd_listener) {
            if ((sockfd_listener = pwifi_connect_socket(PWIFI_LISTENER_INTERFACE)) == -1) {
                wpa_printf(MSG_ERROR, "Failed to connect to listener socket.");
                sockfd_listener = 0;
            }
        }

        if (pwifi_send_msg(sockfd_listener, msg, os_strlen(msg)) == -1) {
            wpa_printf(MSG_DEBUG, "Failed to send request. Reconnecting socket.");
            close(sockfd_listener);
            sockfd_listener = 0;
            retries--;
        } else {
            sent_request = 1;
        }
    }

    if (sent_request) {
        return 0;
    } else {
        return -1;
    }
}

/**
 * Remove a BSS if no station is left connected.
 *
 * @param hapd The hapd data of the BSS.
 *
 * @return  0 on success
 *         -1 on error
 */
static int handle_bss_removal(struct hostapd_data *hapd)
{
    unsigned int bss_id;
    char msg[MAXBUFLEN] = { 0 };
    char *source_address_a;
    u8 sa[6] = { 0 };

    if (!hapd) {
        return -1;
    }

    if (hapd->num_sta > 0) {
        wpa_printf(MSG_DEBUG, "Still stations left associated. Not tearing down BSS.");
        return 0;
    }

    bss_id = check_hapd_id(hapd, NULL, 0);
    if (bss_id == -1) {
        wpa_printf(MSG_DEBUG, "We do not have that BSS.");
        return 0;
    }

    eloop_cancel_timeout(pwifi_handle_sta_timeout, bss_data[bss_id].hapd, NULL);

    /*Find the Source Address of the Client of that particular network.
     *
     */    
    if(hapd->sta_list) { //this should give us the last responsible station since we only have one per network!
    	os_memcpy(sa,hapd->sta_list->addr,6);
    }
    source_address_a = ether_ntoa(((struct ether_addr *) &sa[0]));
    /* The service backend should shut down any running services when hostapd
     * diestablishes a BSS. Therefore sent it a notification. */
    sprintf(msg, "%s %s %.*s", PWIFI_IPC_DISBAND, source_address_a, bss_data[bss_id].ssid_len, bss_data[bss_id].ssid);
    send_to_backend(msg);

    hostapd_free_stas(hapd);
    hostapd_flush_old_stations(hapd, WLAN_REASON_UNSPECIFIED);
    hostapd_cleanup(hapd);
    /* remove BSS, flush stations and memory and uninitialize our internal array slot */
    if (remove_bss(bss_id) == -1) {
        wpa_printf(MSG_ERROR, "Failed to remove BSS.");
        return -1;
    }
    os_free(bss_data[bss_id].hapd);
    os_memset(&bss_data[bss_id], 0, sizeof(struct pwifi_bss_data));
    return 0;
}

/**
 * Insert a pwifi client IP assignment Information Element into the given buffer.
 *
 * @param pos    The current position on the buffer.
 * @param len    The remaining length of the buffer.
 * @param bss_id The id of the active BSS in our bss_data array.
 * @param sa     MAC address of the station which requires an assignment.
 *
 * @return The updated position on the buffer.
 */
static u8 *insert_ip_ie(u8 *pos, size_t len, unsigned int bss_id, const u8 sa[ETH_ALEN])
{
    char addr[MAXBUFLEN] = { 0 };
    unsigned int station, addr_len, first_free = PWIFI_MAX_STA;
    struct ip_assignment *ip;

    /* Get next free IP address to assign it to the connecting client. */
    for (station = 0; station < PWIFI_MAX_STA; station++) {
        ip = &bss_data[bss_id].assigned_ips[station];
        if (ip->is_assigned && !os_memcmp(ip->sta_addr, sa, ETH_ALEN)) {
            break;
        } else if (!ip->is_assigned && first_free == PWIFI_MAX_STA) {
            first_free = station;
        }
    }
    /* If the station did not receive an assignment yet, assign the first free
     * IP address. */
    if (station >= PWIFI_MAX_STA && first_free < PWIFI_MAX_STA) {
        station = first_free;
    }
    if (station >= PWIFI_MAX_STA) {
        wpa_printf(MSG_ERROR, "No free IP addresses left.");
        return pos;
    }

    ip = &bss_data[bss_id].assigned_ips[station];
    os_memcpy(ip->sta_addr, sa, ETH_ALEN);
    ip->is_assigned = 1;
    sprintf(addr, "10.0.%d.%d/24", bss_id, station);
    addr_len = os_strlen(addr);
    wpa_printf(MSG_DEBUG, "Inserting IP address assignment '%s' in PRES.", addr);

    *pos++ = PWIFI_EID_IP;
    *pos++ = addr_len;

    os_memcpy(pos, addr, addr_len);
    return pos + addr_len;
}

/**
 * Insert a pwifi password or psk info Information Element into the given buffer.
 *
 * The password or psk is copied from its respective entry in the bss_data array.
 *
 * @param pos    The current position on the buffer.
 * @param len    The remaining length of the buffer.
 * @param bss_id The id of the active BSS in our bss_data array.
 *
 * @return The updated position on the buffer.
 */
static u8 *insert_pwd_or_psk_ie(u8 *pos, size_t len, unsigned int bss_id)
{
    unsigned int pwd_len = 0;

    if (bss_data[bss_id].password_is_psk) {
        *pos++  = PWIFI_EID_PSK;
        pwd_len = PMK_LEN;
        wpa_printf(MSG_DEBUG, "Inserting binary PSK into PRES.");
    } else {
        *pos++  = PWIFI_EID_PWD;
        pwd_len = os_strlen(bss_data[bss_id].password.string) + 1;
    }

    *pos++ = pwd_len;
    os_memcpy(pos, bss_data[bss_id].password.binary, pwd_len);
    wpa_printf(MSG_ERROR, "So-fi error: Sending PSK: %s", bss_data[bss_id].password.binary );
    return pos + pwd_len;
}

/**
 * Insert a pwifi URL info Information Element into the given buffer.
 *
 * @param pos    The current position on the buffer.
 * @param len    The remaining length of the buffer.
 * @param bss_id The id of the active BSS in our bss_data array.
 *
 * @return The updated position on the buffer.
 */
static u8 *insert_app_ie(u8 *pos, size_t len, unsigned int bss_id)
{
    u8 *ie_url;

    if (!(ie_url = get_ie_after_pos(bss_data[bss_id].service_data,
                                    bss_data[bss_id].service_data_len,
                                    PWIFI_EID_URL))) {
        wpa_printf(MSG_DEBUG, "No pwifi URL info in buffer.");
        return pos;
    }

    wpa_printf(MSG_DEBUG, "Inserting URL IE '%s' in PRES.", ie_url + 2);
    /* Length in TLV does not include the ID and length itself, therefore + 2. */
    os_memcpy(pos, ie_url, ie_url[1]+2);
    return pos + ie_url[1]+2;
}

/**
 * Insert a pwifi load info Information Element into the given buffer.
 *
 * @param pos    The current position on the buffer.
 * @param len    The remaining length of the buffer.
 * @param bss_id The id of the active BSS in our bss_data array.
 *
 * @return The updated position on the buffer.
 */
static u8 *insert_load_ie(u8 *pos, size_t len, unsigned int bss_id)
{
    *pos++ = PWIFI_EID_LOAD;
    *pos++ = 1; /* currently load is only a single Byte with # connected STAs */
    *pos++ = bss_data[bss_id].hapd->num_sta;
    return pos;
}

/**
 * Check whether the requested service is offered by us.
 * Additional information from the listener will be copied to the provided
 * reply buffer.
 *
 * @param ssid          The SSID given with the request.
 * @param ssid_len      The length of the SSID.
 * @param service_reply Destination buffer for additional information provided
 *                      from the service backend.
 * @return 1 service is available
 *         0 service is not available
 */
static int check_service_request(const u8 *const ssid, const u8 ssid_len,
                                 u8 *const service_reply, u8 *const sa)
{
    char request[MAXBUFLEN] = { 0 };
    char *source_address_a;

    wpa_printf(MSG_DEBUG, "Handling service request.");

    if (!sockfd_hostapd) {
        if ((sockfd_hostapd = pwifi_bind_socket(PWIFI_HOSTAPD_INTERFACE)) == -1) {
            wpa_printf(MSG_ERROR, "Failed to bind hostapd socket.");
            sockfd_hostapd = 0;
            return 0;
        }
    }

    /* Pass the request as well as the interface to the listener as it does
     * not know on which interface the service will be provided, only the port. */
    source_address_a = ether_ntoa(((struct ether_addr *) &sa[0]));
    sprintf(request, "%s %s 10.0.%d.1 %.*s", PWIFI_IPC_REQUEST, source_address_a, free_bss_id, ssid_len, ssid);

    if (send_to_backend(request) == -1) {
        return 0;
    }
    os_memset(request, 0, MAXBUFLEN);

    wpa_printf(MSG_DEBUG, "Waiting for an answer...");
    if (pwifi_recv_msg(sockfd_hostapd, request, MAXBUFLEN) == -1) {
        wpa_printf(MSG_DEBUG, "No answer from service backend.");
        return 0;
    }

    wpa_printf(MSG_DEBUG, "Received answer: %s", request);
    if (os_strncmp(request, PWIFI_IPC_ACK, PWIFI_IPC_ACK_LEN) == 0) {
        if (service_reply) {
            os_memcpy(service_reply, request + PWIFI_IPC_ACK_LEN,
                      MAXBUFLEN - PWIFI_IPC_ACK_LEN);
        }
        return 1;
    }
    if (os_strncmp(request, PWIFI_IPC_PACK, PWIFI_IPC_PACK_LEN) == 0) {
    	if(service_reply) {
    		os_memcpy(service_reply, request + PWIFI_IPC_PACK_LEN, MAXBUFLEN - PWIFI_IPC_PACK_LEN);
    	}
    	return 2;
    }
    if (os_strncmp(request, PWIFI_IPC_NACK, PWIFI_IPC_NACK_LEN) == 0) {
        return 0;
    }

    return 0;
}

/**
 * Handle a Personal Wi-Fi probe request.
 * If the incoming PREQ is pwifi encoded we set up a BSS and return the newly
 * created hapd data. If the BSS is already set up or the SSID is invalid or
 * we do not have any free slots for BSSs anymore we return the given hapd data.
 *
 * @param hapd     The BSS data on which the PREQ came in.
 * @param ssid     SSID given with the request.
 * @param ssid_len Length of the given SSID.
 *
 * @return  link to newly created BSS data if a new BSS was set up
 *          the given hapd else
 */
struct hostapd_data *pwifi_handle_probe_request(struct hostapd_data *const hapd, const u8 *const ssid, const u8 ssid_len, const u8 *const source_address)
{
    char ifname[IFNAMSIZ] = { 0 };
    u8   service_reply[MAXBUFLEN] = { 0 };
    struct hostapd_data *new_bss;
    struct os_time preq_timer, service_req_timer;
    u8 sa[6] = { 0 };
    int sr_eval = 0;
    u8 *ie;

    //Copy source address to sa buffer to not loose the address on teardown.
    os_memcpy(sa,source_address,6);
    /* We need to fit the SSID and an additional character for null-termination. */
    char bss_name[HOSTAPD_MAX_SSID_LEN + 1] = { 0 };

    if (!pwifi_ssid_is_pwifi_encoded(ssid, ssid_len)) {
        return hapd;
    }

    if (check_bss_id(hapd, ssid, ssid_len) >= 0) {
        wpa_printf(MSG_DEBUG, "pwifi: BSS %.*s already active.", ssid_len, ssid);
        return hapd;
    }

    if(set_free_bss_id(hapd,ssid,ssid_len) == 0) {
    	wpa_printf(MSG_DEBUG, "pwifi error: found no free slot for BSS generation.");
    }

    if (free_bss_id >= PWIFI_MAX_BSS_COUNT) {
            wpa_printf(MSG_ERROR, "pwifi error: found no free slot for BSS generation.");
            return hapd;
    }

    wpa_printf(MSG_ERROR, "Handling pwifi request.");
    pwifi_start_timer(&preq_timer, NULL);



    pwifi_start_timer(&service_req_timer, NULL);
    sr_eval = check_service_request(ssid, ssid_len, service_reply, sa);
    if (sr_eval == 1) {
		/* Service reply is packed in a pwifi TLV. We only copy the payload data. */
		bss_data[free_bss_id].service_data_len = service_reply[1];
		os_memcpy(bss_data[free_bss_id].service_data, service_reply + 2, bss_data[free_bss_id].service_data_len);
		pwifi_elapsed_time(&service_req_timer, "pwifi service request time:");

		/* if we got here everything is alright, set up interface with given input */
	    if ((ie = get_ie_after_pos(bss_data[free_bss_id].service_data, bss_data[free_bss_id].service_data_len, PWIFI_EID_SSID))) {
	        sprintf(bss_name,"%.*s", ie[1], &ie[2]);
	    }else{
	    	sprintf(bss_name, "%.*s", ssid_len, ssid);
	    }
	    sprintf(ifname, "wlan0_%d", free_bss_id);
		wpa_printf(MSG_DEBUG, "pwifi: Adding BSS %s on interface %s.", bss_name, ifname);
		add_bss(free_bss_id, ifname, bss_name, &sa[0]);
		bss_data[free_bss_id].active = 1;
		new_bss = bss_data[free_bss_id].hapd;
		eloop_register_timeout(PWIFI_BSS_TIMEOUT, 0, pwifi_handle_sta_timeout, new_bss, NULL);
		free_bss_id = PWIFI_MAX_BSS_COUNT;

		pwifi_elapsed_time(&preq_timer, "pwifi PREQ handler time:");

		return new_bss;
    }else if(sr_eval == 2){
    	os_memcpy(bss_name, service_reply + PWIFI_IPC_PACK_LEN + 2, HOSTAPD_MAX_SSID_LEN);
    	pwifi_handle_offbandSending(hapd,(const u8 *const)bss_name,HOSTAPD_MAX_SSID_LEN,&sa[0]);
    	pwifi_elapsed_time(&service_req_timer, "pwifi service request time:");
    	pwifi_elapsed_time(&preq_timer, "pwifi PREQ handler time:");
    	return hapd;
    }else{
    	wpa_printf(MSG_DEBUG, "pwifi: We do not offer the requested service.");
    	return hapd;
    }
}




/**
 * Handle a deauthentication notice and tear down the respective interface if no
 * station is left connected.
 *
 * @param hapd The BSS from which the station deauthenticates.
 * @return  0 on success
 *         -1 on error
 */
int pwifi_handle_deauth(struct hostapd_data *hapd)
{
    wpa_printf(MSG_DEBUG, "Handling deauthentication.");

    return handle_bss_removal(hapd);
}

/**
 * Handle the insertion of Information Elements in a probe response.
 *
 * @param pos      Current buffer position of the probe response.
 * @param len      Remaining buffer length available in the probe response.
 * @param ssid     SSID of the probe request.
 * @param ssid_len Length of the SSID.
 * @param sa       MAC address of the station which sent the probe request.
 * @return Updated position of probe response buffer.
 */
u8 * pwifi_handle_ie_insertion(u8 *pos, size_t len, const u8 *const ssid, const u8 ssid_len, const u8 sa[ETH_ALEN])
{
    u8 *ie_len, *pwifi_ie;
    size_t remaining_len;
    int bss_id;

    /* only native clients can actually read our IEs */
    //if (!pwifi_is_native_client(ssid, ssid_len)) {
    //    return pos;
    //}
    if(!pwifi_ssid_is_pwifi_encoded(ssid,ssid_len)){
    	return pos;
    }

    if ((bss_id = check_bss_id(NULL, ssid, ssid_len)) == -1) {
        wpa_printf(MSG_ERROR, "BSS for SSID %.*s not found.", ssid_len, ssid);
        return pos;
    }

    /* Information Element structure:
     * Element ID + Length + Payload
     * 1 Byte | 1 Byte | Number of Bytes specified in Length field */

    *pos++ = PWIFI_EID;
    ie_len = pos;
    pos++;
    pwifi_ie = pos;
    /* IP assignment is first field after EID and length -> len - 2 */
    remaining_len = len - 2;
    /* LOAD IE is always inserted as it is used by the client to skip full
     * networks. */
    pos = insert_load_ie(pos, remaining_len, bss_id);

    remaining_len = pos - pwifi_ie;
    pos = insert_ip_ie(pos, remaining_len, bss_id, sa);

    //remaining_len = pos - pwifi_ie;
    //pos = insert_pwd_or_psk_ie(pos, remaining_len, bss_id);
    remaining_len = pos - pwifi_ie;
    pos = insert_app_ie(pos, remaining_len, bss_id);

    *ie_len = pos - pwifi_ie;

    wpa_hexdump(MSG_MSGDUMP, "pwifi IEs in PRES: ", pwifi_ie, pos - pwifi_ie);

    return pos;
}

/**
 * Handle the timeout of a station in one of our BSSs.
 * If the station was the last connected one the BSS is teared down.
 *
 * Provide the BSS hapd data in the first parameter. The function signature
 * has to be this way to be able to use it with the eloop timeout functionality.
 *
 * @param eloop_ctx   The respective BSS data structure.
 * @param timeout_ctx UNUSED
 */
void pwifi_handle_sta_timeout(void *eloop_ctx, void *timeout_ctx)
{
    struct hostapd_data *hapd = eloop_ctx;

    wpa_printf(MSG_DEBUG, "Handling station timeout.");
    handle_bss_removal(hapd);
}

/**
 * Set the pointer for the internal interfaces data structure.
 *
 * @param interface The interface structure for all interface configuration.
 */
void pwifi_set_interfaces(struct hapd_interfaces *const interface)
{
    interfaces = interface;
}
