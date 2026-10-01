// A single open-system 802.11 authentication exchange, not encrypted LDN auth.
// Wire reference: kinnay/LDN ldn/wlan.py AuthenticationFrame and STAInterface.
#ifndef FRLG_AUTH_FRAME_H
#define FRLG_AUTH_FRAME_H
#include "ldn_observation.h"

enum { AUTH_REQUEST_SIZE = 38, AUTH_RADIOTAP_SIZE = 8 };

// Select the requested public LDN ID and its unicast transmitter. LDN action
// advertisements use a broadcast BSSID (kinnay's ActionFrame.encode), unlike
// auth responses. Also accept a BSSID equal to the transmitter.
// The addresses stay in memory and are never printed.
static inline bool observed_ldn_peer(const uint8_t *packet, size_t size,
        bool radiotap, uint64_t communication_id, uint8_t peer[6]) {
    LDNObservation observed = observe_ldn(packet, size, radiotap);
    if (!observed.ldn_header || observed.communication_id != communication_id ||
            !wifi_frame_view(&packet, &size, radiotap)) return false;
    static const uint8_t zero[6] = {0};
    static const uint8_t broadcast[6] = {255, 255, 255, 255, 255, 255};
    if ((packet[1] & 3) || (packet[10] & 1) || !memcmp(packet + 10, zero, 6) ||
            memcmp(packet + 4, broadcast, 6) ||
            (memcmp(packet + 16, broadcast, 6) && memcmp(packet + 10, packet + 16, 6))) return false;
    memcpy(peer, packet + 10, 6);
    return true;
}

static inline void build_auth_request(uint8_t request[AUTH_REQUEST_SIZE],
        const uint8_t source[6], const uint8_t peer[6], uint16_t sequence) {
    memset(request, 0, AUTH_REQUEST_SIZE);
    request[2] = AUTH_RADIOTAP_SIZE;
    request[8] = 0xb0;
    memcpy(request + 12, peer, 6);
    memcpy(request + 18, source, 6);
    memcpy(request + 24, peer, 6);
    uint16_t control = (uint16_t)((sequence & 0xfff) << 4);
    request[30] = (uint8_t)control;
    request[31] = (uint8_t)(control >> 8);
    request[34] = 1; // algorithm 0, transaction 1, status 0; all little-endian
}

static inline bool observed_auth_response(const uint8_t *packet, size_t size,
        bool radiotap, const uint8_t source[6], const uint8_t peer[6], uint16_t *status) {
    if (!wifi_frame_view(&packet, &size, radiotap) || size < 30 ||
            packet[0] != 0xb0 || (packet[1] & 0xc7) || (packet[22] & 15) ||
            memcmp(packet + 4, source, 6) || memcmp(packet + 10, peer, 6) ||
            memcmp(packet + 16, peer, 6) || packet[24] || packet[25] ||
            packet[26] != 2 || packet[27]) return false;
    *status = packet[28] | ((uint16_t)packet[29] << 8);
    return true;
}
#endif
