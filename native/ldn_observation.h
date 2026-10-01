// Recognize the public LDN advertisement header. No cryptographic validation.
// Wire reference: https://github.com/kinnay/LDN/blob/master/ldn/__init__.py
#ifndef FRLG_LDN_OBSERVATION_H
#define FRLG_LDN_OBSERVATION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Observed in a hosted FireRed session on the user's Switch 2 (2026-10-01).
// A communication ID does not establish the game's language or authenticate it.
#define FRLG_COMMUNICATION_ID UINT64_C(0x01006fa0233f8000)

typedef struct {
    bool management;
    bool action;
    bool beacon;
    bool probe_request;
    bool probe_response;
    bool ldn_header;
    uint64_t communication_id;
} LDNObservation;

// Return a bounded 802.11 view, stripping only the capture metadata.
static inline bool wifi_frame_view(const uint8_t **packet, size_t *size, bool radiotap) {
    if (radiotap) {
        if (*size < 8 || (*packet)[0] != 0) return false;
        size_t length = (*packet)[2] | ((size_t)(*packet)[3] << 8);
        if (length < 8 || length > *size) return false;
        *packet += length; *size -= length;
    }
    return *size >= 24;
}

// An echo observed on the sending interface is not over-the-air evidence.
// Match the complete body and addresses, tolerating only sequence/duration
// changes. This counter deliberately does not guess at rewritten addresses.
static inline bool observed_probe_request_echo(const uint8_t *packet, size_t size,
        bool radiotap, const uint8_t *request, size_t request_size) {
    if (!wifi_frame_view(&packet, &size, radiotap) || request_size < 24 || size < request_size)
        return false;
    return packet[0] == 0x40 && (packet[1] & 0xc7) == 0 &&
        !memcmp(packet + 4, request + 4, 18) &&
        !memcmp(packet + 24, request + 24, request_size - 24);
}

static inline bool observed_probe_response(const uint8_t *packet, size_t size,
        bool radiotap, const uint8_t destination[6]) {
    if (!wifi_frame_view(&packet, &size, radiotap)) return false;
    // Probe responses have a 24-byte MAC header and 12 fixed body bytes.
    // Match the random source used only by this experiment, never local echoes
    // of the transmitted request (which has a different subtype).
    return size >= 36 && packet[0] == 0x50 && (packet[1] & 0xc7) == 0 &&
        (packet[22] & 0x0f) == 0 && !memcmp(packet + 4, destination, 6);
}

static inline LDNObservation observe_ldn(const uint8_t *packet, size_t size, bool radiotap) {
    LDNObservation result = {0};
    if (!wifi_frame_view(&packet, &size, radiotap) || (packet[0] & 0x0f) != 0) return result;
    result.management = true;
    result.beacon = (packet[0] & 0xf0) == 0x80;
    result.probe_request = (packet[0] & 0xf0) == 0x40;
    result.probe_response = (packet[0] & 0xf0) == 0x50;
    if ((packet[0] & 0xf0) != 0xd0) return result;
    result.action = true;
    // Ignore encrypted or fragmented management bodies; they aren't headers.
    if ((packet[1] & 0x44) || (packet[22] & 0x0f)) return result;
    size_t header = (packet[1] & 0x80) ? 28 : 24; // optional HT Control
    if (size < header + 52) return result;
    const uint8_t *body = packet + header;
    const uint8_t prefix[] = {0x7f, 0x00, 0x22, 0xaa, 0x04, 0x00, 0x01, 0x01};
    if (memcmp(body, prefix, sizeof(prefix))) return result;
    if (body[44] < 2 || body[44] > 4 || body[45] < 1 || body[45] > 3) return result;
    result.ldn_header = true;
    for (unsigned i = 0; i < 8; ++i)
        result.communication_id = (result.communication_id << 8) | body[12 + i];
    return result;
}
#endif
