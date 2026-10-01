// Recognize the public LDN advertisement header. No cryptographic validation.
// Wire reference: https://github.com/kinnay/LDN/blob/master/ldn/__init__.py
#ifndef FRLG_LDN_OBSERVATION_H
#define FRLG_LDN_OBSERVATION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    bool management;
    bool action;
    bool ldn_header;
    uint64_t communication_id;
} LDNObservation;

static inline bool observed_probe_response(const uint8_t *packet, size_t size,
        bool radiotap, const uint8_t destination[6]) {
    if (radiotap) {
        if (size < 8 || packet[0] != 0) return false;
        size_t length = packet[2] | ((size_t)packet[3] << 8);
        if (length < 8 || length > size) return false;
        packet += length; size -= length;
    }
    // Probe responses have a 24-byte MAC header and 12 fixed body bytes.
    // Match the random source used only by this experiment, never local echoes
    // of the transmitted request (which has a different subtype).
    return size >= 36 && packet[0] == 0x50 && (packet[1] & 0xc7) == 0 &&
        (packet[22] & 0x0f) == 0 && !memcmp(packet + 4, destination, 6);
}

static inline LDNObservation observe_ldn(const uint8_t *packet, size_t size, bool radiotap) {
    LDNObservation result = {0};
    if (radiotap) {
        if (size < 8 || packet[0] != 0) return result;
        size_t length = packet[2] | ((size_t)packet[3] << 8);
        if (length < 8 || length > size) return result;
        packet += length;
        size -= length;
    }
    if (size < 24 || (packet[0] & 0x0f) != 0) return result;
    result.management = true;
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
