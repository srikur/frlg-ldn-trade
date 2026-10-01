#ifndef FRLG_PROBE_FRAME_H
#define FRLG_PROBE_FRAME_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum { PROBE_REQUEST_SIZE = 44, PROBE_RADIOTAP_SIZE = 8 };

// An empty radiotap header, broadcast management header, zero-length SSID IE,
// and supported rates. Source is provided by the caller, not hardcoded/spoofed
// as another device. A 12-bit sequence avoids a constant-zero sequence.
static inline void build_probe_request(uint8_t request[PROBE_REQUEST_SIZE],
        const uint8_t source[6], uint16_t sequence) {
    memset(request, 0, PROBE_REQUEST_SIZE);
    request[2] = PROBE_RADIOTAP_SIZE;
    request[8] = 0x40;
    memset(request + 12, 0xff, 6);
    memset(request + 24, 0xff, 6);
    memcpy(request + 18, source, 6);
    uint16_t control = (uint16_t)((sequence & 0xfff) << 4);
    request[30] = (uint8_t)control;
    request[31] = (uint8_t)(control >> 8);
    const uint8_t rates[] = {1, 8, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    memcpy(request + 34, rates, sizeof(rates));
}
#endif
