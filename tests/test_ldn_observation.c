#include "../native/ldn_observation.h"
#include "../native/probe_frame.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    uint8_t frame[84] = {0}; // 8-byte radiotap + 24-byte MAC + 52-byte LDN header
    frame[2] = 8;
    frame[8] = 0xd0;
    const uint8_t prefix[] = {0x7f, 0, 0x22, 0xaa, 4, 0, 1, 1};
    memcpy(frame + 32, prefix, sizeof(prefix));
    const uint8_t game[] = {1, 0, 0x61, 0, 0x11, 0, 0, 0};
    memcpy(frame + 44, game, sizeof(game));
    frame[76] = 3; frame[77] = 3;
    LDNObservation result = observe_ldn(frame, sizeof(frame), true);
    assert(result.management && result.action && result.ldn_header);
    assert(result.communication_id == UINT64_C(0x0100610011000000));
    assert(observe_ldn(frame + 8, sizeof(frame) - 8, false).ldn_header);
    for (size_t i = 0; i < sizeof(frame); ++i)
        assert(!observe_ldn(frame, i, true).ldn_header);
    frame[2] = 7; assert(!observe_ldn(frame, sizeof(frame), true).ldn_header);
    frame[2] = 255; assert(!observe_ldn(frame, sizeof(frame), true).ldn_header);
    frame[2] = 8;
    frame[9] = 0x40; assert(!observe_ldn(frame, sizeof(frame), true).ldn_header);
    frame[9] = 4; assert(!observe_ldn(frame, sizeof(frame), true).ldn_header);
    frame[9] = 0;
    frame[30] = 1; assert(!observe_ldn(frame, sizeof(frame), true).ldn_header);
    frame[30] = 0;
    frame[8] = 0x80;
    result = observe_ldn(frame, sizeof(frame), true);
    assert(result.management && result.beacon && !result.action && !result.ldn_header);
    frame[8] = 8; assert(!observe_ldn(frame, sizeof(frame), true).management);
    frame[8] = 0xd0;
    frame[35] ^= 1; assert(!observe_ldn(frame, sizeof(frame), true).ldn_header);
    frame[35] ^= 1;
    frame[76] = 9; assert(!observe_ldn(frame, sizeof(frame), true).ldn_header);
    frame[76] = 3;
    frame[77] = 0; assert(!observe_ldn(frame, sizeof(frame), true).ldn_header);
    frame[77] = 3;
    // Header Control is four bytes when the Order bit is set.
    uint8_t ordered[88] = {0};
    memcpy(ordered, frame, 32);
    memcpy(ordered + 36, frame + 32, 52);
    ordered[9] = 0x80;
    assert(observe_ldn(ordered, sizeof(ordered), true).ldn_header);
    const uint8_t destination[] = {2, 4, 6, 8, 10, 12};
    uint8_t response[44] = {0};
    response[2] = 8; response[8] = 0x50;
    memcpy(response + 12, destination, 6);
    assert(observed_probe_response(response, sizeof(response), true, destination));
    assert(observed_probe_response(response + 8, sizeof(response) - 8, false, destination));
    for (size_t i = 0; i < sizeof(response); ++i)
        assert(!observed_probe_response(response, i, true, destination));
    response[8] = 0x40; // An outgoing request echo must never count as a reply.
    assert(!observed_probe_response(response, sizeof(response), true, destination));
    response[8] = 0x50; response[12] ^= 1;
    assert(!observed_probe_response(response, sizeof(response), true, destination));
    assert(observe_ldn(response, sizeof(response), true).probe_response);

    uint8_t request[PROBE_REQUEST_SIZE];
    build_probe_request(request, destination, 0xabc);
    assert(request[2] == 8 && request[3] == 0 && request[4] == 0);
    assert(request[8] == 0x40 && request[9] == 0);
    assert(!memcmp(request + 18, destination, 6));
    for (unsigned i = 0; i < 6; ++i) assert(request[12 + i] == 0xff && request[24 + i] == 0xff);
    assert(request[30] == 0xc0 && request[31] == 0xab);
    // Decode the information-element list independently of its construction.
    size_t cursor = 32;
    unsigned elements = 0;
    while (cursor < sizeof(request)) {
        assert(sizeof(request) - cursor >= 2);
        unsigned id = request[cursor], length = request[cursor + 1];
        assert(length <= sizeof(request) - cursor - 2);
        if (elements == 0) assert(id == 0 && length == 0); // wildcard SSID
        if (elements == 1) assert(id == 1 && length == 8); // supported rates
        cursor += 2 + length;
        ++elements;
    }
    assert(elements == 2 && cursor == sizeof(request));
    assert(observe_ldn(request, sizeof(request), true).probe_request);
    assert(!observe_ldn(request, sizeof(request), true).probe_response);
    assert(!observed_probe_response(request, sizeof(request), true, destination));
    uint8_t echoed[PROBE_REQUEST_SIZE];
    memcpy(echoed, request, sizeof(request));
    assert(observed_probe_request_echo(echoed, sizeof(echoed), true, request + 8, sizeof(request) - 8));
    for (size_t i = 0; i < sizeof(echoed); ++i)
        assert(!observed_probe_request_echo(echoed, i, true, request + 8, sizeof(request) - 8));
    echoed[31] ^= 1;
    assert(observed_probe_request_echo(echoed, sizeof(echoed), true, request + 8, sizeof(request) - 8));
    echoed[18] ^= 1;
    assert(!observed_probe_request_echo(echoed, sizeof(echoed), true, request + 8, sizeof(request) - 8));
    echoed[18] ^= 1; echoed[42] ^= 1;
    assert(!observed_probe_request_echo(echoed, sizeof(echoed), true, request + 8, sizeof(request) - 8));
    build_probe_request(request, destination, 0xffff);
    assert(request[30] == 0xf0 && request[31] == 0xff); // fragment stays zero
    puts("LDN observation parser: bounds, framing, identification, and exclusions passed.");
    return 0;
}
