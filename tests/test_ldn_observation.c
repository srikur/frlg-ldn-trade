#include "../native/ldn_observation.h"
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
    assert(result.management && !result.action && !result.ldn_header);
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
    puts("LDN observation parser: bounds, framing, identification, and exclusions passed.");
    return 0;
}
