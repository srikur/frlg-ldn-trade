#include "../native/auth_frame.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    const uint8_t source[6] = {2, 1, 2, 3, 4, 5};
    const uint8_t peer[6] = {2, 6, 7, 8, 9, 10};
    uint8_t request[AUTH_REQUEST_SIZE];
    build_auth_request(request, source, peer, 0xabc);
    assert(sizeof(request) == 38 && request[2] == 8 && request[8] == 0xb0 && request[9] == 0);
    assert(!memcmp(request + 12, peer, 6) && !memcmp(request + 18, source, 6));
    assert(!memcmp(request + 24, peer, 6));
    assert(request[30] == 0xc0 && request[31] == 0xab);
    const uint8_t body[] = {0, 0, 1, 0, 0, 0};
    assert(!memcmp(request + 32, body, sizeof(body)));
    uint16_t status = 0xffff;
    assert(!observed_auth_response(request, sizeof(request), true, source, peer, &status));

    uint8_t response[38] = {0};
    response[2] = 8; response[8] = 0xb0;
    memcpy(response + 12, source, 6);
    memcpy(response + 18, peer, 6);
    memcpy(response + 24, peer, 6);
    response[34] = 2;
    assert(observed_auth_response(response, sizeof(response), true, source, peer, &status) && status == 0);
    assert(observed_auth_response(response + 8, 30, false, source, peer, &status));
    for (size_t i = 0; i < sizeof(response); ++i)
        assert(!observed_auth_response(response, i, true, source, peer, &status));
    response[36] = 17;
    assert(observed_auth_response(response, sizeof(response), true, source, peer, &status) && status == 17);
    response[37] = 1;
    assert(observed_auth_response(response, sizeof(response), true, source, peer, &status) && status == 273);
    const size_t invalid[] = {8, 12, 18, 24, 30, 32, 33, 34, 35};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        response[invalid[i]] ^= 1;
        assert(!observed_auth_response(response, sizeof(response), true, source, peer, &status));
        response[invalid[i]] ^= 1;
    }
    for (unsigned flags = 1; flags <= 128; flags <<= 1) {
        response[9] = flags;
        bool invalidFlags = (flags & 0xc7) != 0;
        assert(observed_auth_response(response, sizeof(response), true, source, peer, &status) != invalidFlags);
    }

    uint8_t advert[84] = {0}, selected[6] = {0};
    advert[2] = 8; advert[8] = 0xd0;
    memset(advert + 12, 255, 6);
    memcpy(advert + 18, peer, 6); memset(advert + 24, 255, 6);
    const uint8_t prefix[] = {0x7f, 0, 0x22, 0xaa, 4, 0, 1, 1};
    const uint8_t commID[] = {1, 0, 0x6f, 0xa0, 0x23, 0x3f, 0x80, 0};
    memcpy(advert + 32, prefix, sizeof(prefix));
    memcpy(advert + 44, commID, sizeof(commID));
    advert[76] = 3; advert[77] = 3;
    assert(observed_ldn_peer(advert, sizeof(advert), true, UINT64_C(0x01006fa0233f8000), selected));
    assert(!memcmp(selected, peer, 6));
    memcpy(advert + 24, peer, 6);
    assert(observed_ldn_peer(advert, sizeof(advert), true, FRLG_COMMUNICATION_ID, selected));
    memset(advert + 24, 255, 6);
    assert(!observed_ldn_peer(advert, sizeof(advert), true, UINT64_C(0x0100610011000000), selected));
    for (size_t i = 0; i < sizeof(advert); ++i)
        assert(!observed_ldn_peer(advert, i, true, FRLG_COMMUNICATION_ID, selected));
    advert[24] ^= 2;
    assert(!observed_ldn_peer(advert, sizeof(advert), true, FRLG_COMMUNICATION_ID, selected));
    advert[24] ^= 2;
    advert[12] = 0;
    assert(!observed_ldn_peer(advert, sizeof(advert), true, FRLG_COMMUNICATION_ID, selected));
    advert[12] = 255;
    advert[18] |= 1; advert[24] |= 1;
    assert(!observed_ldn_peer(advert, sizeof(advert), true, FRLG_COMMUNICATION_ID, selected));
    puts("Authentication frame: construction, peer selection, bounds, matching, rejection status and echo exclusions passed.");
}
