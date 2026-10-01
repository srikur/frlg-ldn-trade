// Exercise report ownership across the listener's autorelease-pool boundary.
// Uses only a synthetic offline capture; no root access or radio changes.
#define main macos_listener_main
#include "../native/macos_listen.m"
#undef main
#include <assert.h>

int main(void) {
    @autoreleasepool {
        char path[] = "/tmp/frlg-listen-test-XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);
        close(fd);
        pcap_t *dead = pcap_open_dead(DLT_IEEE802_11_RADIO, 256);
        assert(dead);
        pcap_dumper_t *dump = pcap_dump_open(dead, path);
        assert(dump);
        // Public FRLG advertisement header, not an authenticated LDN packet.
        uint8_t frame[84] = {0};
        frame[2] = 8;
        frame[8] = 0xd0;
        const uint8_t prefix[] = {0x7f, 0, 0x22, 0xaa, 4, 0, 1, 1};
        const uint8_t game[] = {1, 0, 0x61, 0, 0x11, 0, 0, 0};
        memcpy(frame + 32, prefix, sizeof(prefix));
        memcpy(frame + 44, game, sizeof(game));
        frame[76] = 3;
        frame[77] = 3;
        struct pcap_pkthdr header = {.caplen = sizeof(frame), .len = sizeof(frame)};
        pcap_dump((u_char *)dump, &header, frame);
        pcap_dump_close(dump);
        pcap_close(dead);

        const char *args[] = {"macos-listen", "--offline", path};
        NSMutableArray *reports = [NSMutableArray array];
        for (unsigned i = 0; i < 3; ++i) {
            NSDictionary *report = nil;
            // Like the sweep, retain a report after listenOnce's pool drains.
            int status = listenOnce(3, args, &report);
            assert(status == 0 && report);
            [reports addObject:report];
        }
        unlink(path);
        for (NSDictionary *report in reports) {
            assert([report[@"mode"] isEqualToString:@"offline"]);
            assert([report[@"packets_examined"] unsignedLongLongValue] == 1);
            assert([report[@"frlg_header_candidates"] unsignedLongLongValue] == 1);
            assert([report[@"communication_id_counts"][@"0x0100610011000000"] unsignedLongLongValue] == 1);
            assert(![report[@"transmission_tested"] boolValue]);
        }
        // Check that nested dictionaries survive and remain serializable too.
        NSData *json = [NSJSONSerialization dataWithJSONObject:reports options:0 error:nil];
        assert(json.length > 0);
        puts("macOS listener: three offline reports survive capture autorelease pools and serialize.");
    }
    return 0;
}
