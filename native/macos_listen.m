// Bounded passive reception experiment. Monitor mode may interrupt normal Wi-Fi.
// No scan/channel changes, injection, decryption, keys, or packet-file output.
#import <Foundation/Foundation.h>
#include <math.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "ldn_observation.h"

static volatile sig_atomic_t interrupted = 0;
static void stopListening(int signalNumber) { (void)signalNumber; interrupted = 1; }
static double now(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}
static void usage(FILE *out) {
    fprintf(out, "Usage: macos-listen [--interface en0] [--seconds 15]\n"
        "       macos-listen --offline file.pcap\n"
        "Live mode enables monitor capture on the current channel for 1-60 seconds.\n"
        "It may interrupt ordinary Wi-Fi. No channel changes or transmission.\n"
        "Only aggregate counts and public game IDs are printed; no packets saved.\n");
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        const char *interface = "en0", *offline = NULL;
        double seconds = 15;
        BOOL liveOption = NO;
        for (int i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "--interface") && i + 1 < argc) {
                interface = argv[++i]; liveOption = YES;
            } else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) {
                char *end = NULL;
                seconds = strtod(argv[++i], &end); liveOption = YES;
                if (!*argv[i] || *end || !isfinite(seconds) || seconds < 1 || seconds > 60) {
                    usage(stderr); return 64;
                }
            } else if (!strcmp(argv[i], "--offline") && i + 1 < argc) offline = argv[++i];
            else if (!strcmp(argv[i], "--help")) { usage(stdout); return 0; }
            else { usage(stderr); return 64; }
        }
        if ((offline && liveOption) || !*interface || strlen(interface) >= IFNAMSIZ) {
            usage(stderr); return 64;
        }
        for (const char *p = interface; *p; ++p)
            if (!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.", *p)) {
                usage(stderr); return 64;
            }
        signal(SIGINT, stopListening);
        signal(SIGTERM, stopListening);
        char error[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *handle = offline ? pcap_open_offline(offline, error) : pcap_create(interface, error);
        if (!handle) { fprintf(stderr, "%s\n", error); return 2; }
        if (!offline) {
            if (pcap_set_snaplen(handle, 256) || pcap_set_timeout(handle, 100) ||
                    pcap_set_rfmon(handle, 1)) {
                fprintf(stderr, "Capture configuration: %s\n", pcap_geterr(handle));
                pcap_close(handle); return 2;
            }
            fprintf(stderr, "Enabling monitor capture for %.0f seconds on the current channel.\n", seconds);
            int code = pcap_activate(handle);
            if (code < 0) {
                fprintf(stderr, "Capture activation: %s\n", pcap_geterr(handle));
                pcap_close(handle); return 2;
            }
            if (code > 0) fprintf(stderr, "Capture warning: %s\n", pcap_statustostr(code));
        }
        int datalink = pcap_datalink(handle);
        if (datalink != DLT_IEEE802_11_RADIO && datalink != DLT_IEEE802_11) {
            fprintf(stderr, "Link type %d does not expose the required 802.11 frames.\n", datalink);
            pcap_close(handle); return 2;
        }
        if (!offline) {
            // Discard ordinary data traffic in BPF. Payloads are never logged.
            struct bpf_program filter;
            if (pcap_compile(handle, &filter, "type mgt", 1, PCAP_NETMASK_UNKNOWN) < 0) {
                fprintf(stderr, "Capture filter: %s\n", pcap_geterr(handle));
                pcap_close(handle); return 2;
            }
            int code = pcap_setfilter(handle, &filter);
            pcap_freecode(&filter);
            if (code < 0 || pcap_setnonblock(handle, 1, error) < 0) {
                fprintf(stderr, "Capture setup: %s %s\n", pcap_geterr(handle), error);
                pcap_close(handle); return 2;
            }
        }
        uint64_t packets = 0, management = 0, actions = 0, advertisements = 0, frlg = 0;
        NSMutableDictionary *gameIDs = [NSMutableDictionary dictionary];
        double start = now();
        BOOL failed = NO;
        while (!interrupted && (offline || now() - start < seconds)) {
            struct pcap_pkthdr *header = NULL;
            const u_char *packet = NULL;
            int code = pcap_next_ex(handle, &header, &packet);
            if (code == PCAP_ERROR_BREAK) break;
            if (code < 0) { fprintf(stderr, "%s\n", pcap_geterr(handle)); failed = YES; break; }
            if (code == 0) { usleep(10000); continue; }
            ++packets;
            LDNObservation observed = observe_ldn(packet, header->caplen, datalink == DLT_IEEE802_11_RADIO);
            management += observed.management;
            actions += observed.action;
            if (observed.ldn_header) {
                ++advertisements;
                frlg += observed.communication_id == UINT64_C(0x0100610011000000);
                NSString *gameID = [NSString stringWithFormat:@"0x%016llx", (unsigned long long)observed.communication_id];
                if (gameIDs[gameID] || gameIDs.count < 64)
                    gameIDs[gameID] = @([gameIDs[gameID] unsignedLongLongValue] + 1);
            }
        }
        double elapsed = now() - start;
        pcap_close(handle); // Also on Ctrl-C/error: release the capture handle.
        NSDictionary *report = @{
            @"schema_version": @1,
            @"mode": offline ? @"offline" : @"live_passive",
            @"datalink": @(datalink), @"elapsed_seconds": @(elapsed),
            @"interrupted": @(interrupted != 0), @"read_error": @(failed),
            @"packets_examined": @(packets), @"management_frames": @(management),
            @"action_frames": @(actions), @"ldn_header_candidates": @(advertisements),
            @"frlg_header_candidates": @(frlg), @"communication_id_counts": gameIDs,
            @"transmission_tested": @NO, @"ldn_compatibility": @"unproven",
            @"interpretation": @"Headers are unauthenticated. Zero matches can mean the wrong channel, no host, or no usable reception."
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:report
            options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
        if (!json) return 2;
        fwrite(json.bytes, 1, json.length, stdout); fputc('\n', stdout);
        return failed ? 2 : 0;
    }
}
