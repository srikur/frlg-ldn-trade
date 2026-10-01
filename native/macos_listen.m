// Bounded passive reception experiment. Monitor mode may interrupt normal Wi-Fi.
// Optional --channel disconnects Wi-Fi and selects a supported 2.4 GHz channel.
// --probe-request explicitly sends one ordinary wildcard Wi-Fi probe request.
// Otherwise reception only. No decryption, keys, or packet-file output.
#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
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
    fprintf(out, "Usage: macos-listen [--interface en0] [--seconds 15] [--all-frames] [--channel 6] [--probe-request]\n"
        "       macos-listen --offline file.pcap\n"
        "Live mode enables promiscuous monitor capture for 1-60 seconds.\n"
        "It may interrupt ordinary Wi-Fi. --channel explicitly disconnects first\n"
        "and tunes to a supported 2.4 GHz channel. Reconnect Wi-Fi afterward.\n"
        "--all-frames counts all frame types instead of filtering for management.\n"
        "--probe-request sends ONE wildcard probe request and counts matching replies.\n"
        "Only aggregate counts and public game IDs are printed; no packets saved.\n");
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        const char *interface = "en0", *offline = NULL;
        double seconds = 15;
        NSInteger requestedChannel = 0;
        BOOL allFrames = NO;
        BOOL probeRequest = NO;
        BOOL liveOption = NO;
        for (int i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "--interface") && i + 1 < argc) {
                interface = argv[++i]; liveOption = YES;
            } else if (!strcmp(argv[i], "--all-frames")) {
                allFrames = YES; liveOption = YES;
            } else if (!strcmp(argv[i], "--probe-request")) {
                probeRequest = YES; liveOption = YES;
            } else if (!strcmp(argv[i], "--channel") && i + 1 < argc) {
                char *end = NULL;
                requestedChannel = strtol(argv[++i], &end, 10); liveOption = YES;
                if (!*argv[i] || *end || requestedChannel < 1 || requestedChannel > 14) {
                    usage(stderr); return 64;
                }
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
        CWInterface *wifi = nil;
        NSInteger channelBefore = 0, channelAtStart = 0;
        if (!offline) {
            // Check access before an explicit channel selection can disconnect Wi-Fi.
            int monitor = pcap_can_set_rfmon(handle);
            if (monitor != 1) {
                fprintf(stderr, "Monitor capability query returned %d: %s\n", monitor, pcap_geterr(handle));
                pcap_close(handle); return 2;
            }
            wifi = [[CWWiFiClient sharedWiFiClient] interfaceWithName:@(interface)];
            channelBefore = wifi.wlanChannel.channelNumber;
            if (requestedChannel) {
                CWChannel *selected = nil;
                for (CWChannel *channel in wifi.supportedWLANChannels)
                    if (channel.channelNumber == requestedChannel && channel.channelBand == kCWChannelBand2GHz) {
                        selected = channel; break;
                    }
                if (!selected) {
                    fprintf(stderr, "CoreWLAN did not report requested 2.4 GHz channel %ld.\n", (long)requestedChannel);
                    pcap_close(handle); return 2;
                }
                fprintf(stderr, "Disconnecting Wi-Fi to select 2.4 GHz channel %ld; reconnect afterward.\n", (long)requestedChannel);
                [wifi disassociate];
                NSError *channelError = nil;
                if (![wifi setWLANChannel:selected error:&channelError]) {
                    fprintf(stderr, "Channel selection failed: %s. Reconnect Wi-Fi manually.\n", channelError.localizedDescription.UTF8String);
                    pcap_close(handle); return 2;
                }
            }
            if (pcap_set_snaplen(handle, 256) || pcap_set_timeout(handle, 100) ||
                    pcap_set_promisc(handle, 1) || pcap_set_rfmon(handle, 1)) {
                fprintf(stderr, "Capture configuration: %s\n", pcap_geterr(handle));
                pcap_close(handle); return 2;
            }
            fprintf(stderr, "Enabling promiscuous monitor capture for %.0f seconds.\n", seconds);
            int code = pcap_activate(handle);
            if (code < 0) {
                fprintf(stderr, "Capture activation: %s\n", pcap_geterr(handle));
                pcap_close(handle); return 2;
            }
            if (code > 0) fprintf(stderr, "Capture warning: %s\n", pcap_statustostr(code));
            channelAtStart = wifi.wlanChannel.channelNumber;
        }
        int datalink = pcap_datalink(handle);
        if (datalink != DLT_IEEE802_11_RADIO && datalink != DLT_IEEE802_11) {
            fprintf(stderr, "Link type %d does not expose the required 802.11 frames.\n", datalink);
            pcap_close(handle); return 2;
        }
        if (!offline && !allFrames) {
            // Discard ordinary data traffic in BPF. Payloads are never logged.
            struct bpf_program filter;
            if (pcap_compile(handle, &filter, "type mgt", 1, PCAP_NETMASK_UNKNOWN) < 0) {
                fprintf(stderr, "Capture filter: %s\n", pcap_geterr(handle));
                pcap_close(handle); return 2;
            }
            int code = pcap_setfilter(handle, &filter);
            pcap_freecode(&filter);
            if (code < 0) {
                fprintf(stderr, "Capture filter: %s\n", pcap_geterr(handle));
                pcap_close(handle); return 2;
            }
        }
        if (!offline && pcap_setnonblock(handle, 1, error) < 0) {
            fprintf(stderr, "Nonblocking capture: %s\n", error);
            pcap_close(handle); return 2;
        }
        uint64_t packets = 0, management = 0, actions = 0, advertisements = 0, frlg = 0;
        uint64_t probeResponses = 0;
        uint8_t probeSource[6] = {0};
        int injectedBytes = 0;
        size_t injectionSize = 0;
        NSString *injectionError = @"";
        if (probeRequest) {
            // Radiotap (empty fields), broadcast probe request, wildcard SSID,
            // supported rates. A fresh local/unicast address distinguishes any
            // response from background scanning. No address is printed.
            uint8_t request[44] = {0};
            request[2] = 8;
            request[8] = 0x40;
            memset(request + 12, 0xff, 6);
            memset(request + 24, 0xff, 6);
            arc4random_buf(probeSource, sizeof(probeSource));
            probeSource[0] = (probeSource[0] & 0xfc) | 0x02;
            memcpy(request + 18, probeSource, 6);
            // Offsets 32/33 encode a zero-length SSID IE.
            const uint8_t rates[] = {1, 8, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
            memcpy(request + 34, rates, sizeof(rates));
            size_t offset = datalink == DLT_IEEE802_11_RADIO ? 0 : 8;
            injectionSize = sizeof(request) - offset;
            fprintf(stderr, "Sending one wildcard Wi-Fi probe request; a matching reply is required to confirm over-the-air transmission.\n");
            injectedBytes = pcap_inject(handle, request + offset, injectionSize);
            if (injectedBytes < 0) injectionError = @(pcap_geterr(handle));
        }
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
            if (probeRequest && observed_probe_response(packet, header->caplen,
                    datalink == DLT_IEEE802_11_RADIO, probeSource)) ++probeResponses;
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
        NSMutableDictionary *captureStats = [NSMutableDictionary dictionary];
        struct pcap_stat stats;
        if (!offline && pcap_stats(handle, &stats) == 0) {
            captureStats[@"received"] = @(stats.ps_recv);
            captureStats[@"dropped"] = @(stats.ps_drop);
            captureStats[@"interface_dropped"] = @(stats.ps_ifdrop);
        }
        pcap_close(handle); // Also on Ctrl-C/error: release the capture handle.
        NSDictionary *report = @{
            @"schema_version": @3,
            @"mode": offline ? @"offline" : probeRequest ? @"live_probe_request" : @"live_passive",
            @"filter": offline || allFrames ? @"none" : @"management",
            @"promiscuous_requested": @(!offline),
            @"requested_2ghz_channel": @(requestedChannel),
            @"channel_before": @(channelBefore), @"channel_at_start": @(channelAtStart),
            @"pcap_stats": captureStats,
            @"datalink": @(datalink), @"elapsed_seconds": @(elapsed),
            @"interrupted": @(interrupted != 0), @"read_error": @(failed),
            @"packets_examined": @(packets), @"management_frames": @(management),
            @"action_frames": @(actions), @"ldn_header_candidates": @(advertisements),
            @"frlg_header_candidates": @(frlg), @"communication_id_counts": gameIDs,
            @"transmission_tested": @(probeRequest), @"ldn_compatibility": @"unproven",
            @"probe_request": @{
                @"attempted": @(probeRequest), @"bytes_requested": @(injectionSize),
                @"write_result": @(injectedBytes), @"error": injectionError,
                @"matching_responses": @(probeResponses),
                @"interpretation": @"A matching response supports transmission of this management frame only. No response is inconclusive even if the write succeeds."
            },
            @"interpretation": @"Headers are unauthenticated. Zero matches can mean the wrong channel, no host, or no usable reception."
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:report
            options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
        if (!json) return 2;
        fwrite(json.bytes, 1, json.length, stdout); fputc('\n', stdout);
        return failed || injectedBytes < 0 ? 2 : 0;
    }
}
