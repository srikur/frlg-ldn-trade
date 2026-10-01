// Bounded passive reception experiment. Monitor mode may interrupt normal Wi-Fi.
// Optional --channel disconnects Wi-Fi and selects a supported 2.4 GHz channel.
// --probe-request explicitly sends one ordinary wildcard Wi-Fi probe request.
// --auth-request sends one open-system auth request to a selected LDN advertiser.
// Otherwise reception only. No decryption, keys, or packet-file output.
#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
#include <math.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "ldn_observation.h"
#include "probe_frame.h"
#include "auth_frame.h"

static volatile sig_atomic_t interrupted = 0;
static void stopListening(int signalNumber) { (void)signalNumber; interrupted = 1; }
static double now(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}
static BOOL interfaceAddress(const char *name, uint8_t address[6]) {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return NO;
    BOOL found = NO;
    for (struct ifaddrs *entry = interfaces; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_LINK || strcmp(entry->ifa_name, name)) continue;
        const struct sockaddr_dl *link = (const struct sockaddr_dl *)entry->ifa_addr;
        if (link->sdl_alen != 6 || link->sdl_len < offsetof(struct sockaddr_dl, sdl_data) + link->sdl_nlen + 6) continue;
        memcpy(address, link->sdl_data + link->sdl_nlen, 6);
        static const uint8_t zero[6] = {0};
        found = !(address[0] & 1) && memcmp(address, zero, 6);
        if (found) break;
    }
    freeifaddrs(interfaces);
    return found;
}
static void usage(FILE *out) {
    fprintf(out, "Usage: macos-listen [--interface en0] [--seconds 15] [--all-frames] [--channel 6]\n"
        "                    [--probe-request [--probe-source random|interface]]\n"
        "                    [--comm-id HEX]\n"
        "       macos-listen --auth-request --channel N --comm-id HEX [--seconds 15] [--all-frames]\n"
        "       macos-listen --ldn-sweep [--interface en0] [--seconds 15] [--all-frames]\n"
        "       macos-listen --offline file.pcap\n"
        "Live mode enables promiscuous monitor capture for 1-60 seconds.\n"
        "It may interrupt ordinary Wi-Fi. --channel explicitly disconnects first\n"
        "and tunes to a supported 2.4 GHz channel. Reconnect Wi-Fi afterward.\n"
        "--all-frames counts all frame types instead of filtering for management.\n"
        "--probe-request sends ONE wildcard probe request and counts matching replies.\n"
        "--probe-source interface tests the current interface address instead of a random one.\n"
        "--comm-id selects a target header counter (also supported offline).\n"
        "--auth-request waits for that ID, then sends ONE open-system Wi-Fi auth request.\n"
        "It uses the assigned interface address; no association, keys, or game traffic.\n"
        "--ldn-sweep listens on 2.4 GHz channels 1, 6, 11 for --seconds EACH.\n"
        "It cannot be combined with --channel, --probe-request, --auth-request, or --offline.\n"
        "Only aggregate counts and public game IDs are printed; no packets saved.\n");
}

// Capture has its own autorelease pool. Retain into the caller's strong slot
// before that pool drains; an implicit __autoreleasing out parameter dangles.
static int emitReport(NSDictionary *report, NSDictionary *__strong *output) {
    if (output) { *output = report; return 0; }
    NSData *json = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
    if (!json) return 2;
    fwrite(json.bytes, 1, json.length, stdout); fputc('\n', stdout);
    return 0;
}

static int listenOnce(int argc, const char **argv, NSDictionary *__strong *output) {
    @autoreleasepool {
        const char *interface = "en0", *offline = NULL;
        double seconds = 15;
        NSInteger requestedChannel = 0;
        BOOL allFrames = NO;
        BOOL sweep = NO;
        BOOL probeRequest = NO;
        BOOL authRequest = NO, commIDOption = NO;
        uint64_t targetCommID = FRLG_COMMUNICATION_ID;
        const char *probeSourceMode = "random";
        BOOL sourceOption = NO;
        BOOL liveOption = NO;
        for (int i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "--interface") && i + 1 < argc) {
                interface = argv[++i]; liveOption = YES;
            } else if (!strcmp(argv[i], "--all-frames")) {
                allFrames = YES; liveOption = YES;
            } else if (!strcmp(argv[i], "--ldn-sweep")) {
                sweep = YES; liveOption = YES;
            } else if (!strcmp(argv[i], "--probe-request")) {
                probeRequest = YES; liveOption = YES;
            } else if (!strcmp(argv[i], "--auth-request")) {
                authRequest = YES; liveOption = YES;
            } else if (!strcmp(argv[i], "--comm-id") && i + 1 < argc) {
                const char *digits = argv[++i];
                if (!strncmp(digits, "0x", 2) || !strncmp(digits, "0X", 2)) digits += 2;
                if (!*digits || strlen(digits) > 16 || strspn(digits, "0123456789abcdefABCDEF") != strlen(digits)) {
                    usage(stderr); return 64;
                }
                targetCommID = strtoull(digits, NULL, 16); commIDOption = YES;
            } else if (!strcmp(argv[i], "--probe-source") && i + 1 < argc) {
                probeSourceMode = argv[++i]; sourceOption = YES; liveOption = YES;
                if (strcmp(probeSourceMode, "random") && strcmp(probeSourceMode, "interface")) {
                    usage(stderr); return 64;
                }
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
        if ((offline && liveOption) || (sourceOption && !probeRequest) ||
                (sweep && (requestedChannel || probeRequest || authRequest)) ||
                (authRequest && (probeRequest || !requestedChannel || !commIDOption)) ||
                !*interface || strlen(interface) >= IFNAMSIZ) {
            usage(stderr); return 64;
        }
        for (const char *p = interface; *p; ++p)
            if (!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.", *p)) {
                usage(stderr); return 64;
            }
        signal(SIGINT, stopListening);
        signal(SIGTERM, stopListening);
        NSString *targetID = [NSString stringWithFormat:@"0x%016llx", (unsigned long long)targetCommID];
        if (sweep) {
            // Reuse the tested capture path. Each channel's BPF handle closes
            // before the next channel is selected, including on error/Ctrl-C.
            const char *channels[] = {"1", "6", "11"};
            NSString *duration = [NSString stringWithFormat:@"%.17g", seconds];
            const char *channelArgs[] = {argv[0], "--interface", interface,
                "--seconds", duration.UTF8String, "--channel", NULL,
                "--comm-id", targetID.UTF8String, "--all-frames", NULL};
            NSMutableArray *results = [NSMutableArray array];
            uint64_t totalLDN = 0, totalFRLG = 0, totalTarget = 0;
            int status = 0;
            fprintf(stderr, "Listening on channels 1, 6 and 11 for %.0f seconds each. Keep the Switch hosting throughout; reconnect Wi-Fi afterward.\n", seconds);
            for (unsigned i = 0; i < 3 && !interrupted; ++i) {
                channelArgs[6] = channels[i];
                NSDictionary *report = nil;
                status = listenOnce(allFrames ? 10 : 9, channelArgs, &report);
                NSMutableDictionary *result = [@{@"requested_2ghz_channel": @(atoi(channels[i])),
                    @"exit_status": @(status)} mutableCopy];
                if (report) {
                    result[@"capture"] = report;
                    totalLDN += [report[@"ldn_header_candidates"] unsignedLongLongValue];
                    totalFRLG += [report[@"frlg_header_candidates"] unsignedLongLongValue];
                    totalTarget += [report[@"target_header_candidates"] unsignedLongLongValue];
                    fprintf(stderr, "Channel %s finished: %llu packets, %llu FRLG header candidates.\n",
                        channels[i], [report[@"packets_examined"] unsignedLongLongValue],
                        [report[@"frlg_header_candidates"] unsignedLongLongValue]);
                }
                [results addObject:result];
                if (status) break;
            }
            BOOL complete = status == 0 && !interrupted && results.count == 3;
            NSDictionary *report = @{
                @"schema_version": @2, @"mode": @"live_passive_sweep",
                @"frlg_communication_id": [NSString stringWithFormat:@"0x%016llx", (unsigned long long)FRLG_COMMUNICATION_ID],
                @"target_communication_id": targetID, @"target_header_candidates": @(totalTarget),
                @"requested_channels": @[@1, @6, @11], @"seconds_per_channel": @(seconds),
                @"results": results, @"complete": @(complete), @"interrupted": @(interrupted != 0),
                @"ldn_header_candidates": @(totalLDN), @"frlg_header_candidates": @(totalFRLG),
                @"transmission_tested": @NO, @"ldn_compatibility": @"unproven",
                @"interpretation": @"Unauthenticated header discovery only. This covers the LDN library's default 2.4 GHz channels, not every possible host channel. Zero matches do not establish incompatibility."
            };
            int jsonStatus = emitReport(report, output);
            return interrupted ? 130 : status ? status : jsonStatus;
        }
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
        uint64_t beacons = 0, allProbeRequests = 0, allProbeResponses = 0, requestEchoes = 0;
        uint64_t probeResponses = 0;
        uint8_t probeSource[6] = {0};
        uint8_t interfaceSource[6] = {0};
        BOOL haveInterfaceSource = !offline && interfaceAddress(interface, interfaceSource);
        if (authRequest && !haveInterfaceSource) {
            fprintf(stderr, "Cannot read the assigned interface address; no authentication request sent.\n");
            pcap_close(handle); return 2;
        }
        uint64_t targetHeaders = 0, authResponses = 0;
        uint8_t authPeer[6] = {0};
        BOOL authAttempted = NO;
        int authWrite = 0;
        size_t authSize = 0;
        NSString *authError = @"";
        struct timeval authSentAt = {0};
        NSMutableDictionary *authStatuses = [NSMutableDictionary dictionary];
        uint64_t interfaceResponses = 0;
        uint8_t request[PROBE_REQUEST_SIZE] = {0};
        int injectedBytes = 0;
        size_t injectionSize = 0;
        NSString *injectionError = @"";
        if (probeRequest) {
            if (!strcmp(probeSourceMode, "interface")) {
                if (!haveInterfaceSource) {
                    fprintf(stderr, "Cannot read the assigned interface address; no packet injected.\n");
                    pcap_close(handle); return 2;
                }
                memcpy(probeSource, interfaceSource, 6);
            } else {
                arc4random_buf(probeSource, sizeof(probeSource));
                probeSource[0] = (probeSource[0] & 0xfc) | 0x02;
            }
            build_probe_request(request, probeSource, (uint16_t)arc4random_uniform(4096));
            size_t offset = datalink == DLT_IEEE802_11_RADIO ? 0 : PROBE_RADIOTAP_SIZE;
            injectionSize = sizeof(request) - offset;
            fprintf(stderr, "Sending one wildcard Wi-Fi probe request using %s source mode. Write success and local echoes are not over-the-air evidence.\n", probeSourceMode);
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
            uint16_t authStatus = 0;
            BOOL afterAuthWrite = authAttempted && (header->ts.tv_sec > authSentAt.tv_sec ||
                (header->ts.tv_sec == authSentAt.tv_sec && header->ts.tv_usec >= authSentAt.tv_usec));
            if (afterAuthWrite && observed_auth_response(packet, header->caplen,
                    datalink == DLT_IEEE802_11_RADIO, interfaceSource, authPeer, &authStatus)) {
                ++authResponses;
                NSString *key = [NSString stringWithFormat:@"%u", (unsigned)authStatus];
                if (authStatuses[key] || authStatuses.count < 64)
                    authStatuses[key] = @([authStatuses[key] unsignedLongLongValue] + 1);
            }
            if (probeRequest && observed_probe_response(packet, header->caplen,
                    datalink == DLT_IEEE802_11_RADIO, probeSource)) ++probeResponses;
            if (probeRequest && haveInterfaceSource && observed_probe_response(packet, header->caplen,
                    datalink == DLT_IEEE802_11_RADIO, interfaceSource)) ++interfaceResponses;
            if (probeRequest && observed_probe_request_echo(packet, header->caplen,
                    datalink == DLT_IEEE802_11_RADIO, request + PROBE_RADIOTAP_SIZE,
                    sizeof(request) - PROBE_RADIOTAP_SIZE)) ++requestEchoes;
            management += observed.management;
            actions += observed.action;
            beacons += observed.beacon;
            allProbeRequests += observed.probe_request;
            allProbeResponses += observed.probe_response;
            if (observed.ldn_header) {
                ++advertisements;
                frlg += observed.communication_id == FRLG_COMMUNICATION_ID;
                targetHeaders += observed.communication_id == targetCommID;
                NSString *gameID = [NSString stringWithFormat:@"0x%016llx", (unsigned long long)observed.communication_id];
                if (gameIDs[gameID] || gameIDs.count < 64)
                    gameIDs[gameID] = @([gameIDs[gameID] unsignedLongLongValue] + 1);
            }
            if (authRequest && !authAttempted && observed_ldn_peer(packet, header->caplen,
                    datalink == DLT_IEEE802_11_RADIO, targetCommID, authPeer)) {
                uint8_t auth[AUTH_REQUEST_SIZE];
                build_auth_request(auth, interfaceSource, authPeer, (uint16_t)arc4random_uniform(4096));
                size_t offset = datalink == DLT_IEEE802_11_RADIO ? 0 : AUTH_RADIOTAP_SIZE;
                authSize = sizeof(auth) - offset;
                authAttempted = YES; // Never retry, even if the write fails.
                fprintf(stderr, "Observed selected LDN ID; sending one open-system Wi-Fi authentication request.\n");
                gettimeofday(&authSentAt, NULL);
                authWrite = pcap_inject(handle, auth + offset, authSize);
                if (authWrite < 0) authError = @(pcap_geterr(handle));
            }
        }
        double elapsed = now() - start;
        NSInteger channelAtEnd = wifi.wlanChannel.channelNumber;
        uint8_t interfaceAtEnd[6] = {0};
        BOOL readableAtEnd = !offline && interfaceAddress(interface, interfaceAtEnd);
        NSMutableDictionary *captureStats = [NSMutableDictionary dictionary];
        struct pcap_stat stats;
        if (!offline && pcap_stats(handle, &stats) == 0) {
            captureStats[@"received"] = @(stats.ps_recv);
            captureStats[@"dropped"] = @(stats.ps_drop);
            captureStats[@"interface_dropped"] = @(stats.ps_ifdrop);
        }
        pcap_close(handle); // Also on Ctrl-C/error: release the capture handle.
        NSDictionary *report = @{
            @"schema_version": @5,
            @"mode": offline ? @"offline" : authRequest ? @"live_auth_request" : probeRequest ? @"live_probe_request" : @"live_passive",
            @"frlg_communication_id": [NSString stringWithFormat:@"0x%016llx", (unsigned long long)FRLG_COMMUNICATION_ID],
            @"target_communication_id": targetID, @"target_header_candidates": @(targetHeaders),
            @"filter": offline || allFrames ? @"none" : @"management",
            @"promiscuous_requested": @(!offline),
            @"requested_2ghz_channel": @(requestedChannel),
            @"channel_before": @(channelBefore), @"channel_at_start": @(channelAtStart),
            @"channel_at_end": @(channelAtEnd),
            @"pcap_stats": captureStats,
            @"datalink": @(datalink), @"elapsed_seconds": @(elapsed),
            @"interrupted": @(interrupted != 0), @"read_error": @(failed),
            @"packets_examined": @(packets), @"management_frames": @(management),
            @"beacon_frames": @(beacons), @"probe_request_frames": @(allProbeRequests),
            @"probe_response_frames": @(allProbeResponses),
            @"action_frames": @(actions), @"ldn_header_candidates": @(advertisements),
            @"frlg_header_candidates": @(frlg), @"communication_id_counts": gameIDs,
            @"transmission_tested": @(probeRequest || authAttempted), @"ldn_compatibility": @"unproven",
            @"auth_request": @{
                @"requested": @(authRequest), @"attempted": @(authAttempted),
                @"source_mode": @"interface", @"bytes_requested": @(authSize),
                @"write_result": @(authWrite), @"error": authError,
                @"full_write": @(authAttempted && authWrite >= 0 && (size_t)authWrite == authSize),
                @"matching_responses": @(authResponses), @"status_counts": authStatuses,
                @"interpretation": @"A matching peer reply supports transmission of this management frame only. Status 0 is open-system Wi-Fi authentication, not encrypted LDN authentication or a trade. No reply is inconclusive."
            },
            @"probe_request": @{
                @"attempted": @(probeRequest), @"bytes_requested": @(injectionSize),
                @"source_mode": @(probeSourceMode),
                @"write_result": @(injectedBytes), @"error": injectionError,
                @"full_write": @(probeRequest && injectedBytes >= 0 && (size_t)injectedBytes == injectionSize),
                @"matching_responses": @(probeResponses),
                @"request_echoes": @(requestEchoes),
                @"responses_to_interface_address": @(interfaceResponses),
                @"interface_address_readable": @(haveInterfaceSource),
                @"interface_address_changed": haveInterfaceSource && readableAtEnd ? @(memcmp(interfaceSource, interfaceAtEnd, 6) != 0) : NSNull.null,
                @"interpretation": @"Writes and local echoes do not establish RF transmission. Responses to the interface address can be from OS scanning. A separate receiver provides stronger evidence."
            },
            @"interpretation": @"Headers are unauthenticated. Zero matches can mean the wrong channel, no host, or no usable reception."
        };
        int jsonStatus = emitReport(report, output);
        BOOL incompleteWrite = probeRequest && (injectedBytes < 0 || (size_t)injectedBytes != injectionSize);
        BOOL incompleteAuth = authRequest && (!authAttempted || authWrite < 0 || (size_t)authWrite != authSize);
        return failed || incompleteWrite || incompleteAuth ? 2 : jsonStatus;
    }
}

int main(int argc, const char **argv) {
    return listenOnce(argc, argv, NULL);
}
