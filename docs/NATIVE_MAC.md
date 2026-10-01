# Native macOS LDN investigation

Investigated 2026-10-01. Goal: use the Mac's existing Wi-Fi to trade `.pk3`
files with an unmodified Switch 2 running FireRed. No ESP32, USB radio, or
Linux installation. **Native channel selection and reception of public LDN
headers matching a FireRed ID are demonstrated on this N1 Mac. No encrypted
LDN connection or trade has been proven.**
Only this Mac is currently available; the next experiment uses the Switch
itself as the nearby peer, without a second receiver. The user confirmed
that the running FireRed edition is English.

**Current feasibility:** reception is demonstrated; native trading is not
implemented. Two wildcard probe writes and one request to the detected LDN
advertiser were accepted locally but produced no matching peer reply. The
direct driver connection also fails, and the inspected public key setters
cannot install the required CCMP traffic key. Further progress needs new
evidence about a transmit/driver-control route; repeating the same captures
does not resolve these gaps. This is not a proof that every native route is
impossible.

## The most useful finding

The Linux library's **joining** implementation uses a managed station. It asks
the driver to associate, installs CCMP keys at indices 0 and 1, subscribes to
action-frame reception, and exchanges LDN authentication through EtherType
`0x88b7`. It authorizes the station after authentication. The fully simulated
monitor-mode access point is a different implementation. Therefore arbitrary
raw-frame injection is not necessarily required for a Mac that only joins the
Switch's room. It still needs controls beyond ordinary Wi-Fi association.
[Source: STAInterface](https://github.com/kinnay/LDN/blob/master/ldn/wlan.py)

This is a narrower port than implementing an entire access point. A candidate
would retain the Pokémon/Pia/RFU logic and replace Linux wireless control plus
the `AF_PACKET` receiver. Reusing protocol code may require separating it from
the LDN package's Linux imports. The current `LiveTransport` remains Linux-only.

## Two candidate implementations

| Approach | What needs proving on macOS | Main uncertainty |
| --- | --- | --- |
| Native station + private driver control | Associate with the LDN host, install its static CCMP keys without a WPA four-way handshake, exchange custom authentication, receive host advertisements alongside data | Whether the current driver exposes these operations to our process |
| Raw 802.11 through BPF/libpcap | Receive advertisements; send and receive association and encrypted data frames; maintain sufficiently reliable acknowledgments | Capture support does not establish injection, driver ACK behavior, or successful communication |

Both are hypotheses. A negative injection result would weaken the second
approach but would not by itself rule out the native-station approach.

Public CoreWLAN offers a 32-byte pairwise **master** key setter and a WEP key
setter. Neither documents installing LDN's 16-byte CCMP traffic key directly.
Padding the LDN key to 32 bytes would not give it the same meaning.
[CoreWLAN CWInterface](https://developer.apple.com/documentation/corewlan/cwinterface)

Apple's `NWEthernetChannel` exposes custom EtherTypes and requires the
`com.apple.developer.networking.custom-protocol` entitlement. It is a possible
component for the authentication frames after association; it supplies neither
raw 802.11 management access nor a CCMP-key setter. Its API excludes IPv4, IPv6,
ARP and other system-handled EtherTypes, so game UDP traffic needs a separate
path. These details are also documented in the installed SDK's
`Network.framework/Headers/ethernet_channel.h`.
[NWEthernetChannel](https://developer.apple.com/documentation/network/nwethernetchannel)

The open-source AirportItlwm driver implements Apple's private `CIPHER_KEY`
operation for AES-CCM traffic keys. That establishes a relevant private
interface in that driver family, **not** compatibility with Apple's N1 driver
or permission for an ordinary app to use it.
[AirportItlwm source](https://github.com/OpenIntelWireless/itlwm/blob/master/AirportItlwm/AirportSTAIOCTL.cpp)

## What was checked on this Mac

These are local measurements, not compatibility claims for all Macs.

| Check | Observed result |
| --- | --- |
| OS | arm64 macOS 27.0, build 26A428 |
| Wi-Fi | System Profiler identifies N1; IORegistry traces `en0` to `com.apple.driver.AppleCentauriAlpha` and `AppleWLANInterfaceSTA` |
| Private frameworks | Apple80211 and CoreWiFi load; Apple80211 Open/Bind/Get/Set/Associate symbols exist |
| Private handle test | Open returns 0; BindToInterface returns -1 outside the execution sandbox, including the user's root run; Close returns 0 |
| libpcap | Installed version 1.10.1 |
| Monitor query, sandboxed | -1, BPF access: Operation not permitted |
| Monitor query, ordinary user outside sandbox | -8, BPF access: Permission denied |
| Administrator query | User ran the built probe in Terminal: `can_set_rfmon = 1`, no error. Monitor mode is advertised |
| First capture | Radiotap link type 127 activated; 15 seconds, current channel, management filter, no promiscuous request: zero delivered packets |
| Second capture | CoreWLAN selected channel 6 from channel 44; promiscuous mode, no BPF filter: 2,149 packets, 1,806 management frames, 269 action frames in 15 seconds; no reported drops |
| LDN advertisements | Zero candidate LDN/FRLG headers in that capture; Switch hosting state not yet confirmed |
| First raw-transmission attempt | `pcap_inject` accepted all 44 bytes without error; 1,551 packets received in 15 seconds, including 1,340 management and 255 action frames, no reported drops, zero matching probe responses |
| Interface-source comparison | 44/44 bytes accepted again; 1,485 packets, 1,255 management frames, 313 actions, 833 beacons, 23 probe requests and 68 probe responses; zero matching responses, interface-address responses or request echoes; no reported drops |
| Comparison channel/address checks | Channel 6 at both capture endpoints; assigned interface address readable and unchanged at the endpoints |
| Completed three-channel sweep, FireRed hosting | Channels 1/6/11 received 1,494/2,022/1,832 packets. Channel 6 contained 139 candidate LDN headers with ID `0x01006fa0233f8000`; none on 1 or 11. No reported drops; requested channels matched start/end readings |
| Initial FRLG label for that sweep | Incorrectly reported zero because it compared only against inherited ID `0x0100610011000000`. The public ID was decoded correctly; the classification/default has now been corrected |
| Targeted authentication experiment | Channel 6, 15 seconds: 1,988 packets, 407 actions, 135 matching FireRed-ID headers, zero reported drops. One 38-byte request accepted in full with no error; zero matching authentication responses. Channel/address unchanged at endpoints |
| Private bind diagnosis, ordinary user outside sandbox | Saved errno 102 (`Operation not supported on socket`); process logs report a missing Wi-Fi DriverKit entitlement, failed `IOServiceOpen` (`0xe00002bc`), and a failed legacy IOCTL fallback |
| Over-the-air transmission, key installation, association, trading | Not demonstrated; write acceptance alone is insufficient |

The second capture establishes actual management/action-frame reception and
channel selection. Channel, filtering, and promiscuous mode changed together,
so the result does not identify which change fixed the first empty capture.
It does not establish transmission, LDN discovery, or key control.

The installed Sunrise driver contains monitor and cipher-related strings, but
it is **not the active driver on this Mac**. Those strings were discarded as
evidence of N1 capabilities. The active Centauri executable links the private
DriverKit CentauriAlpha/AppleWLANPrime frameworks. Its exported symbols alone
do not expose a usable packet API.

Runtime inspection found `monitorMode`, `setPairwiseMasterKey:error:` and
`setWEPKey:flags:index:error:` on CWInterface. No methods containing the probe's
selected action-frame/cipher terms appeared on CWFInterface. This limited name
search does not establish that no lower-level/private route exists. Likewise,
Apple80211's failed bind needs further diagnosis; it is not proof that every
private interface is inaccessible.

### Why the private bind fails

Inspection of the installed IO80211 framework and a fresh probe's process logs
now provides more than the original `-1` return value. The log identifies the
missing entitlement `com.apple.private.driverkit.driver-access`, with value
`com.apple.private.wifi.driverkit`, then reports `IOServiceOpen` failure and
an unsuccessful IOCTL compatibility fallback. This is a concrete access
obstacle for the direct Apple80211 route. The IOKit status is generic; these
observations do not establish that entitlement is the only obstacle. The
earlier root run also failed to bind, so sudo alone has not solved it.

Apple Developer Technical Support has answered a report of this exact
entitlement error: a third-party developer cannot obtain a provisioning
profile authorizing an Apple-private entitlement. Consequently, adding this
name to an entitlements plist is not a normal signing fix. Apple's suggested
public CoreWLAN replacement in that discussion addresses Wi-Fi scanning; it
does not promise arbitrary driver commands or LDN traffic-key installation.
[Apple DTS response](https://developer.apple.com/forums/thread/756747)

Probe schema 2 saves errno immediately after Bind. In the ordinary-user run
outside the execution sandbox it was 102. This is consistent with the observed
IOCTL fallback failure, not proof of missing radio capabilities. Private API
errno behavior is undocumented; the report labels this limitation.

To inspect only this program's recent diagnostic messages after running it:

```sh
/usr/bin/log show --last 5m --style compact --predicate 'process == "macos-probe" AND (eventMessage CONTAINS[c] "entitlement" OR eventMessage CONTAINS[c] "IOServiceOpen" OR eventMessage CONTAINS[c] "BindToInterface")'
```

Runtime method enumeration also finds CoreWiFi's mediated association API
(`associateWithParameters:error:`) and password/EAP-oriented association
parameters, but no explicit static CCMP traffic-key setter in the inspected
classes. This metadata check calls no setters and does not prove that a
different mediated route is absent. A native-station implementation still
needs a demonstrated way to install the LDN traffic keys.

### Public key-setter implementation check

Read-only inspection of the installed macOS 27.0 build 26A428 SDK and the
arm64e `/usr/libexec/airportd` implementation further narrows the mediated
route. No setter was invoked and no current network key was read or changed.

- The SDK documents `setPairwiseMasterKey:error:` as a 32-byte PMK setter.
  In `CWXPCSubsystem setPairwiseMasterKey:interfaceName:connection:error:`,
  the installed service compares a non-nil key's length with `0x20` and takes
  the error path for any other length. It submits cipher type 6 through
  `Apple80211Set`; this does not expose an arbitrary cipher selector.
- In `CWXPCSubsystem setWEPKey:flags:index:interfaceName:connection:error:`,
  the service accepts a non-nil key only when its length is 5 or 13 bytes.
  It chooses type 1 or 2 from that length before calling `Apple80211Set`.
  The public `CWCipherKeyFlags` select unicast/multicast/transmit/receive use,
  not the cipher algorithm. Supplying a 16-byte CCMP key cannot use this path.

These observations establish restrictions of the inspected methods, not of
all code in the service. They explain why ordinary association or a PMK/WEP
setter cannot directly replace the Linux client's static traffic-key install.
The comparison points in the inspected arm64e image are `0x10001CBB4` (PMK
length), `0x10001D288` and `0x10001D298` (WEP lengths); virtual addresses may
change in another OS build. The read-only inspection can be reproduced with:

```sh
xcrun dyld_info -disassemble /usr/libexec/airportd > /tmp/airportd-disassembly.txt
rg -n 'CWXPCSubsystem setWEPKey:|CWXPCSubsystem setPairwiseMasterKey:' /tmp/airportd-disassembly.txt
```

This complements the installed `CoreWLAN.framework/Headers/CWInterface.h`
and `CoreWLANTypes.h`, and the public API description.
[CWInterface](https://developer.apple.com/documentation/corewlan/cwinterface)

## Reproduce the non-disruptive probe

Requires macOS 13+ and Xcode or the Command Line Tools. No Python packages,
Switch keys, running game, capture files, or network downloads are needed.

From the repository:

```sh
make mac-probe
./build/macos-probe --interface en0 --private
```

If BPF access is denied, run the built program in your local Terminal:

```sh
sudo ./build/macos-probe --interface en0 --private
```

Build as your normal user; only the probe needs elevated access. Enter a sudo
password in Terminal, never in chat. Omit `--private` to skip private-framework
loading and Open/Bind/Close. The JSON contains driver/class names and status
codes, but no SSIDs, MAC addresses, IP addresses, serials, or key material.

The source never activates a capture handle, reads packets, scans, associates,
changes channels, calls a key setter, or transmits. Binding an Apple80211
handle selects its interface; it does not connect Wi-Fi to another network.

Interpret `monitor_query.can_set_rfmon` as follows:

- `1`: libpcap advertises a monitor path. Reception and transmission still need
  independent experiments.
- `0`: this libpcap path does not advertise monitor mode; private-driver paths
  have not been ruled out.
- Negative: the query failed. Use the error text; **do not label this hardware
  incompatibility**. Exit status 2 means an inconclusive query. Exit 0 means
  the query completed, not that the Mac supports LDN.

[libpcap's return-value contract](https://www.tcpdump.org/manpages/pcap_can_set_rfmon.3pcap.html)

Apple's libpcap implementation opens BPF and checks the available link-layer
formats for this query. It does not select the monitor format here. That
explains why even this non-activating query needs BPF permissions.
[Apple libpcap source](https://github.com/apple-oss-distributions/libpcap/blob/main/libpcap/pcap-bpf.c)

## Next experiments and success criteria

1. **Completed:** administrator monitor query returns 1 on this N1 Mac.
2. **Completed at the public-header level:** the hosted-room sweep received
   139 LDN header candidates on channel 6. Their ID matches a published
   FireRed application ID. Headers remain unauthenticated; this is not
   advertisement decryption or room entry.
3. Investigate native association/key control first. Determine the current
   Apple80211/DriverKit call path and permissions, and whether it permits
   manual traffic keys and concurrent advertisement reception. The read-only
   probe deliberately does not exercise setters on the current Wi-Fi session.
   The direct Apple80211 path now has an observed access/fallback failure;
   symbol presence alone is not a reason to proceed to arbitrary setters.
4. **Attempted, unresolved:** both wildcard probe tests and the targeted
   authentication test accepted writes with zero matching replies. A local
   write is insufficient. Before another live experiment, identify a specific
   driver-send behavior or a concrete test defect that the new experiment can
   distinguish. A positive result would still need sustained bidirectional
   traffic and ACK behavior.
5. With usable radio control and the required LDN key material, prove room
   discovery, LDN authentication, and Pia UDP exchange. Then integrate a Mac
   transport and test one disposable trade plus a console save reload before
   offering the living dex.

The present LDN code derives advertisement/data keys from Switch key material;
the game-specific Pia key is a separate layer. A successful Mac radio probe
would not remove the missing-keys prerequisite for trading.
[LDN encryption](https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol#encryption-keys)

## Passive listener

This is a separate, opt-in experiment: unlike `macos-probe`, it enables monitor
capture and may interrupt ordinary Wi-Fi. It uses the current channel unless
`--channel` is supplied. Run locally, not through a session relying on this Wi-Fi.
Close other packet-capture programs first. The listener closes its handle after
the requested duration, on Ctrl-C, or on a read error; reconnect Wi-Fi manually
if the OS does not resume the connection.

```sh
make mac-listen native-test
sudo ./build/macos-listen --interface en0 --seconds 15
```

Have the Switch host a FireRed trade room nearby if convenient. The listener
requests promiscuous mode, uses a management-frame BPF filter by default,
processes at most 256 bytes per packet,
and prints aggregate counts plus public communication IDs. It does not save
captures, transmit, install keys, decrypt advertisements, or print addresses
or SSIDs. The time limit accepts 1–60 seconds.

The successful reception experiment used the following stronger configuration:

```sh
sudo ./build/macos-listen --interface en0 --seconds 15 --all-frames --channel 6
```

`--all-frames` removes the BPF filter, still retaining only aggregate counts.
`--channel` accepts a supported 2.4 GHz channel (usually 1, 6 or 11 for these
LDN experiments). It checks monitor access and channel availability, explicitly
disassociates, then sets the channel through CoreWLAN. It does not remember or
restore the previous network: reconnect Wi-Fi afterward. This mode reports
the requested channel, CoreWLAN's channel readings, and pcap receive/drop stats.
A channel value of zero means no readable value/no explicit selection, not a
real Wi-Fi channel.

### Find the Switch with one command

On the Switch, go upstairs in a Pokémon Center and select **Direct Corner →
Trade Center → Become Leader**. Leave it waiting for another player throughout
the capture. The existing Linux library scans channels 1, 6 and 11 by default;
the new sweep covers those same channels. These are not an exhaustive list of
every channel on which an LDN host could operate.
[Upstream workflow](https://github.com/tornadus/frlg-ldn-trade#usage),
[LDN scan defaults](https://github.com/kinnay/LDN/blob/master/ldn/__init__.py)

```sh
sudo ./build/macos-listen --interface en0 --ldn-sweep --seconds 15 --all-frames
```

This listens for **15 seconds per channel**, approximately 45 seconds total,
and disconnects normal Wi-Fi. Reconnect afterward. No probe request is sent,
and no keys are needed to recognize public LDN headers. One JSON report
contains each channel's existing capture report and combined header counts.
The capture handle closes before advancing to another channel. An error stops
the sweep and marks it incomplete; Ctrl-C reports the partial results and exits
with status 130. Channel-selection overhead is additional to the capture time.

`--ldn-sweep` cannot be combined with `--channel`, `--probe-request`,
`--auth-request`, or `--offline`. Current sweep schema 2 wraps single-capture
schema 5 and reports both the FRLG match ID and an independently selectable
target ID (`--comm-id HEX`). The completed live sweep used the earlier schema
1/4 combination, before the FRLG ID correction described below.

The first live sweep attempt crashed after the first channel, before emitting
JSON. The local macOS crash report showed `objc_retain` inside `listenOnce`.
An offline regression reproduced the same crash: a report returned through an
implicitly autoreleasing out parameter outlived the capture's autorelease
pool. The output parameter now explicitly retains into the caller's strong
slot. `make native-test` exercises three successive offline captures, retained
nested reports, and JSON serialization under AddressSanitizer/UBSan. The sweep
also prints a completion line for each channel. The failed run provides no
LDN discovery result; the corrected live sweep subsequently completed with
the results recorded in the table above.

Interpretation:

- `management_frames > 0` establishes management-frame delivery to this
  process. `action_frames > 0` also demonstrates action-frame reception.
- `frlg_header_candidates > 0` means an observed header contains the expected
  locally observed FRLG communication ID `0x01006fa0233f8000`. Headers are **unauthenticated**:
  this cannot establish successful advertisement decryption or room entry.
- Zero FRLG matches can mean a different channel, no host advertisement, or
  unusable reception. Even zero management frames requires checking channel,
  nearby activity, capture configuration, and driver behavior before drawing
  a hardware conclusion.

### Correcting the communication ID

The completed sweep decoded 139 advertisements with ID
`0x01006fa0233f8000`. The tool's original `frlg_header_candidates` check used
upstream's constant `0x0100610011000000`, so it falsely labeled those as zero
FRLG matches. Checking the big-endian advertisement layout in kinnay's encoder
confirmed the offset and byte order; this was an overly narrow ID check, not
a missed packet or a decoder endian error.
[Advertisement encoder](https://github.com/kinnay/LDN/blob/master/ldn/__init__.py),
[Inherited transport default](https://github.com/tornadus/frlg-ldn-trade/blob/main/frlgsim/transport.py)

Ruimusume's own tool documentation lists the observed value as the Japanese
FireRed **application title ID**. The user is running English FireRed. A
network communication ID need not identify the installed language edition;
the capture is consistent with a shared identifier, but does not establish
every edition's behavior or cryptographically identify the transmitter.
[Tool author's version table](https://gbatemp.net/threads/switch-pokemon-fire-red-leaf-green-jp-en-nsce-cheats-tools.680562/)

The native diagnostic and the Linux trader's default now use the observed ID.
The trader's existing `--comm-id` override remains available. The native
listener also accepts `--comm-id` and separately reports
`target_communication_id` / `target_header_candidates`; choosing a target
never relabels arbitrary IDs as FRLG. The detector does not infer language
from these fields. An offline fixture with the captured ID now covers its
classification, and the existing sweep report-lifetime regression still runs.

The Nintendo vendor/LDN signature and network identifier are outside the
encrypted advertisement payload. The minimal parser checks those public fields
and bounds; it does not substitute for the full LDN decoder.
[Advertisement layout](https://github.com/kinnay/LDN/blob/master/ldn/__init__.py)

An existing radiotap or raw 802.11 pcap can be examined without touching Wi-Fi:

```sh
./build/macos-listen --offline /path/to/capture.pcap
```

Validation performed: both native programs compile with warnings as errors;
the parser passes AddressSanitizer/UndefinedBehaviorSanitizer tests covering
truncation, malformed radiotap lengths, encrypted/fragmented frames, other
frame types, header controls, version/format checks and FRLG identification.
An offline synthetic pcap also passed the complete pcap-to-JSON path. None of
these tests establish over-the-air compatibility.

## Explicit transmission experiment

The optional `--probe-request` flag changes the listener into a transmission
experiment. It sends **one** ordinary broadcast probe request with a wildcard
SSID and a fresh locally administered source address, then counts probe
responses addressed to that source. It needs no Switch or keys. The only
injected frame is the probe request; the driver handles the normal Wi-Fi
disconnection described above.

```sh
sudo ./build/macos-listen --interface en0 --seconds 15 --all-frames --channel 6 --probe-request
```

Reconnect Wi-Fi afterward. Without this explicit flag, the previous listening
commands remain passive. The JSON reports the write return value and error
separately from matching responses. A successful write alone is inconclusive.
An outgoing-request echo cannot count as a response. A matching response
supports over-the-air transmission of this management frame; it does not
establish CCMP data transmission or reliable LDN operation. Zero responses
can also result from frame rewriting, loss or access-point behavior.

**First result:** the user ran the 44-byte random-source probe. The write
returned 44, with an empty error string, but no matching response appeared.
Reception continued normally (1,551 frames; 255 action frames). This proves
write acceptance, not RF transmission, and does not prove injection impossible.

The probe's basic layout was checked: eight-byte empty radiotap header,
24-byte probe-request MAC header with broadcast destination/BSSID, zero-length
SSID information element, and eight supported rates. New frame-construction
tests independently walk its information elements and check addresses,
sequence/fragment encoding, and total length.

libpcap explicitly documents that some platforms/drivers rewrite the source
address or link-layer type. The previous match against a fresh temporary
address would miss a response addressed to the actual interface instead.
This is a hypothesis to test, not an observation of N1 behavior.
[pcap_inject documentation](https://www.tcpdump.org/manpages/pcap_inject.3pcap.html)

A controlled comparison now permits the assigned interface address:

```sh
sudo ./build/macos-listen --interface en0 --seconds 15 --all-frames --channel 6 --probe-request --probe-source interface
```

This still sends only one ordinary request and needs a Wi-Fi reconnect
afterward. `random` remains the default; specifying `--probe-source` without
`--probe-request` is rejected. Neither mode prints the source address.
Schema version 4 adds beacon/probe-request/probe-response counts, matching
request echoes, responses to the assigned interface address, full-write
status, the final channel, and interface-address change detection. Endpoints
alone cannot exclude a temporary channel/address change during the capture.

Do not treat local request echoes as RF proof. Responses to the interface
address may also originate from normal macOS scanning, so those are weaker
evidence than responses to a fresh random address.

**Second result:** the interface-source comparison also accepted all 44 bytes,
with no matching responses or request echoes. The capture contained 68 probe
responses to other destinations, showing that probe responses were receivable.
Channel 6 and the interface address matched at the start and end. This weakens
the source-rewriting explanation but still does not establish where the test
frame went or prove that raw transmission is impossible. Further identical
probe-request attempts are unlikely to resolve this uncertainty.

Apple's published libpcap implementation forwards injection to a BPF `write`.
The published XNU BPF implementation dispatches complete-header writes through
a registered driver send callback when available, otherwise through raw
network-interface output. It does not wait for evidence of radio delivery.
This explains why the return value alone cannot answer our RF question;
inspection of published code is not a trace of this N1 driver's execution.
[Apple libpcap](https://github.com/apple-oss-distributions/libpcap/blob/main/libpcap/pcap-bpf.c),
[XNU BPF write path](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.c)

A separate receiver could help diagnose injection, but none is available now.
The completed sweep instead found a relevant advertiser on channel 6. That
provides a peer for the following targeted test; reception alone still does
not establish transmission or a trade.

The source uses `pcap_inject`, the same interface used by OWL's macOS path.
[OWL transmission code](https://github.com/seemoo-lab/owl/blob/master/daemon/io.c)

The parser's sanitized tests include truncated responses, destination matching,
and rejection of outgoing request echoes. Offline mode rejects all live-only
options, including `--probe-request`.

## One targeted authentication request

`--auth-request` waits for an advertisement matching an explicitly supplied
`--comm-id`, learns its unicast transmitter address, and sends **one**
open-system 802.11 authentication request to it using the Mac's assigned
interface address. It never retries or falls back to another game. The LDN
library's managed client requests open-system Wi-Fi authentication before
its separate encrypted LDN exchange; its software AP also implements this
request/response exchange. A retail Switch reply is still an experiment.
[LDN wireless implementation](https://github.com/kinnay/LDN/blob/master/ldn/wlan.py)

Keep FireRed waiting at **Direct Corner → Trade Center → Become Leader**:

```sh
sudo ./build/macos-listen --interface en0 --channel 6 --seconds 15 --all-frames --comm-id 0x01006fa0233f8000 --auth-request
```

This disconnects ordinary Wi-Fi; reconnect afterward. No keys are needed.
It sends no association request, encrypted LDN authentication, or Pokémon
data. The Nintendo advertisement uses a broadcast BSSID; the unicast
transmitter supplies the target for this experiment. No addresses are printed
or saved. Without `--auth-request` or `--probe-request`, capture stays passive.

The JSON's `auth_request` reports whether a matching advertiser was found and
a write attempted, requested/written byte counts, matching replies, and their
status-code counts. Replies must be captured after the write begins, addressed
to the Mac, from the selected peer/BSSID, with open-system algorithm 0 and
transaction sequence 2. Request echoes, other peers and earlier buffered
packets do not count.

- A matching peer reply supports over-the-air transmission of this management
  frame. A refusal status is still a reply; status 0 means only this basic
  Wi-Fi authentication step succeeded, not LDN authentication or room entry.
- A full write with no reply remains inconclusive. A single request can be
  lost or ignored; it does not prove hardware incompatibility.
- No suitable advertiser means no request is sent (`attempted: false`).
  That and an incomplete write exit with status 2. Exit 0 means the experiment
  completed, not that a response or a trade succeeded.

This option requires both an explicit channel and communication ID, and is
mutually exclusive with probe injection, sweep and offline modes. Frame,
peer-selection and response-matching tests run with ASan/UBSan; CLI checks
cover conflicting options and the unchanged passive offline path. Live
transmission remains unproven until the peer experiment supplies evidence.

**Live result:** the Mac continued receiving the selected advertiser (135
matching headers), attempted the request, and `pcap_inject` returned 38/38
with no error. There were zero matching replies. The complete capture had
1,988 packets, 407 action frames and 81 probe responses, with no reported
drops. Channel 6 and the assigned interface address matched at both endpoints.
Thus the experiment found a relevant peer but did not establish RF delivery
or authentication success.

A follow-up audit checked the authentication fields against kinnay's encoder:
algorithm 0, transaction 1, status 0, destination/BSSID from the advertiser,
and the assigned interface source. LDN action advertisements' broadcast BSSID
is accepted during discovery; it is not used as the authentication destination.
The response matcher expects transaction 2 and also accepts refusal statuses.
No frame-layout defect was found. The published Darwin BPF implementation uses
`microtime` capture timestamps, consistent with the wall-clock filter; this
source check is not a runtime timestamp measurement on N1.

The aggregate report cannot distinguish a driver discard from a lost/ignored
request, a response not delivered to this capture, or unexpected rewriting.
No full packet capture was saved for replay. Three accepted writes across
these experiments therefore remain three inconclusive RF tests, not evidence
that transmission works or a proof that it is impossible.

## Related work and limits

OWL includes macOS libpcap capture/injection code, but requires a compatible
radio with active monitor behavior. Its macOS build support is not evidence
that current N1 hardware can inject. AirDrop/AWDL itself speaks a different
protocol from Nintendo LDN.
[OWL requirements](https://github.com/seemoo-lab/owl#requirements),
[OWL I/O implementation](https://github.com/seemoo-lab/owl/blob/master/daemon/io.c)

Native macOS userspace USB-radio drivers demonstrate that protocol work can
run on macOS, but they use different hardware and USB access. Their success
does not supply access to the built-in N1 radio.
[RTL8812AU implementation](https://github.com/xen-proc/rtl8812au-macos)

A normal Linux VM's virtual network interface also does not supply the physical
Wi-Fi controls needed by the existing Linux implementation. A Mac frontend
with a Linux radio server could reuse the trader, but that would be a different
architecture from the native built-in-radio goal investigated here.
