# Native macOS LDN investigation

Investigated 2026-10-01. Goal: use the Mac's existing Wi-Fi to trade `.pk3`
files with an unmodified Switch 2 running FireRed. No ESP32, USB radio, or
Linux installation. **Native channel selection and action-frame reception are
now demonstrated on this N1 Mac. No LDN connection or trade has been proven.**

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
| Transmission, key installation, association, trading | Not yet demonstrated; transmission experiment prepared |

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
2. **Partly completed:** general management/action reception works. Next test
   Nintendo advertisements while the Switch hosts a room, on channels 1, 6,
   and 11 as needed. Header recognition does not need keys. Selecting monitor
   mode/channel may interrupt the Mac's ordinary Wi-Fi.
3. Investigate native association/key control first. Determine the current
   Apple80211/DriverKit call path and permissions, and whether it permits
   manual traffic keys and concurrent advertisement reception. The read-only
   probe deliberately does not exercise setters on the current Wi-Fi session.
4. If needed, test raw transmission independently. A successful local write
   is insufficient: a peer response or a separate over-the-air observation is
   needed, followed by sustained bidirectional traffic and ACK behavior.
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

Interpretation:

- `management_frames > 0` establishes management-frame delivery to this
  process. `action_frames > 0` also demonstrates action-frame reception.
- `frlg_header_candidates > 0` means an observed header contains the expected
  FRLG communication ID `0x0100610011000000`. Headers are **unauthenticated**:
  this cannot establish successful advertisement decryption or room entry.
- Zero FRLG matches can mean a different channel, no host advertisement, or
  unusable reception. Even zero management frames requires checking channel,
  nearby activity, capture configuration, and driver behavior before drawing
  a hardware conclusion.

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

The source uses `pcap_inject`, the same interface used by OWL's macOS path.
[OWL transmission code](https://github.com/seemoo-lab/owl/blob/master/daemon/io.c)

The parser's sanitized tests include truncated responses, destination matching,
and rejection of outgoing request echoes. Offline mode rejects all live-only
options, including `--probe-request`.

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
