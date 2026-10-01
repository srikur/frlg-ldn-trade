# Software-only connection research

Checked 2026-10-01. Target: an unmodified Switch 2 running retail FireRed,
trading individual `.pk3` files from an existing computer.

## Findings

1. **An ESP32 is optional.** Upstream's Linux transport already talks directly
   through a compatible Wi-Fi card. An internal RTL8821CE is reported working;
   an internal RZ616 is less reliable. Hardware/driver compatibility matters
   more than whether the radio is internal or external.
   [Upstream requirements](https://github.com/tornadus/frlg-ldn-trade#requirements)

2. **LDN needs access below normal IP networking.** The underlying library uses
   Linux wireless control and wireless action-frame reception/transmission.
   Connecting both devices to a home router does not provide that interface.
   [LDN library](https://github.com/kinnay/LDN#usage-instructions)

3. **Native macOS is an active research path.** The Linux joining code uses a
   managed station with static CCMP keys, so full raw injection is not the only
   candidate. The local N1 Mac uses the Centauri DriverKit stack. Its libpcap
   capability query returns 1 with administrator access: monitor mode is
   advertised. The ordinary-user failure was a permission error. A native
   read-only probe builds with `make mac-probe`, and a separate bounded passive
   listener with `make mac-listen`. CoreWLAN channel selection and actual
   management/action reception now work on this Mac: one 15-second capture
   delivered 2,149 packets, including 269 action frames. A subsequent injection
   call accepted a 44-byte probe request, but no matching response was observed.
   A comparison using the interface's assigned address had the same outcome.
   The private Apple80211 bind logs a missing DriverKit entitlement and fails
   both its driver connection and legacy fallback. A completed native sweep
   then received 139 public LDN header candidates on channel 6 while English
   FireRed hosted a room. Their ID, `0x01006fa0233f8000`, corrects the inherited
   default in the diagnostic and trader. Encrypted discovery, over-the-air
   transmission and usable key-control access remain unproven.
   [Native Mac evidence and experiments](NATIVE_MAC.md)

4. **Windows alternatives do not establish built-in-radio support.** The
   published `ldnd.exe` workflow uses a compatible USB adapter with a WinUSB
   driver. Porting it is a separate option. Given the preference for existing
   hardware, Linux with a supported internal radio is an alternative if such
   a computer becomes available. Only the Mac is available at present.
   [Windows setup](https://gist.github.com/unlimitedcoder2/af2f09694563c6a6cd3d3e9ec45750bd)

5. **Switch keys are a separate prerequisite.** The current implementation
   derives LDN encryption keys from `prod.keys`. The GBA passphrase/Pia key
   included in upstream does not replace this lower-layer material. Retail
   sessions use encryption; a library's debug flag does not switch a retail
   console to plaintext. No verified key-free route was found.
   [LDN protocol](https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol#encryption-keys)

## Next evidence needed

The Mac-only sweep now establishes reception of candidate FireRed LDN headers
on channel 6. The next experiment keeps FireRed waiting at **Direct Corner →
Trade Center → Become Leader** and sends one ordinary Wi-Fi authentication
request to that advertiser, looking for a matching response. It needs no keys
and does not enter a room or initiate a Pokémon trade. See the native guide
for `--auth-request`, its Wi-Fi interruption, and how to interpret the results.
Private driver access and encrypted LDN communication remain separate tasks.

Once keys and a suitable radio are available, test discovery, room entry, one
disposable trade, graceful exit, and a save reload on the console. Then test a
small sample before transferring all 386. Offline tests do not establish live
Switch 2 reliability.
