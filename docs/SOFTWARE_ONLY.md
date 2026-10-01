# Software-only connection research

Checked 2026-09-30. Target: an unmodified Switch 2 running retail FireRed,
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

3. **Native macOS remains unproven here.** The local Mac runs arm64 macOS 27
   and reports an N1 Wi-Fi 7 device using `IO80211_driverkit`. Public CoreWLAN
   documentation describes interface/network selection, not an LDN raw-frame
   transport. A sandboxed, non-activating libpcap monitor-capability query
   returned an error; this is inconclusive, not proof of hardware limitations.
   No capture or transmission test was performed.
   [Apple CoreWLAN](https://developer.apple.com/documentation/corewlan)

4. **Windows alternatives do not establish built-in-radio support.** The
   published `ldnd.exe` workflow uses a compatible USB adapter with a WinUSB
   driver. Porting it is a separate option. Given the preference for existing
   hardware, the first candidate is Linux with a supported internal radio.
   [Windows setup](https://gist.github.com/unlimitedcoder2/af2f09694563c6a6cd3d3e9ec45750bd)

5. **Switch keys are a separate prerequisite.** The current implementation
   derives LDN encryption keys from `prod.keys`. The GBA passphrase/Pia key
   included in upstream does not replace this lower-layer material. Retail
   sessions use encryption; a library's debug flag does not switch a retail
   console to plaintext. No verified key-free route was found.
   [LDN protocol](https://github.com/kinnay/NintendoClients/wiki/LDN-Protocol#encryption-keys)

## Next evidence needed

Run `python3 frlgdex.py doctor --phy phy0` on the candidate Linux computer.
Record the OS, chipset/driver, and monitor support. The command works before
dependencies or keys are available and reports missing prerequisites without
printing key values. On Windows, identify the adapter model first; do not
assume WSL exposes the physical radio.

Once keys and a suitable radio are available, test discovery, room entry, one
disposable trade, graceful exit, and a save reload on the console. Then test a
small sample before transferring all 386. Offline tests do not establish live
Switch 2 reliability.
