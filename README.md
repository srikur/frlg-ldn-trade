# FRLG living-dex trader

A fork of [tornadus/frlg-ldn-trade](https://github.com/tornadus/frlg-ldn-trade)
for moving Gen-3 `.pk3` collections into FireRed/LeafGreen on Switch or Switch 2
through in-game trades.

Collection commands work on macOS, Windows, and Linux with Python 3.12+.
**Live trading currently uses upstream's Linux Wi-Fi transport.** An ESP32 is
not required if an existing radio and Linux driver support LDN. Switch
`prod.keys` are still required. Native Mac/Windows and key-free transports have
not been implemented. See [software-only research](docs/SOFTWARE_ONLY.md).

This fork has passed offline tests with synthetic data, including all 386
species. **Its changes have not yet been tested against a real Switch 2.**

## Audit your collection

These commands need no dependencies or Switch keys:

```sh
python3 frlgdex.py doctor
python3 frlgdex.py audit /path/to/shiny-dex
python3 frlgdex.py audit /path/to/shiny-dex --json
```

Checks include 80/100-byte files, checksums, shiny status, National Dex coverage,
duplicate species, eggs, and trade evolutions. Hoenn internal IDs are correctly
mapped to National Dex order. These checks establish structure, not encounter
legality or live-game acceptance.

`.pk3` means decrypted PKHeX format; `.ek3` means encrypted save/link format.
Correct misleading extensions before import. Original files are never edited
or deleted by this tool.

**Preserving all 386 species:** Kadabra, Machoke, Graveler, and Haunter normally
evolve when traded. Gen-3 Everstone prevents this. Item-based evolutions are
also flagged. Prepare any item changes in a separate collection before import;
this tool does not silently change your Pokémon. Mew/Deoxys without the
fateful-encounter flag are flagged for review.

## Import and track progress

Keep the workspace outside the source collection:

```sh
python3 frlgdex.py init /path/to/shiny-dex --workspace ./transfers
python3 frlgdex.py status --workspace ./transfers
python3 frlgdex.py trade --workspace ./transfers
```

`trade` without `--live` previews the next file and prerequisites. It never
joins a network or marks a transfer complete. Files are offered in National Dex
order. Re-importing the same files preserves progress. Changed imported files
must be restored before offering them; prepare the collection first.

The initial workflow runs **one trade per session**, following upstream's
documented route. Upstream also has 1–6 trade options, but this runner does not
yet use those experimental batch paths. The Switch player chooses and confirms
each trade and walks out afterward. Plan for 386 outgoing Pokémon and enough
box space for 386 incoming Pokémon.

## Live setup on Linux

Use Python 3.12+ and install your distribution's `iw`, `iproute2`, and
NetworkManager tools. Booting Linux on an existing Windows computer is a
candidate if its Wi-Fi driver supports the required frames. A normal VM's
virtual Ethernet adapter does not supply raw Wi-Fi access.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python frlgdex.py doctor --phy phy0 --keys /absolute/path/prod.keys
```

`doctor` is read-only. It reports the driver and advertised monitor support;
it does not capture traffic or change networking. Passing is **not** proof of
frame-injection compatibility; that requires a live test. Upstream reports good
results with internal RTL8821CE (`rtw88_8821ce`), poor reliability with RZ616
(`mt7921e`), and problems with Intel AX200.

The live backend takes the selected adapter away from ordinary networking.
Run locally, not over SSH through that adapter. Upstream does not automatically
restore NetworkManager ownership afterward. To restore it, substitute its
normal interface name for `wlan0`:

```sh
sudo nmcli device set wlan0 managed yes
sudo ip link set wlan0 up
```

On the Switch, unlock the Direct Corner. For the full collection, obtain the
National Pokédex; completing Celio's network-machine quest is the normal
preparation for Gen-3 interoperability. Start with a disposable test Pokémon.
Use an absolute key path because sudo can change the home directory:

```sh
sudo .venv/bin/python frlgdex.py trade --workspace ./transfers --phy phy0 --keys /absolute/path/prod.keys --live
```

Then on the Switch:

1. Upstairs in a Pokémon Center, choose **Direct Corner → Trade Center → Become Leader**.
2. Accept **EMU**, enter the room, and sit in the **left chair**.
3. Choose the Pokémon to give away and accept the offered Pokémon.
4. Let the game save, cancel the trade menu, and walk out.
5. Verify the received Pokémon is in the Switch's saved party/boxes.

The runner supplies the selected file in both simulated party slots: slot 0
stays with the simulated trainer; slot 1 is offered once. Each attempt gets its
own source snapshot and `received.pk3` backup. The original remains intact.

The attempt stays in **review** until you verify the console result:

```sh
python3 frlgdex.py resolve --workspace ./transfers ATTEMPT_ID confirmed
```

If you verified the Switch did **not** receive it, use `not_traded` instead.
Do not resolve uncertain results or resolve while the trader is running.
A received file or successful process exit does not prove the console saved.
Unresolved attempts block further sends, including after crashes. If the
workspace was created as root, use sudo for ledger updates too.

## Changes and validation

- Offline audit, full species mapping, and a persistent SQLite transfer ledger.
- Explicit `.pk3`/`.ek3` decoding, including zero-XOR-key Pokémon.
- Corrupt-file rejection before radio access.
- Fixed upstream's undefined `args` reference that broke backups at commit.
  Backup failures are retried and file replacement is atomic.
- Platform/key/radio preflight and strict FRLG network selection.
- Pokémon, saves, keys, captures, and transfer databases excluded from Git.

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Tests use generated structures, never user saves or key material. They cover
all species, substructure permutations, shiny boundaries, corrupt files,
evolution checks, interrupted transfers, duplicate attempts, source integrity,
offline operation, and immediate/atomic received-Pokémon backups.

The original entry point remains `frlgtrade.py`.
See [upstream documentation](docs/UPSTREAM.md).

## Credits and license

[tornadus/frlg-ldn-trade](https://github.com/tornadus/frlg-ldn-trade),
[kinnay/LDN](https://github.com/kinnay/LDN), and
[pret/pokefirered](https://github.com/pret/pokefirered).
AGPL-3.0; see [LICENSE](LICENSE).
