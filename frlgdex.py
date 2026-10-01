#!/usr/bin/env python3
"""Audit a Gen-3 collection and guide one-at-a-time trades to Switch FireRed/LeafGreen.

doctor/audit/init/status/resolve work offline with the Python standard library.
trade uses the upstream Linux LDN transport and needs its runtime dependencies.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

from frlgsim.collection import Workspace, audit
from frlgsim.preflight import diagnose


def show_audit(report):
    print(f"{report['valid_files']} valid files; {report['unique_species']}/386 species; "
          f"{report['shiny_species']}/386 shiny species.")
    for label, key in (("Missing Dex numbers", "missing_dex"),
                       ("Duplicate species", "duplicate_species")):
        if report[key]:
            print(f"{label}: " + ", ".join(map(str, report[key])))
    for entry in sorted(report["entries"], key=lambda e: (e["dex"], e["path"])):
        for warning in entry["warnings"]:
            print(f"#{entry['dex']:03} {entry['name']}: {warning}")
    for error in report["errors"]:
        print(f"INVALID {error['path']}: {error['error']}")
    if not report["valid_files"]:
        print("No valid .pk3/.ek3 files found.")
    print("Checks verify data structure and shiny status, not encounter legality or live compatibility.")


def show_status(workspace):
    rows = workspace.rows()
    counts = Counter(row["status"] for row in rows)
    confirmed_dex = {row["dex"] for row in rows if row["status"] == "confirmed"}
    print(f"{len(rows)} files imported. Confirmed species: {len(confirmed_dex)}/386. "
          f"Pending: {counts['pending']}; review: {counts['review']}; confirmed files: {counts['confirmed']}.")
    for row in rows:
        star = "shiny" if row["shiny"] else "normal"
        print(f"{row['dex']:03}  {row['name']:<12}  {star:<6}  {row['status']}")
    unresolved = workspace.unresolved()
    if unresolved:
        print(f"\nAttempt needing review: {unresolved['id']}")
        print("Verify the Switch's saved party/boxes, then resolve as confirmed or not_traded.")


def run_trade(workspace, args):
    entry = workspace.next_entry()
    if not entry:
        print("No pending Pokemon. Use init to import a collection.")
        return 0
    print(f"Next: #{entry['dex']:03} {entry['name']} (level {entry['level']}, "
          f"{'shiny' if entry['shiny'] else 'not shiny'}).")
    for warning in entry["warnings"]:
        print(warning)
    report = diagnose(args.keys, args.phy, require_root=True)
    for message in report["errors"]:
        print("BLOCKED: " + message)
    if not args.live:
        print("Preview only. No radio access, attempt, or Pokemon output was created.")
        print("When prerequisites pass, add --live to start one trade.")
        return 0
    if report["errors"]:
        return 2
    attempt, offer, received, _ = workspace.prepare(allow_evolution=args.allow_evolution)
    command = [sys.executable, str(Path(__file__).with_name("frlgtrade.py")), "--live",
               "--phy", args.phy, "--keys", str(Path(args.keys).expanduser().resolve()),
               "--slot", "1", "--trades", "1", "--verbose", "-o", str(received),
               str(offer), str(offer)]
    print("\nOn the Switch: Direct Corner → Trade Center → Become Leader.")
    print("Accept EMU, enter the room, sit in the left chair, and choose trade fodder.")
    print("After the trade saves, cancel the trade menu and walk out of the room.")
    print(f"Attempt: {attempt}\nReceived backup: {received}", flush=True)
    code = 1
    try:
        # Preserve the terminal for the upstream graceful Ctrl+C handler. The ledger
        # remains 'review' even on a crash or a zero return code.
        child = subprocess.Popen(command)
        while True:
            try:
                code = child.wait()
                break
            except KeyboardInterrupt:
                # The terminal also sends SIGINT to the child. Let its first
                # interrupt finish the link gracefully; its second forces exit.
                print("Waiting for the trader to close; Ctrl+C again forces its exit.")
    except OSError as exc:
        print(f"Could not launch trader: {exc}")
    finally:
        workspace.record_exit(attempt, code)
    print("\nVerify that the Pokemon is in the Switch's saved party/boxes.")
    print(f"Then run: python3 frlgdex.py resolve --workspace {str(workspace.root)!r} "
          f"{attempt} confirmed")
    print("Use not_traded only if you verified it was not received. Uncertain attempts stay in review.")
    return code


def parser():
    ap = argparse.ArgumentParser(description=__doc__)
    commands = ap.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="read-only platform, keys, and Wi-Fi checks")
    doctor.add_argument("--json", action="store_true")
    for name in ("audit", "init"):
        command = commands.add_parser(name, help="inspect collection" if name == "audit" else "import a collection")
        command.add_argument("directory")
        if name == "audit":
            command.add_argument("--json", action="store_true")
        else:
            command.add_argument("--workspace", default="transfers")
    status = commands.add_parser("status", help="show confirmed, pending, and uncertain transfers")
    trade = commands.add_parser("trade", help="preview next Pokemon; --live starts one trade")
    resolve = commands.add_parser("resolve", help="record your verification of an attempted trade")
    for command in (status, trade, resolve):
        command.add_argument("--workspace", default="transfers")
    for command in (doctor, trade):
        command.add_argument("--keys", default="~/.switch/prod.keys")
        command.add_argument("--phy", default="phy0")
    trade.add_argument("--live", action="store_true")
    trade.add_argument("--allow-evolution", action="store_true",
                       help="intentionally allow the offered species to evolve on the Switch")
    resolve.add_argument("attempt")
    resolve.add_argument("outcome", choices=("confirmed", "not_traded"))
    return ap


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            report = diagnose(args.keys, args.phy)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(f"{report['platform']} / {report['architecture']}")
                for message in report["errors"]:
                    print("BLOCKED: " + message)
                for note in report["notes"]:
                    print(note)
            return 2 if report["errors"] else 0
        if args.command in ("audit", "init"):
            report = audit(args.directory)
            if args.command == "audit":
                if args.json:
                    print(json.dumps(report, indent=2, ensure_ascii=False))
                else:
                    show_audit(report)
                return 1 if report["errors"] or not report["entries"] else 0
            show_audit(report)
            if report["errors"] or not report["entries"]:
                return 1
            if Path(args.workspace).expanduser().resolve().is_relative_to(Path(report["root"])):
                raise ValueError("workspace must be outside the source collection")
        elif not (Path(args.workspace).expanduser() / "collection.sqlite3").is_file():
            raise ValueError("workspace not initialized; run init with your collection directory first")
        workspace = Workspace(args.workspace)
        try:
            if args.command == "init":
                workspace.import_report(report)
                print(f"Collection imported into {workspace.root}; source files were not modified.")
            elif args.command == "status":
                show_status(workspace)
            elif args.command == "trade":
                return run_trade(workspace, args)
            elif args.command == "resolve":
                workspace.resolve(args.attempt, args.outcome)
                print(f"Attempt {args.attempt}: {args.outcome}.")
        finally:
            workspace.close()
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
