import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from frlgsim.collection import Workspace, audit, inspect_file
from frlgsim.mon import Mon, to_decrypted, to_encrypted
from frlgsim.preflight import check_keys, diagnose, KEY_NAMES
from frlgsim.species import SPECIES
import frlgdex


def specimen(species=1, *, pid=1, otid=1, item=0, size=80, flags=2, egg=False):
    """Synthetic checksummed structure; no user Pokemon or keys in fixtures."""
    data = bytearray(size)
    data[0:4] = pid.to_bytes(4, "little")
    data[4:8] = otid.to_bytes(4, "little")
    data[8:18] = b"\xff" * 10
    data[18:20] = bytes([2, flags])
    data[20:27] = b"\xff" * 7
    data[32:34] = species.to_bytes(2, "little")
    data[34:36] = item.to_bytes(2, "little")
    data[36:40] = (1000).to_bytes(4, "little")
    data[44:46] = (33).to_bytes(2, "little")
    data[72:76] = (0x3fffffff | ((1 << 30) if egg else 0)).to_bytes(4, "little")
    checksum = sum(int.from_bytes(data[i:i+2], "little") for i in range(32, 80, 2)) & 65535
    data[28:30] = checksum.to_bytes(2, "little")
    return bytes(data)


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()

    def write(self, name="one.pk3", **kwargs):
        path = self.source / name
        path.write_bytes(specimen(**kwargs))
        return path

    def workspace(self):
        workspace = Workspace(self.root / "transfers")
        self.addCleanup(workspace.close)
        workspace.import_report(audit(self.source))
        return workspace

    def test_all_386_species_are_audited_in_national_order(self):
        for species in SPECIES:
            self.write(f"{species}.pk3", species=species)
        report = audit(self.source)
        self.assertEqual(report["unique_species"], 386)
        self.assertEqual(report["shiny_species"], 386)
        self.assertEqual(report["missing_dex"], [])
        self.assertEqual(report["errors"], [])
        self.assertEqual(SPECIES[411], (358, "Chimecho"))
        self.assertEqual(SPECIES[410], (386, "Deoxys"))

    def test_shiny_boundary_and_trade_evolution(self):
        shiny = self.write("shiny.pk3", pid=1, otid=6)
        normal = self.write("normal.pk3", pid=1, otid=9)
        self.assertTrue(inspect_file(shiny)["shiny"])
        self.assertFalse(inspect_file(normal)["shiny"])
        kadabra = self.write("kadabra.pk3", species=64)
        self.assertEqual(inspect_file(kadabra)["evolves_to"], "Alakazam")
        kadabra.write_bytes(specimen(species=64, item=195))
        self.assertIsNone(inspect_file(kadabra)["evolves_to"])
        clamperl = self.write("clamperl.pk3", species=373, item=193)
        self.assertEqual(inspect_file(clamperl)["evolves_to"], "Gorebyss")

    def test_bad_files_are_reported_without_rewriting(self):
        invalid = self.write("corrupt.pk3")
        data = bytearray(invalid.read_bytes())
        data[40] ^= 1
        invalid.write_bytes(data)
        self.write("empty.pk3", species=0)
        self.write("egg.pk3", egg=True)
        self.write("bad-egg.pk3", flags=3)
        (self.source / "short.pk3").write_bytes(b"not a pokemon")
        report = audit(self.source)
        self.assertEqual(len(report["errors"]), 5)
        self.assertEqual(invalid.read_bytes(), data)

    def test_all_shuffle_orders_and_zero_xor_key_round_trip(self):
        for pid in range(24):
            for size in (80, 100):
                canonical = specimen(pid=pid, otid=pid, size=size)
                encrypted = to_encrypted(canonical)
                self.assertEqual(to_decrypted(encrypted), canonical)
                for suffix, data in (("pk3", canonical), ("ek3", encrypted)):
                    path = self.source / f"mon.{suffix}"
                    path.write_bytes(data)
                    loaded = Mon.from_file(path)
                    self.assertEqual(to_decrypted(loaded.raw)[:80], canonical[:80])
                    self.assertFalse(loaded.is_empty)
                    self.assertTrue(loaded.checksum_ok)

    def test_crash_requires_review_and_does_not_advance_collection(self):
        original = self.write()
        workspace = self.workspace()
        attempt, offer, received, entry = workspace.prepare()
        self.assertEqual(offer.read_bytes(), original.read_bytes())
        # Even a received file and successful process exit are insufficient proof.
        Mon.from_file(offer).save_pk3(received)
        workspace.record_exit(attempt, 0)
        with self.assertRaisesRegex(ValueError, "review"):
            workspace.next_entry()
        workspace.import_report(audit(self.source))
        self.assertEqual(workspace.rows()[0]["status"], "review")
        second = Workspace(workspace.root)
        self.addCleanup(second.close)
        with self.assertRaisesRegex(ValueError, "review"):
            second.prepare()
        workspace.resolve(attempt, "confirmed")
        self.assertIsNone(workspace.next_entry())
        self.assertEqual(original.read_bytes(), specimen())
        with self.assertRaises(ValueError):
            workspace.resolve(attempt, "not_traded")

    def test_retry_has_fresh_backups_and_changed_source_is_rejected(self):
        original = self.write()
        workspace = self.workspace()
        first, offer, _, _ = workspace.prepare()
        workspace.resolve(first, "not_traded")
        second, new_offer, _, _ = workspace.prepare()
        self.assertNotEqual(offer, new_offer)
        self.assertTrue(offer.exists())
        workspace.resolve(second, "not_traded")
        original.write_bytes(specimen(species=2))
        with self.assertRaisesRegex(ValueError, "source file changed"):
            workspace.prepare()
        self.assertIsNone(workspace.unresolved())

    def test_evolution_requires_intent_and_workspace_cannot_contaminate_inputs(self):
        self.write(species=64)
        workspace = self.workspace()
        with self.assertRaisesRegex(ValueError, "evolve"):
            workspace.prepare()
        self.assertIsNone(workspace.unresolved())
        workspace.prepare(allow_evolution=True)
        inside = Workspace(self.source / "transfers")
        self.addCleanup(inside.close)
        with self.assertRaisesRegex(ValueError, "outside"):
            inside.import_report(audit(self.source))

    def test_offline_cli_without_site_packages(self):
        self.write()
        command = [sys.executable, "-S", str(Path(frlgdex.__file__)), "audit", str(self.source), "--json"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["valid_files"], 1)

    def test_preview_and_missing_prerequisites_never_launch_or_claim(self):
        self.write()
        workspace = self.workspace()
        for live in (False, True):
            argv = ["trade", "--workspace", str(workspace.root)] + (["--live"] if live else [])
            with patch("frlgdex.diagnose", return_value={"errors": ["missing keys"]}), \
                 patch("frlgdex.subprocess.Popen") as launch, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(frlgdex.main(argv), 2 if live else 0)
                launch.assert_not_called()
            self.assertIsNone(workspace.unresolved())


class PrerequisiteTests(unittest.TestCase):
    def test_key_errors_do_not_expose_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prod.keys"
            self.assertIn("missing", check_keys(path))
            path.write_text("private = DO-NOT-PRINT-THIS")
            self.assertNotIn("DO-NOT-PRINT-THIS", check_keys(path))
            path.write_text("\n".join(name + " = " + "ab" * 16 for name in KEY_NAMES))
            self.assertIsNone(check_keys(path))

    def test_macos_never_runs_linux_commands(self):
        with patch("frlgsim.preflight.platform.system", return_value="Darwin"), \
             patch("frlgsim.preflight.subprocess.run") as run:
            report = diagnose("/nonexistent/prod.keys")
            self.assertTrue(any("Linux" in e for e in report["errors"]))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
