from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import frlgtrade
from frlgsim import config, trade_runtime
from frlgsim.mon import Mon
from test_collection import specimen


class RuntimeTests(unittest.TestCase):
    def test_commit_is_backed_up_before_link_teardown(self):
        """Regression: run_live formerly passed an undefined global 'args'."""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "offer.pk3"
            source.write_bytes(specimen())
            received = Path(directory) / "received.pk3"
            pokemon = Mon.from_file(source)
            run = config.TradeRunConfig(
                config.DEFAULT_TRAINER,
                config.TradePlan(party_paths=(str(source), str(source)), output_path=str(received)),
                config.LdnConfig(), config.JoinerOptions())
            engine = SimpleNamespace(commits=0, received_mons=[], received_mon=None)
            transport = Mock(ssid=b"\0" * 16, our_mac=b"a" * 6, host_mac=b"b" * 6,
                             our_ip="169.254.1.2", host_ip="169.254.1.1")
            simulator = SimpleNamespace(ni_rejected=False, host_disconnected=True, close=Mock())

            def tick():
                engine.commits = 1
                engine.received_mons = [pokemon]

            simulator.tick = tick
            log = trade_runtime.ConsoleLog(False, output=lambda *a: None)
            with patch("frlgtrade.make_engine", return_value=engine), \
                 patch("frlgtrade.tmod.LiveTransport") as adapter, \
                 patch("frlgtrade.simmod.Sim", return_value=simulator), \
                 patch("frlgtrade.pia_connect.ConnectionManager"), \
                 patch("builtins.print"):
                adapter.return_value.start.return_value = transport
                transport.stop.side_effect = lambda: self.assertTrue(received.exists())
                frlgtrade.run_live(run, log)
            self.assertEqual(Mon.from_file(received).box_bytes(), pokemon.box_bytes())

    def test_corrupt_party_is_rejected_before_radio_access(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "invalid.pk3"
            source.write_bytes(b"\xff" * 80)
            run = config.TradeRunConfig(
                config.DEFAULT_TRAINER,
                config.TradePlan(party_paths=(str(source), str(source))),
                config.LdnConfig(), config.JoinerOptions())
            with patch("frlgtrade.tmod.LiveTransport") as transport:
                with self.assertRaises(ValueError):
                    frlgtrade.run_live(run, trade_runtime.ConsoleLog(False, output=lambda *a: None))
                transport.assert_not_called()

    def test_failed_atomic_save_preserves_previous_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "received.pk3"
            original = specimen()
            destination.write_bytes(original)
            pokemon = Mon.from_pk3(specimen(species=2), encrypted=False)
            with patch("os.replace", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    pokemon.save_pk3(destination)
            self.assertEqual(destination.read_bytes(), original)
            self.assertEqual(list(Path(directory).iterdir()), [destination])


if __name__ == "__main__":
    unittest.main()
