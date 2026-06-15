"""Smoke + behavior tests for UASLOG. Standard library only, no network."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import uaslog
from uaslog.core import (
    analyze,
    classify_rf_band,
    parse_log,
    ParseError,
    SEVERITY_ORDER,
)
from uaslog.cli import main

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEMO = os.path.join(REPO_ROOT, "demos", "01-basic", "detections.jsonl")


class TestMeta(unittest.TestCase):
    def test_exports(self):
        self.assertEqual(uaslog.TOOL_NAME, "uaslog")
        self.assertTrue(uaslog.TOOL_VERSION)
        self.assertTrue(hasattr(uaslog, "parse_log"))
        self.assertTrue(hasattr(uaslog, "analyze"))


class TestParsing(unittest.TestCase):
    def test_parse_jsonl(self):
        text = (
            '{"timestamp": "2026-01-01T00:00:00Z", "track_id": "x", "freq_mhz": 2437}\n'
            '{"timestamp": "2026-01-01T00:00:01Z", "track_id": "x", "freq_mhz": 2437}\n'
        )
        events = parse_log(text)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].track_id, "x")
        self.assertEqual(events[0].freq_mhz, 2437.0)

    def test_parse_csv(self):
        text = (
            "timestamp,track_id,freq_mhz,rssi_dbm\n"
            "2026-01-01T00:00:00Z,k,915,-60\n"
        )
        events = parse_log(text)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].track_id, "k")
        self.assertEqual(events[0].rssi_dbm, -60.0)

    def test_parse_json_array(self):
        events = parse_log('[{"track_id": "a", "freq_mhz": 5800}]')
        self.assertEqual(len(events), 1)

    def test_empty_raises(self):
        with self.assertRaises(ParseError):
            parse_log("   ")

    def test_garbage_raises(self):
        with self.assertRaises(ParseError):
            parse_log("!!!not a log!!!")


class TestRfClassification(unittest.TestCase):
    def test_24ghz(self):
        cls = classify_rf_band(2437.0)
        self.assertIsNotNone(cls)
        self.assertFalse(cls[1])  # unauthorized/monitored

    def test_unmatched(self):
        self.assertIsNone(classify_rf_band(123.0))

    def test_none(self):
        self.assertIsNone(classify_rf_band(None))


class TestAnalysis(unittest.TestCase):
    def setUp(self):
        with open(DEMO, "r", encoding="utf-8") as fh:
            self.events = parse_log(fh.read())
        self.result = analyze(self.events)

    def test_codes_present(self):
        codes = {f.code for f in self.result.findings}
        self.assertIn("RF_UNAUTHORIZED_BAND", codes)
        self.assertIn("TRACK_TELEPORT", codes)
        self.assertIn("SWARM", codes)
        self.assertIn("LOITER", codes)

    def test_swarm_is_critical(self):
        swarm = [f for f in self.result.findings if f.code == "SWARM"]
        self.assertEqual(len(swarm), 1)
        self.assertEqual(swarm[0].severity, "critical")

    def test_gnss_high(self):
        gnss = [f for f in self.result.findings
                if f.code == "RF_UNAUTHORIZED_BAND" and "GNSS" in f.detail.get("band", "")]
        self.assertTrue(gnss)
        self.assertEqual(gnss[0].severity, "high")

    def test_max_severity(self):
        self.assertEqual(self.result.max_severity, "critical")

    def test_findings_sorted_by_severity(self):
        ranks = [SEVERITY_ORDER[f.severity] for f in self.result.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_stats(self):
        self.assertEqual(self.result.stats["event_count"], len(self.events))
        self.assertGreaterEqual(self.result.stats["track_count"], 3)

    def test_clean_log_no_findings(self):
        text = (
            '{"timestamp": "2026-01-01T00:00:00Z", "track_id": "q", "freq_mhz": 100.0, "rssi_dbm": -80}\n'
        )
        res = analyze(parse_log(text))
        self.assertEqual(res.findings, [])
        self.assertEqual(res.max_severity, "info")


class TestCli(unittest.TestCase):
    def test_analyze_table_returns_nonzero(self):
        rc = main(["analyze", DEMO])
        self.assertEqual(rc, 1)  # findings present

    def test_analyze_json(self):
        rc = main(["analyze", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)

    def test_clean_returns_zero(self):
        import tempfile
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as tf:
            tf.write('{"track_id": "q", "freq_mhz": 100.0, "rssi_dbm": -90}\n')
            path = tf.name
        try:
            rc = main(["analyze", path])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_min_severity_gating(self):
        # With threshold critical, demo still has a SWARM -> exit 1.
        self.assertEqual(main(["analyze", DEMO, "--min-severity", "critical"]), 1)

    def test_no_command_returns_2(self):
        self.assertEqual(main([]), 2)

    def test_bad_path_returns_2(self):
        self.assertEqual(main(["analyze", "/no/such/file.jsonl"]), 2)

    def test_subprocess_json_valid(self):
        proc = subprocess.run(
            [sys.executable, "-m", "uaslog", "analyze", DEMO, "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertIn("findings", data)
        self.assertEqual(data["max_severity"], "critical")

    def test_version_flag(self):
        proc = subprocess.run(
            [sys.executable, "-m", "uaslog", "--version"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("uaslog", proc.stdout)


class TestHardeningEdgeCases(unittest.TestCase):
    """Tests added during production hardening — cover error/edge paths."""

    # ------------------------------------------------------------------
    # Input validation: bad lat/lon/freq are silently coerced to None
    # ------------------------------------------------------------------

    def test_out_of_range_lat_becomes_none(self):
        """Latitude outside ±90 should be treated as missing."""
        text = '{"track_id": "t1", "lat": 999.0, "lon": 10.0}\n'
        events = parse_log(text)
        self.assertIsNone(events[0].lat)

    def test_out_of_range_lon_becomes_none(self):
        """Longitude outside ±180 should be treated as missing."""
        text = '{"track_id": "t1", "lat": 10.0, "lon": -999.0}\n'
        events = parse_log(text)
        self.assertIsNone(events[0].lon)

    def test_negative_freq_becomes_none(self):
        """Negative frequency is physically impossible; should be dropped."""
        text = '{"track_id": "t1", "freq_mhz": -100.0}\n'
        events = parse_log(text)
        self.assertIsNone(events[0].freq_mhz)

    def test_zero_freq_becomes_none(self):
        """Zero frequency is meaningless; should be dropped."""
        text = '{"track_id": "t1", "freq_mhz": 0.0}\n'
        events = parse_log(text)
        self.assertIsNone(events[0].freq_mhz)

    # ------------------------------------------------------------------
    # haversine: floating-point edge case — identical positions
    # ------------------------------------------------------------------

    def test_haversine_identical_points_no_exception(self):
        """Same lat/lon pair should return 0 without raising."""
        from uaslog.core import _haversine_m
        self.assertAlmostEqual(_haversine_m(45.0, 90.0, 45.0, 90.0), 0.0)

    # ------------------------------------------------------------------
    # analyze: empty event list is valid (no findings, zero stats)
    # ------------------------------------------------------------------

    def test_analyze_empty_events(self):
        """analyze([]) must succeed and return zero-count stats."""
        from uaslog.core import analyze
        result = analyze([])
        self.assertEqual(result.stats["event_count"], 0)
        self.assertEqual(result.stats["finding_count"], 0)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.max_severity, "info")

    # ------------------------------------------------------------------
    # CLI: binary / non-UTF-8 file returns exit code 2
    # ------------------------------------------------------------------

    def test_binary_file_returns_2(self):
        """A binary file that cannot be decoded as UTF-8 should exit 2."""
        import tempfile
        with tempfile.NamedTemporaryFile(
            "wb", suffix=".bin", delete=False
        ) as tf:
            tf.write(bytes(range(256)))  # guaranteed non-UTF-8 bytes
            path = tf.name
        try:
            rc = main(["analyze", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # mcp_server: module imports cleanly (no broken scan/to_json refs)
    # ------------------------------------------------------------------

    def test_mcp_server_imports(self):
        """mcp_server must be importable without raising ImportError."""
        import importlib
        try:
            mod = importlib.import_module("uaslog.mcp_server")
        except ImportError as exc:
            self.fail(f"mcp_server import raised ImportError: {exc}")
        self.assertTrue(callable(mod.serve))

    # ------------------------------------------------------------------
    # CSV: header-only file (no data rows) raises ParseError
    # ------------------------------------------------------------------

    def test_csv_header_only_raises(self):
        """CSV with only a header row and no data should raise ParseError."""
        with self.assertRaises(ParseError):
            parse_log("timestamp,track_id,freq_mhz\n")


if __name__ == "__main__":
    unittest.main()
