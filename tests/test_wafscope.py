"""Behavioural tests: wafscope against a local simulator (tests/mock_server.py).

Run with:  python3 -m unittest discover -s tests -v
No network access is needed; every target is 127.0.0.1.
"""
import json
import os
import socket
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import wafscope  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, mode):
        self.port = free_port()
        self.proc = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_server.py"), mode, str(self.port)])
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("mock server did not start")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)


def scan(mode):
    srv = Server(mode)
    try:
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "wafscope.py"), f"http://127.0.0.1:{srv.port}/",
             "--json", "--timeout", "3"], capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout), out.returncode
    finally:
        srv.stop()


class ModeTests(unittest.TestCase):
    def test_cloudflare_is_identified_and_blocking_is_confirmed(self):
        res, code = scan("cloudflare")
        self.assertEqual(res["vendors"][0]["vendor"], "Cloudflare")
        self.assertGreaterEqual(res["vendors"][0]["confidence"], 0.75)
        self.assertTrue(res["vendors"][0]["blocking_confirmed"])
        self.assertTrue(res["enforcing"])
        self.assertTrue(all(p["blocked"] for p in res["probes"]))
        self.assertEqual(code, 0)

    def test_generic_waf_blocks_without_vendor(self):
        res, _ = scan("generic")
        self.assertEqual(res["vendors"], [])
        self.assertTrue(res["enforcing"])
        self.assertGreaterEqual(res["generic_confidence"], 0.75)

    def test_silent_connection_drop_counts_as_blocking(self):
        res, _ = scan("silent")
        self.assertTrue(res["enforcing"])
        self.assertTrue(all("connection" in p["reason"] for p in res["probes"] if p["blocked"]))

    def test_soft_block_with_http_200_is_detected(self):
        res, _ = scan("soft")
        self.assertTrue(res["enforcing"])
        self.assertTrue(any("soft block" in p["reason"] for p in res["probes"]))

    def test_plain_site_reports_no_evidence(self):
        res, code = scan("none")
        self.assertFalse(res["enforcing"])
        self.assertEqual(res["vendors"], [])
        self.assertEqual(res["generic_confidence"], 0)
        self.assertEqual(code, 1)

    def test_closed_port_is_an_error(self):
        out = subprocess.run([sys.executable, os.path.join(ROOT, "wafscope.py"),
                              f"http://127.0.0.1:{free_port()}/", "--json", "--timeout", "2"],
                             capture_output=True, text=True, timeout=20)
        self.assertEqual(out.returncode, 2)
        self.assertIn("error", json.loads(out.stdout))


class SignatureTests(unittest.TestCase):
    def test_every_signature_is_well_formed(self):
        kinds = {"hdr", "hdrre", "hdrv", "cookie", "body", "cname", "cert", "ip"}
        for vendor, sigs in wafscope.SIGS.items():
            for sig in sigs:
                self.assertEqual(len(sig), 4, (vendor, sig))
                kind, pattern, weight, desc = sig
                self.assertIn(kind, kinds, (vendor, sig))
                self.assertTrue(0 < weight <= 1, (vendor, sig))
                self.assertTrue(desc.strip(), (vendor, sig))

    def test_radware_cloud_cname_is_scored(self):
        # Regression: a CNAME to radwarecloud.net was shown but never scored.
        dns = {"ips": ["192.0.2.1"], "cnames": ["abc123.v1.radwarecloud.net"]}
        res = wafscope.collect([("baseline", wafscope.Resp(status=200))], set(), {}, dns, None)
        self.assertGreaterEqual(res["Radware AppWall"]["confidence"], 0.8)

    def test_noisy_or_is_capped_and_monotonic(self):
        r = wafscope.Resp(status=200, headers=[("server", "cloudflare"), ("cf-ray", "x")])
        one = wafscope.collect([("b", wafscope.Resp(headers=[("cf-ray", "x")]))], set(), {}, {}, None)
        two = wafscope.collect([("b", r)], set(), {}, {}, None)
        self.assertGreater(two["Cloudflare"]["confidence"], one["Cloudflare"]["confidence"])
        self.assertLessEqual(two["Cloudflare"]["confidence"], 0.99)


if __name__ == "__main__":
    unittest.main()
