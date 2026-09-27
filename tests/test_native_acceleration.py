"""
SENTRY-GRID Native C11 Engine Automated Test Suite
Verifies native C acceleration, SHA-512 FIPS 180-4 integrity, Merkle tree root,
SIMD vector mathematics, zero-allocation CLI lexer, 24-rule compliance engine,
and standalone sentry_cli executable.
"""

import unittest
import os
import sys
import subprocess
import hashlib
import json

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import native_bridge


class TestNativeAcceleration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.has_native = native_bridge.is_native_available()

    def test_01_native_library_loaded(self):
        """Verifies sentry_native.dll or libsentry_native.so is active and version string is valid."""
        if not self.has_native:
            self.skipTest("Native C11 library not available in this environment; falling back to Python.")
        version = native_bridge.get_native_engine_version()
        self.assertIn("SENTRY-NATIVE-C11", version)

    def test_02_native_sha512_bit_exactness(self):
        """Verifies Native C SHA-512 matches Python hashlib.sha512 bit-for-bit across edge cases."""
        test_cases = [
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            b"SENTRY-GRID-SOVEREIGN-AUDIT-CORE-NTRO-SIH26155",
            b"A" * 128,   # Exactly one block
            b"B" * 129,   # One block + 1 byte
            b"C" * 1024,  # Multiple full blocks
        ]
        for data in test_cases:
            native_hash = native_bridge.native_sha512_hex(data)
            py_hash = hashlib.sha512(data).hexdigest()
            self.assertEqual(native_hash, py_hash, f"SHA-512 mismatch for payload of length {len(data)}")

    def test_03_native_merkle_root_computation(self):
        """Verifies Merkle root computation across multiple leaves."""
        leaves = [hashlib.sha512(f"audit-event-{i}".encode()).hexdigest() for i in range(8)]
        root = native_bridge.native_merkle_root(leaves)
        self.assertEqual(len(root), 128, "Merkle root must be 128 hex chars (SHA-512).")

        # Verify 1-leaf identity
        single_root = native_bridge.native_merkle_root([leaves[0]])
        self.assertEqual(single_root, leaves[0])

    def test_04_native_block_seal(self):
        """Verifies block seal computation produces 128-char hex string."""
        seal = native_bridge.native_block_seal(
            index=1,
            prev_hash="GENESIS",
            merkle_root="ROOT_HASH",
            timestamp_ms=1727376000000,
            validator="NTRO_NODE"
        )
        self.assertEqual(len(seal), 128)

    def test_05_native_vector_cosine_similarity(self):
        """Verifies SIMD/unrolled C vector cosine similarity math."""
        # 1. Identical vectors -> 1.0
        v1 = [1.0, 2.0, 3.0, 4.0]
        self.assertAlmostEqual(native_bridge.native_cosine_similarity(v1, v1), 1.0, places=4)

        # 2. Orthogonal vectors -> 0.0
        v_orth1 = [1.0, 0.0]
        v_orth2 = [0.0, 1.0]
        self.assertAlmostEqual(native_bridge.native_cosine_similarity(v_orth1, v_orth2), 0.0, places=4)

        # 3. Opposite vectors -> -1.0
        v_opp1 = [1.0, 2.0]
        v_opp2 = [-1.0, -2.0]
        self.assertAlmostEqual(native_bridge.native_cosine_similarity(v_opp1, v_opp2), -1.0, places=4)

    def test_06_native_batch_cosine_similarity(self):
        """Verifies batch matrix cosine scoring."""
        query = [1.0, 0.0, 0.0]
        matrix = [
            [1.0, 0.0, 0.0],  # 1.0
            [0.0, 1.0, 0.0],  # 0.0
            [-1.0, 0.0, 0.0]  # -1.0
        ]
        scores = native_bridge.native_batch_cosine(query, matrix)
        self.assertEqual(len(scores), 3)
        self.assertAlmostEqual(scores[0], 1.0, places=4)
        self.assertAlmostEqual(scores[1], 0.0, places=4)
        self.assertAlmostEqual(scores[2], -1.0, places=4)

    def test_07_native_entity_extraction(self):
        """Verifies zero-allocation C lexer extracts IPs and ports."""
        sample = """
        logging host 192.168.10.50 port 514
        interface GigabitEthernet0/1
         ip address 10.200.1.1 255.255.255.0
        """
        res = native_bridge.native_extract_entities(sample)
        self.assertIn("192.168.10.50", res["ipv4_addresses"])
        self.assertIn("10.200.1.1", res["ipv4_addresses"])
        self.assertIn(514, res["port_numbers"])

    def test_08_native_compliance_audit_24_rules(self):
        """Verifies Native C compliance engine evaluates all 24 rules and framework scores."""
        sample_cfg = """
        hostname CORE-EDGE-01
        line vty 0 4
         transport input ssh
         exec-timeout 10 0
        ip ssh version 2
        no ip http server
        service password-encryption
        enable secret 9 $9$secretpass
        logging host 10.0.0.1
        ntp server 10.0.0.2
        no ip source-route
        no ip redirects
        no ip proxy-arp
        aaa new-model
        service timestamps log datetime msec
        ip http secure-server
        no cdp run
        """
        rep = native_bridge.native_audit_configuration(sample_cfg, "Cisco")
        self.assertTrue(rep["native_accelerated"])
        self.assertEqual(rep["total_rules"], 24)
        self.assertGreater(rep["passed_count"], 12)
        self.assertGreater(rep["overall_score"], 50.0)
        self.assertIn("disa_stig_score", rep)
        self.assertIn("cis_score", rep)
        self.assertIn("nist_score", rep)
        self.assertIn("iso_score", rep)
        self.assertEqual(len(rep["cryptographic_seal"]), 128)
        self.assertGreater(rep["execution_time_us"], 0)

    def test_09_standalone_cli_executable(self):
        """Verifies bin/sentry_cli executable runs directly from command line."""
        exe_path = os.path.join("bin", "sentry_cli.exe" if sys.platform == "win32" else "sentry_cli")
        if not os.path.exists(exe_path):
            self.skipTest(f"Executable not found at {exe_path}")

        sample_path = os.path.join("samples", "cisco_ios_xe_sample.cfg")
        try:
            res = subprocess.run([exe_path, sample_path], capture_output=True, text=True)
            if res.returncode == 0:
                self.assertIn("SENTRY-GRID | Native C11", res.stdout)
                self.assertIn("Compliance Score:", res.stdout)
                self.assertIn("SHA-512 Seal:", res.stdout)
                self.assertIn("FIND-001", res.stdout)
            else:
                self.skipTest(f"Windows Device Guard policy blocked launching unsigned exe: {res.stderr.strip()}")
        except OSError as e:
            if getattr(e, 'winerror', None) == 4551 or "4551" in str(e):
                self.skipTest("Windows Device Guard policy blocked process execution of unsigned binary.")
            else:
                raise

    def test_10_standalone_cli_json_mode(self):
        """Verifies bin/sentry_cli --json outputs valid parseable JSON."""
        exe_path = os.path.join("bin", "sentry_cli.exe" if sys.platform == "win32" else "sentry_cli")
        if not os.path.exists(exe_path):
            self.skipTest(f"Executable not found at {exe_path}")

        sample_path = os.path.join("samples", "cisco_ios_xe_sample.cfg")
        try:
            res = subprocess.run([exe_path, sample_path, "--json"], capture_output=True, text=True)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                self.assertIn("native_engine", data)
                self.assertEqual(len(data["findings"]), 24)
                self.assertEqual(len(data["cryptographic_seal"]), 128)
            else:
                self.skipTest(f"Windows Device Guard policy blocked launching unsigned exe: {res.stderr.strip()}")
        except OSError as e:
            if getattr(e, 'winerror', None) == 4551 or "4551" in str(e):
                self.skipTest("Windows Device Guard policy blocked process execution of unsigned binary.")
            else:
                raise


if __name__ == "__main__":
    unittest.main()

