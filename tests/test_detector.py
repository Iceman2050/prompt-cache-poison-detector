"""Tests for prompt-cache-poison-detector. Run: python -m unittest discover -s tests -v"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_cache_poison_detector import (
    Tenant,
    TenantCacheSimulator,
    derive_key_anonymized,
    derive_key_tenant_scoped,
    run_detection,
)
from prompt_cache_poison_detector.cache_schemes import DERIVE_FNS, SCHEMES


class TestKeyDerivation(unittest.TestCase):
    def test_tenant_scoped_differs_across_tenants(self):
        a = derive_key_tenant_scoped("hello world", "tenant-a")
        b = derive_key_tenant_scoped("hello world", "tenant-b")
        self.assertNotEqual(a, b)

    def test_anonymized_ignores_tenant(self):
        a = derive_key_anonymized("hello world", "tenant-a")
        b = derive_key_anonymized("hello world", "tenant-b")
        self.assertEqual(a, b)

    def test_anonymized_normalizes_whitespace_and_case(self):
        a = derive_key_anonymized("Hello   World", "t")
        b = derive_key_anonymized("  hello world ", "t")
        self.assertEqual(a, b)

    def test_all_schemes_deterministic(self):
        for name, fn in DERIVE_FNS.items():
            self.assertEqual(fn("prompt", "tenant"), fn("prompt", "tenant"), name)

    def test_all_schemes_registered(self):
        self.assertEqual(set(SCHEMES), set(DERIVE_FNS))


class TestSimulator(unittest.TestCase):
    def test_store_and_lookup_hit(self):
        sim = TenantCacheSimulator("tenant-scoped")
        t = Tenant("t1")
        sim.store(t, "p1", "completion one")
        entry = sim.lookup(t, "p1")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.completion, "completion one")
        self.assertEqual(sim.stats()["hits"], 1)

    def test_lookup_miss_returns_none(self):
        sim = TenantCacheSimulator("tenant-scoped")
        self.assertIsNone(sim.lookup(Tenant("t1"), "never stored"))

    def test_tenant_scoped_isolates(self):
        sim = TenantCacheSimulator("tenant-scoped")
        sim.store(Tenant("a"), "shared prompt", "a secret")
        self.assertIsNone(sim.lookup(Tenant("b"), "shared prompt"))

    def test_anonymized_shares_across_tenants(self):
        sim = TenantCacheSimulator("anonymized")
        sim.store(Tenant("a"), "shared prompt", "a secret")
        entry = sim.lookup(Tenant("b"), "shared prompt")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.tenant, "a")

    def test_ttl_expiry(self):
        sim = TenantCacheSimulator("tenant-scoped", ttl_seconds=-1.0)
        t = Tenant("t1")
        sim.store(t, "p", "c")
        self.assertIsNone(sim.lookup(t, "p"))

    def test_unknown_scheme_raises(self):
        with self.assertRaises(ValueError):
            TenantCacheSimulator("nope")


class TestDetection(unittest.TestCase):
    def test_expected_verdicts(self):
        result = run_detection()
        self.assertEqual(result.verdict_for("tenant-scoped"), "ISOLATED")
        self.assertEqual(result.verdict_for("anonymized"), "CONFIRMED")
        self.assertEqual(result.verdict_for("global"), "CONFIRMED")
        self.assertEqual(result.verdict_for("prefix-scoped"), "CONFIRMED")
        self.assertEqual(result.verdict_for("casefold-tenant"), "SUSPECT")

    def test_single_scheme_selection(self):
        result = run_detection(["tenant-scoped"])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.verdict_for("tenant-scoped"), "ISOLATED")

    def test_report_contains_all_verdicts(self):
        report = run_detection().report()
        for token in ("ISOLATED", "SUSPECT", "CONFIRMED", "schemes tested: 5"):
            self.assertIn(token, report)

    def test_confirmed_evidence_names_canary_and_tenants(self):
        result = run_detection(["anonymized"])
        ev = result.findings[0].evidence
        self.assertIn("CANARY-", ev)
        self.assertIn("tenant-victim", ev)
        self.assertIn("tenant-attacker", ev)


if __name__ == "__main__":
    unittest.main()
