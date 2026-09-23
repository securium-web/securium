"""Offline graph/header gate failures, not Chromium evidence."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import verify_foundation_1b as Gate


class FoundationTests(unittest.TestCase):
    def test_product_in_inventory_or_production_rejected(self):
        for Prefix in Gate.ProductPrefixes:
            for Targets, Deps in ((Prefix + "impl", ""), ("", "  " + Prefix + "impl")):
                with self.assertRaises(Gate.Verify.VerificationError):
                    Gate.CheckGraph(Targets, Deps)

    def test_support_and_unrelated_composebox_retained(self):
        Deps = "//components/compose/core/browser:browser\n//chrome/browser/composebox:impl\n"
        self.assertEqual(["//components/compose/core/browser:browser"], Gate.CheckGraph(Deps, Deps))

    def test_missing_and_enabled_header_rejected(self):
        for Text in ("", "#define BUILDFLAG_INTERNAL_ENABLE_COMPOSE() (1)"):
            with self.assertRaises(Gate.Verify.VerificationError):
                Gate.CheckHeader(Text, {"ENABLE_COMPOSE": 0})
        Gate.CheckHeader("#define BUILDFLAG_INTERNAL_ENABLE_COMPOSE() (0)", {"ENABLE_COMPOSE": 0})
