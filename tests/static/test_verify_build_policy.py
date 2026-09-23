"""Offline failure tests; these are not real Chromium/GN evidence."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import nullcontext

Root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Root / "scripts"))
import verify_build_policy as Verify


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.Manifest = json.loads((Root / "policy/build-policy.json").read_text())
        self.Inventory = [
            {"name": Item["name"],
             "default": {"value": json.dumps(Item["expected"]),
                         "file": "//invented/fixture.gni", "line": 10}}
            for Item in self.Manifest["settings"]
        ]

    def test_matching_inventory_and_override_precedence(self):
        self.Inventory[0]["default"]["value"] = "true"
        self.Inventory[0]["current"] = {"value": "false"}
        Results = Verify.CompareArguments(self.Manifest, self.Inventory)
        self.assertTrue(all(Item["result"] == "MATCH" for Item in Results))

    def test_missing_and_wrong_type_fail(self):
        self.Inventory.pop(0)
        self.Inventory[0]["current"] = {"value": "0"}
        Results = Verify.CompareArguments(self.Manifest, self.Inventory)
        self.assertEqual("MISSING", Results[0]["result"])
        self.assertEqual("MISMATCH", Results[1]["result"])

    def test_secret_value_is_not_retained(self):
        Entry = next(Item for Item in self.Inventory if Item["name"] == "google_api_key")
        Entry["current"] = {"value": '"invented-sensitive-value"'}
        Results = Verify.CompareArguments(self.Manifest, self.Inventory)
        self.assertNotIn("invented-sensitive-value", json.dumps(Results))
        self.assertIn("MISMATCH", json.dumps(Results))

    def test_duplicate_and_missing_provenance_rejected(self):
        with self.assertRaises(Verify.VerificationError):
            Verify.CompareArguments(self.Manifest, self.Inventory + [self.Inventory[0]])
        del self.Inventory[0]["default"]["file"]
        with self.assertRaises(Verify.VerificationError):
            Verify.CompareArguments(self.Manifest, self.Inventory)

    def test_unknown_gn_expression_is_not_interpreted(self):
        for Text in ['"$variable"', '"\\x41"', '[false]', 'foo', '1.0']:
            with self.subTest(Text=Text), self.assertRaises(Verify.VerificationError):
                Verify.ParseScalar(Text)

    def test_environment_scan_is_case_insensitive_and_value_free(self):
        Findings = Verify.EnvironmentFindings({
            "google_api_key": "fake-secret", "GOOGLE_CLIENT_SECRET_MAIN": "other",
            "CL": "/DGOOGLE_API_KEY=fake", "PATH": "normal", "EMPTY": "",
            "GOOGLE_DEFAULT_CLIENT_ID": "",
        })
        self.assertEqual(["CL", "GOOGLE_API_KEY", "GOOGLE_CLIENT_SECRET_MAIN"], Findings)
        self.assertNotIn("fake", json.dumps(Findings))

    def test_other_constraint_modes_preserve_types(self):
        self.assertFalse(Verify.Matches({"requirement": "ALLOWED_SET", "expected": [0]}, False))
        self.assertFalse(Verify.Matches({"requirement": "FORBIDDEN_VALUE", "expected": True}, True))
        self.assertTrue(Verify.Matches({"requirement": "FORBIDDEN_VALUE", "expected": True}, 1))

    def test_saved_environment_reports_only_names_and_scopes(self):
        class Registry:
            HKEY_CURRENT_USER = "user"
            HKEY_LOCAL_MACHINE = "machine"

            @staticmethod
            def OpenKey(Hive, Name):
                return nullcontext(Hive)

            @staticmethod
            def QueryInfoKey(Key):
                return (0, 1, 0)

            @staticmethod
            def EnumValue(Key, Index):
                return (("GOOGLE_API_KEY", "private-test-value", 1) if Key == "user"
                        else ("PATH", "normal", 1))

        Result = Verify.SavedEnvironmentFindings(Registry)
        self.assertEqual({"CURRENT_USER": ["GOOGLE_API_KEY"], "MACHINE": []}, Result)
        self.assertNotIn("private-test-value", json.dumps(Result))

    def test_saved_environment_access_failure_is_not_a_clean_result(self):
        class Registry:
            HKEY_CURRENT_USER = "user"
            HKEY_LOCAL_MACHINE = "machine"

            @staticmethod
            def OpenKey(Hive, Name):
                raise PermissionError("private-error-value")

        with self.assertRaisesRegex(Verify.VerificationError, "could not be inspected") as Error:
            Verify.SavedEnvironmentFindings(Registry)
        self.assertNotIn("private-error-value", str(Error.exception))

    def test_generated_input_is_deterministic_and_explicit(self):
        Text = Verify.BuildArguments(self.Manifest)
        self.assertIn('target_os = "win"\n', Text)
        self.assertIn('google_api_key = ""\n', Text)
        self.assertEqual(sorted(Text.splitlines()), Text.splitlines())

    def test_wrong_sha_and_dirty_source_fail(self):
        with tempfile.TemporaryDirectory() as Directory:
            Source = Path(Directory).resolve()
            with patch.object(Verify, "Run", side_effect=[str(Source), "b" * 40]):
                with self.assertRaisesRegex(Verify.VerificationError, "HEAD differs"):
                    Verify.CheckSource(Source, "a" * 40, [])
            with patch.object(Verify, "Run", side_effect=[str(Source), "a" * 40, " M DEPS"]):
                with self.assertRaisesRegex(Verify.VerificationError, "clean"):
                    Verify.CheckSource(Source, "a" * 40, [])

    def test_failed_command_does_not_disclose_output(self):
        Result = type("Result", (), {"returncode": 1, "stdout": b"secret", "stderr": b"secret"})()
        Commands = []
        with patch.object(Verify.subprocess, "run", return_value=Result):
            with self.assertRaises(Verify.VerificationError) as Error:
                Verify.Run(["gn", "gen", "out/Test"], Root, Commands)
        self.assertNotIn("secret", str(Error.exception) + json.dumps(Commands))
        self.assertEqual(1, Commands[0]["exit_code"])

    def test_evidence_cannot_overwrite_previous_run(self):
        with tempfile.TemporaryDirectory() as Directory:
            Evidence = Path(Directory) / "report.json"
            Evidence.write_text("existing evidence")
            Result = Verify.Main(["--request", "unused", "--source", "unused",
                                  "--gn", "unused", "--evidence", str(Evidence)])
            self.assertEqual(1, Result)
            self.assertEqual("existing evidence", Evidence.read_text())

    def test_explicit_output_reuse_preserves_inputs_and_incremental_files(self):
        with tempfile.TemporaryDirectory() as Directory:
            Output = Path(Directory) / "out/Test"
            Arguments = Verify.BuildArguments(self.Manifest)
            Verify.PrepareOutput(Output, Arguments)
            Stamp = (Output / "args.gn").stat().st_mtime_ns
            (Output / "existing.obj").write_bytes(b"fixture")
            Verify.PrepareOutput(Output, Arguments, Reuse=True)
            self.assertEqual(Stamp, (Output / "args.gn").stat().st_mtime_ns)
            self.assertEqual(b"fixture", (Output / "existing.obj").read_bytes())

    def test_output_reuse_rejects_mismatch_and_implicit_overwrite(self):
        with tempfile.TemporaryDirectory() as Directory:
            Output = Path(Directory) / "out/Test"
            Arguments = Verify.BuildArguments(self.Manifest)
            Verify.PrepareOutput(Output, Arguments)
            with self.assertRaises(Verify.VerificationError):
                Verify.PrepareOutput(Output, Arguments)
            (Output / "args.gn").write_text('enable_compose = true\n')
            with self.assertRaises(Verify.VerificationError):
                Verify.PrepareOutput(Output, Arguments, Reuse=True)
            self.assertEqual('enable_compose = true\n', (Output / "args.gn").read_text())

    def test_malformed_request_retains_failed_report_without_input(self):
        with tempfile.TemporaryDirectory() as Directory:
            Request = Path(Directory) / "request.json"
            Request.write_text("not-json-secret")
            Evidence = Path(Directory) / "evidence.json"
            Result = Verify.Main(["--request", str(Request), "--source", "unused",
                                  "--gn", "unused", "--evidence", str(Evidence)])
            self.assertEqual(1, Result)
            Report = json.loads(Evidence.read_text())
            self.assertEqual("FAIL", Report["status"])
            self.assertFalse(Report["qualification_promoted"])
            self.assertNotIn("not-json-secret", Evidence.read_text())


if __name__ == "__main__":
    unittest.main()
