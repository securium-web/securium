"""Offline tests for Chromium Stable candidate detection and state handling."""

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


RepositoryRoot = Path(__file__).parents[2]
ScriptPath = RepositoryRoot / "scripts" / "chromium_update.py"
FixtureDirectory = RepositoryRoot / "tests" / "fixtures" / "chromiumdash"
ModuleSpec = importlib.util.spec_from_file_location("ChromiumUpdate", ScriptPath)
assert ModuleSpec is not None and ModuleSpec.loader is not None
ChromiumUpdate = importlib.util.module_from_spec(ModuleSpec)
sys.modules[ModuleSpec.name] = ChromiumUpdate
ModuleSpec.loader.exec_module(ChromiumUpdate)


ValidSha = "0123456789abcdef0123456789abcdef01234567"
OtherSha = "1111111111111111111111111111111111111111"
ReleasedSha = "2222222222222222222222222222222222222222"


class ChromiumUpdateTests(unittest.TestCase):
    def Fixture(self, Name: str) -> str:
        return (FixtureDirectory / Name).read_text(encoding="utf-8")

    def RawCandidate(self, Version: str, Sha: str) -> str:
        Payload = json.loads(self.Fixture("valid-stable-windows.json"))
        Payload[0]["version"] = Version
        Payload[0]["hashes"]["chromium"] = Sha
        return json.dumps(Payload)

    def CandidateRecord(self, Version: str, Sha: str):
        return {
            "channel": "Stable",
            "chrome_version": Version,
            "chromium_sha": Sha,
            "detected_at": "2026-01-02T03:04:05Z",
            "platform": "Windows",
            "qualification": "UNQUALIFIED",
        }

    def QualifiedRecord(self, Version: str, Sha: str):
        return {
            "channel": "Stable",
            "chrome_version": Version,
            "chromium_sha": Sha,
            "platform": "Windows",
            "qualification_level": "PATCH-APPLY",
            "qualified_at": "2026-01-03T03:04:05Z",
        }

    def ReleasedRecord(self, Version: str, Sha: str):
        return {
            "channel": "Stable",
            "chrome_version": Version,
            "chromium_sha": Sha,
            "platform": "Windows",
            "release_version": "0.0.1-test",
            "released_at": "2026-01-04T03:04:05Z",
        }

    def State(
        self,
        Candidate=None,
        Qualified=None,
        Released=None,
    ):
        return {
            "schema_version": 1,
            "candidate": Candidate,
            "qualified": Qualified,
            "released": Released,
        }

    def WriteState(self, Directory: str, State):
        StatePath = Path(Directory) / "upstream.json"
        StatePath.write_text(json.dumps(State, indent=2) + "\n", encoding="utf-8")
        return StatePath

    def test_valid_stable_response_parses_chrome_version_and_chromium_sha(self):
        Candidate = ChromiumUpdate.ParseChromiumDashResponse(
            self.Fixture("valid-stable-windows.json")
        )

        self.assertEqual("Stable", Candidate.Channel)
        self.assertEqual("Windows", Candidate.Platform)
        self.assertEqual("123.0.6312.86", Candidate.ChromeVersion)
        self.assertEqual(ValidSha, Candidate.ChromiumSha)

    def test_malformed_json_is_rejected(self):
        with self.assertRaises(ChromiumUpdate.UpstreamDataError):
            ChromiumUpdate.ParseChromiumDashResponse(self.Fixture("malformed.json"))

    def test_missing_version_is_rejected(self):
        with self.assertRaisesRegex(ChromiumUpdate.UpstreamDataError, "version"):
            ChromiumUpdate.ParseChromiumDashResponse(self.Fixture("missing-version.json"))

    def test_missing_chromium_sha_is_rejected(self):
        with self.assertRaisesRegex(ChromiumUpdate.UpstreamDataError, "hashes.chromium"):
            ChromiumUpdate.ParseChromiumDashResponse(self.Fixture("missing-sha.json"))

    def test_invalid_chromium_sha_is_rejected(self):
        with self.assertRaisesRegex(ChromiumUpdate.UpstreamDataError, "40-character"):
            ChromiumUpdate.ParseChromiumDashResponse(self.Fixture("invalid-sha.json"))

    def test_wrong_channel_is_rejected(self):
        with self.assertRaisesRegex(ChromiumUpdate.UpstreamDataError, "Stable"):
            ChromiumUpdate.ParseChromiumDashResponse(self.Fixture("wrong-channel.json"))

    def test_wrong_platform_is_rejected(self):
        with self.assertRaisesRegex(ChromiumUpdate.UpstreamDataError, "Windows"):
            ChromiumUpdate.ParseChromiumDashResponse(self.Fixture("wrong-platform.json"))

    def test_ambiguous_num_one_response_is_rejected(self):
        with self.assertRaisesRegex(ChromiumUpdate.UpstreamDataError, "exactly one"):
            ChromiumUpdate.ParseChromiumDashResponse(self.Fixture("ambiguous.json"))

    def test_unexpected_response_envelope_is_rejected(self):
        with self.assertRaisesRegex(ChromiumUpdate.UpstreamDataError, "array"):
            ChromiumUpdate.ParseChromiumDashResponse(
                self.Fixture("unexpected-envelope.json")
            )

    def test_no_existing_candidate_is_new_candidate(self):
        Candidate = ChromiumUpdate.ParseChromiumDashResponse(
            self.Fixture("valid-stable-windows.json")
        )

        Result = ChromiumUpdate.CompareCandidate(Candidate, self.State())

        self.assertEqual(ChromiumUpdate.Decision.NewCandidate, Result.Name)
        self.assertTrue(Result.QualificationRequired)
        self.assertTrue(Result.DispatchQualification)

    def test_same_unqualified_candidate_is_no_change(self):
        Candidate = ChromiumUpdate.ParseChromiumDashResponse(
            self.Fixture("valid-stable-windows.json")
        )
        State = self.State(Candidate=self.CandidateRecord("123.0.6312.86", ValidSha))

        Result = ChromiumUpdate.CompareCandidate(Candidate, State)

        self.assertEqual(ChromiumUpdate.Decision.NoChange, Result.Name)
        self.assertTrue(Result.QualificationRequired)
        self.assertFalse(Result.DispatchQualification)

    def test_same_version_with_new_sha_is_new_candidate(self):
        Candidate = ChromiumUpdate.ParseChromiumDashResponse(
            self.RawCandidate("123.0.6312.86", OtherSha)
        )
        State = self.State(Candidate=self.CandidateRecord("123.0.6312.86", ValidSha))

        Result = ChromiumUpdate.CompareCandidate(Candidate, State)

        self.assertEqual(ChromiumUpdate.Decision.NewCandidate, Result.Name)
        self.assertTrue(Result.QualificationRequired)

    def test_candidate_equal_to_qualified_needs_no_qualification(self):
        Candidate = ChromiumUpdate.ParseChromiumDashResponse(
            self.Fixture("valid-stable-windows.json")
        )
        State = self.State(Qualified=self.QualifiedRecord("123.0.6312.86", ValidSha))

        Result = ChromiumUpdate.CompareCandidate(Candidate, State)

        self.assertEqual(ChromiumUpdate.Decision.CandidateAlreadyQualified, Result.Name)
        self.assertFalse(Result.QualificationRequired)

    def test_candidate_equal_to_released_needs_no_qualification(self):
        Candidate = ChromiumUpdate.ParseChromiumDashResponse(
            self.Fixture("valid-stable-windows.json")
        )
        State = self.State(
            Qualified=self.QualifiedRecord("123.0.6312.86", ValidSha),
            Released=self.ReleasedRecord("123.0.6312.86", ValidSha),
        )

        Result = ChromiumUpdate.CompareCandidate(Candidate, State)

        self.assertEqual(ChromiumUpdate.Decision.CandidateAlreadyReleased, Result.Name)
        self.assertFalse(Result.QualificationRequired)

    def test_older_upstream_version_is_reported_as_regression(self):
        Candidate = ChromiumUpdate.ParseChromiumDashResponse(
            self.Fixture("valid-stable-windows.json")
        )
        State = self.State(Candidate=self.CandidateRecord("124.0.6367.10", OtherSha))

        Result = ChromiumUpdate.CompareCandidate(Candidate, State)

        self.assertEqual(ChromiumUpdate.Decision.UpstreamRegression, Result.Name)
        self.assertFalse(Result.QualificationRequired)

    def test_same_sha_with_different_version_is_reported_as_conflict(self):
        Candidate = ChromiumUpdate.ParseChromiumDashResponse(
            self.Fixture("valid-stable-windows.json")
        )
        State = self.State(Candidate=self.CandidateRecord("124.0.6367.10", ValidSha))

        Result = ChromiumUpdate.CompareCandidate(Candidate, State)

        self.assertEqual(ChromiumUpdate.Decision.UpstreamConflict, Result.Name)

    def test_candidate_update_preserves_qualified_and_released_authority(self):
        State = self.State(
            Candidate=self.CandidateRecord("122.0.6261.128", OtherSha),
            Qualified=self.QualifiedRecord("122.0.6261.128", OtherSha),
            Released=self.ReleasedRecord("121.0.6167.184", ReleasedSha),
        )
        OriginalQualified = copy.deepcopy(State["qualified"])
        OriginalReleased = copy.deepcopy(State["released"])
        with tempfile.TemporaryDirectory() as TempDirectory:
            StatePath = self.WriteState(TempDirectory, State)

            Report, _ = ChromiumUpdate.ExecuteCheck(
                self.Fixture("valid-stable-windows.json"),
                StatePath,
                WriteCandidate=True,
                DetectedAt="2026-02-01T00:00:00Z",
            )
            UpdatedState = json.loads(StatePath.read_text(encoding="utf-8"))

        self.assertTrue(Report["state_changed"])
        self.assertEqual(OriginalQualified, UpdatedState["qualified"])
        self.assertEqual(OriginalReleased, UpdatedState["released"])
        self.assertEqual(ValidSha, UpdatedState["candidate"]["chromium_sha"])

    def test_malformed_upstream_leaves_state_unchanged(self):
        State = self.State(Candidate=self.CandidateRecord("122.0.6261.128", OtherSha))
        with tempfile.TemporaryDirectory() as TempDirectory:
            StatePath = self.WriteState(TempDirectory, State)
            OriginalBytes = StatePath.read_bytes()

            with self.assertRaises(ChromiumUpdate.UpstreamDataError):
                ChromiumUpdate.ExecuteCheck(
                    self.Fixture("malformed.json"), StatePath, WriteCandidate=True
                )

            self.assertEqual(OriginalBytes, StatePath.read_bytes())

    def test_invalid_local_state_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            StatePath = Path(TempDirectory) / "upstream.json"
            StatePath.write_text('{"schema_version": 999}\n', encoding="utf-8")
            OriginalBytes = StatePath.read_bytes()

            with self.assertRaises(ChromiumUpdate.StateValidationError):
                ChromiumUpdate.ExecuteCheck(
                    self.Fixture("valid-stable-windows.json"),
                    StatePath,
                    WriteCandidate=True,
                )

            self.assertEqual(OriginalBytes, StatePath.read_bytes())

    def test_replace_failure_does_not_corrupt_previous_state(self):
        State = self.State()

        def FailReplace(Source: str, Destination: str) -> None:
            raise OSError("simulated replace failure")

        with tempfile.TemporaryDirectory() as TempDirectory:
            StatePath = self.WriteState(TempDirectory, State)
            OriginalBytes = StatePath.read_bytes()

            with self.assertRaises(ChromiumUpdate.StateWriteError):
                ChromiumUpdate.ExecuteCheck(
                    self.Fixture("valid-stable-windows.json"),
                    StatePath,
                    WriteCandidate=True,
                    DetectedAt="2026-02-01T00:00:00Z",
                    ReplaceFunction=FailReplace,
                )

            self.assertEqual(OriginalBytes, StatePath.read_bytes())
            self.assertEqual([], list(Path(TempDirectory).glob("*.tmp")))

    def test_repeated_detection_does_not_mutate_timestamp_or_state(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            StatePath = self.WriteState(TempDirectory, self.State())
            FirstReport, _ = ChromiumUpdate.ExecuteCheck(
                self.Fixture("valid-stable-windows.json"),
                StatePath,
                WriteCandidate=True,
                DetectedAt="2026-02-01T00:00:00Z",
            )
            FirstBytes = StatePath.read_bytes()

            SecondReport, SecondDecision = ChromiumUpdate.ExecuteCheck(
                self.Fixture("valid-stable-windows.json"),
                StatePath,
                WriteCandidate=True,
                DetectedAt="2026-03-01T00:00:00Z",
            )

            self.assertTrue(FirstReport["state_changed"])
            self.assertEqual(ChromiumUpdate.Decision.NoChange, SecondDecision)
            self.assertFalse(SecondReport["state_changed"])
            self.assertEqual(FirstBytes, StatePath.read_bytes())

    def test_cli_json_output_is_machine_readable_and_new_candidate_is_success(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            StatePath = self.WriteState(TempDirectory, self.State())
            Result = subprocess.run(
                [
                    sys.executable,
                    str(ScriptPath),
                    "check",
                    "--json",
                    "--offline-fixture",
                    str(FixtureDirectory / "valid-stable-windows.json"),
                    "--state",
                    str(StatePath),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        Report = json.loads(Result.stdout)
        self.assertEqual(0, Result.returncode, Result.stderr)
        self.assertEqual("NEW_CANDIDATE", Report["decision"])
        self.assertTrue(Report["dispatch_qualification"])
        self.assertIsNotNone(Report["qualification_request"])
        self.assertFalse(Report["state_changed"])

    def test_cli_invalid_upstream_is_nonzero_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            StatePath = self.WriteState(TempDirectory, self.State())
            OriginalBytes = StatePath.read_bytes()
            Result = subprocess.run(
                [
                    sys.executable,
                    str(ScriptPath),
                    "check",
                    "--json",
                    "--offline-fixture",
                    str(FixtureDirectory / "malformed.json"),
                    "--state",
                    str(StatePath),
                    "--write-candidate",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(OriginalBytes, StatePath.read_bytes())

        Report = json.loads(Result.stdout)
        self.assertEqual(2, Result.returncode)
        self.assertEqual("INVALID_UPSTREAM", Report["decision"])
        self.assertFalse(Report["state_changed"])

    def test_cli_human_output_labels_evidence_and_qualification(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            StatePath = self.WriteState(TempDirectory, self.State())
            Result = subprocess.run(
                [
                    sys.executable,
                    str(ScriptPath),
                    "check",
                    "--offline-fixture",
                    str(FixtureDirectory / "valid-stable-windows.json"),
                    "--state",
                    str(StatePath),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(0, Result.returncode, Result.stderr)
        self.assertIn("Current qualified Chromium:", Result.stdout)
        self.assertIn("Detected Stable Chromium:", Result.stdout)
        self.assertIn("Qualification required: yes", Result.stdout)
        self.assertIn("Evidence level: STATIC only", Result.stdout)


if __name__ == "__main__":
    unittest.main()
