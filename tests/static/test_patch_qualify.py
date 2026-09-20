"""Offline tests for deterministic synthetic patch qualification machinery."""

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


RepositoryRoot = Path(__file__).parents[2]
ScriptPath = RepositoryRoot / "scripts" / "patch_qualify.py"
FixtureRoot = RepositoryRoot / "tests" / "fixtures" / "patch-engine"
RequestRoot = FixtureRoot / "requests"
SourceRoot = FixtureRoot / "sources"
FixtureRepositoryRoot = FixtureRoot / "repositories"
ModuleSpec = importlib.util.spec_from_file_location("PatchQualify", ScriptPath)
assert ModuleSpec is not None and ModuleSpec.loader is not None
PatchQualify = importlib.util.module_from_spec(ModuleSpec)
sys.modules[ModuleSpec.name] = PatchQualify
ModuleSpec.loader.exec_module(PatchQualify)


class PatchQualificationTests(unittest.TestCase):
    def RunFixture(
        self,
        TempDirectory: str,
        RepositoryName: str,
        *,
        SourceName: str = "base",
        RequestName: str = "valid.json",
        FixtureId: str = "test-fixture",
        JsonWriterValue=PatchQualify.AtomicWriteJson,
    ):
        Workspace = Path(TempDirectory) / "workspace"
        Evidence = PatchQualify.RunQualification(
            RequestRoot / RequestName,
            SourceRoot / SourceName,
            FixtureRepositoryRoot / RepositoryName,
            Workspace,
            FixtureId,
            JsonWriterValue=JsonWriterValue,
        )
        return Evidence, Workspace

    def TreeDigest(self, Root: Path) -> str:
        Hasher = hashlib.sha256()
        for FilePath in sorted(PathValue for PathValue in Root.rglob("*") if PathValue.is_file()):
            Hasher.update(FilePath.relative_to(Root).as_posix().encode("utf-8"))
            Hasher.update(b"\0")
            Hasher.update(FilePath.read_bytes())
            Hasher.update(b"\0")
        return Hasher.hexdigest()

    def CreateRepository(self, Root: Path, Series: str, Patches=None, Downstream=None) -> Path:
        Repository = Root / "repository"
        PatchDirectory = Repository / "patches"
        PatchDirectory.mkdir(parents=True)
        (PatchDirectory / "series").write_text(Series, encoding="utf-8", newline="\n")
        for Name, Content in (Patches or {}).items():
            (PatchDirectory / Name).write_text(Content, encoding="utf-8", newline="\n")
        for RelativePath, Content in (Downstream or {}).items():
            Destination = Repository / "src" / "chromium" / RelativePath
            Destination.parent.mkdir(parents=True, exist_ok=True)
            Destination.write_text(Content, encoding="utf-8", newline="\n")
        return Repository

    def FirstPatchContent(self) -> str:
        return (
            FixtureRepositoryRoot
            / "success"
            / "patches"
            / "0001-profile-stage-one.patch"
        ).read_text(encoding="utf-8")

    def test_valid_qualification_request_is_accepted(self):
        RequestData, RequestHash = PatchQualify.LoadQualificationRequest(
            RequestRoot / "valid.json"
        )

        self.assertEqual(1, RequestData["schema_version"])
        self.assertEqual(64, len(RequestHash))

    def test_malformed_qualification_request_is_rejected(self):
        with self.assertRaises(PatchQualify.StageFailure) as Context:
            PatchQualify.LoadQualificationRequest(RequestRoot / "malformed.json")

        self.assertEqual(PatchQualify.FailureClass.InvalidRequest, Context.exception.Failure)

    def test_invalid_request_sha_is_rejected(self):
        with self.assertRaises(PatchQualify.StageFailure) as Context:
            PatchQualify.LoadQualificationRequest(RequestRoot / "invalid-sha.json")

        self.assertEqual(PatchQualify.FailureClass.InvalidRequest, Context.exception.Failure)

    def test_unsupported_request_schema_is_rejected(self):
        with self.assertRaises(PatchQualify.StageFailure) as Context:
            PatchQualify.LoadQualificationRequest(RequestRoot / "unsupported-schema.json")

        self.assertEqual(PatchQualify.FailureClass.InvalidRequest, Context.exception.Failure)

    def test_previous_qualified_revision_and_unknown_fields_are_validated(self):
        ValidRequest = json.loads((RequestRoot / "valid.json").read_text(encoding="utf-8"))
        ValidRequest["previous_qualified"] = {
            "chrome_version": "122.0.6261.128",
            "chromium_sha": "1111111111111111111111111111111111111111",
        }
        PatchQualify.ValidateQualificationRequest(ValidRequest)

        InvalidRequest = copy.deepcopy(ValidRequest)
        InvalidRequest["candidate"]["unexpected"] = True
        with self.assertRaises(PatchQualify.QualificationRequestError):
            PatchQualify.ValidateQualificationRequest(InvalidRequest)

    def test_empty_patch_series_succeeds(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(TempDirectory, "empty")

            self.assertEqual("PASS", Evidence["result"])
            self.assertEqual([], Evidence["execution"]["applied_patches"])
            self.assertTrue((Workspace / "evidence.json").is_file())

    def test_single_patch_applies(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            TempRoot = Path(TempDirectory)
            Repository = self.CreateRepository(
                TempRoot,
                "0001-profile-stage-one.patch\n",
                {"0001-profile-stage-one.patch": self.FirstPatchContent()},
            )
            Workspace = TempRoot / "workspace"

            Evidence = PatchQualify.RunQualification(
                RequestRoot / "valid.json",
                SourceRoot / "base",
                Repository,
                Workspace,
                "single-patch",
            )

            ResultText = (Workspace / "integration" / "browser" / "profile.cc").read_text(
                encoding="utf-8"
            )
        self.assertEqual("PASS", Evidence["result"])
        self.assertIn('return "stage-one"', ResultText)

    def test_multiple_patches_apply_in_declared_dependency_order(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(TempDirectory, "success")
            ResultText = (Workspace / "integration" / "browser" / "profile.cc").read_text(
                encoding="utf-8"
            )

        self.assertEqual("PASS", Evidence["result"])
        self.assertEqual(
            ["0001-profile-stage-one.patch", "0002-profile-stage-two.patch"],
            Evidence["execution"]["applied_patches"],
        )
        self.assertIn('return "stage-two"', ResultText)

    def test_duplicate_patch_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            TempRoot = Path(TempDirectory)
            PatchName = "0001-profile-stage-one.patch"
            Repository = self.CreateRepository(
                TempRoot,
                f"{PatchName}\n{PatchName}\n",
                {PatchName: self.FirstPatchContent()},
            )
            Evidence = PatchQualify.RunQualification(
                RequestRoot / "valid.json",
                SourceRoot / "base",
                Repository,
                TempRoot / "workspace",
                "duplicate-series",
            )

        self.assertEqual("FAIL", Evidence["result"])
        self.assertEqual("INVALID_SERIES", Evidence["execution"]["failure_class"])

    def test_missing_patch_is_rejected(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            TempRoot = Path(TempDirectory)
            Repository = self.CreateRepository(
                TempRoot, "0001-missing.patch\n"
            )
            Evidence = PatchQualify.RunQualification(
                RequestRoot / "valid.json",
                SourceRoot / "base",
                Repository,
                TempRoot / "workspace",
                "missing-patch",
            )

        self.assertEqual("INVALID_SERIES", Evidence["execution"]["failure_class"])

    def test_malformed_patch_is_rejected_before_integration(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(TempDirectory, "malformed")

            self.assertEqual("INVALID_SERIES", Evidence["execution"]["failure_class"])
            self.assertFalse((Workspace / "integration").exists())

    def test_unsafe_patch_series_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(TempDirectory, "unsafe-series")

            self.assertEqual("UNSAFE_PATH", Evidence["execution"]["failure_class"])
            self.assertFalse((Workspace / "integration").exists())

    def test_unsafe_path_inside_patch_is_rejected(self):
        UnsafePatch = """diff --git a/../outside.cc b/../outside.cc
--- a/../outside.cc
+++ b/../outside.cc
@@ -1 +1 @@
-old
+new
"""
        with tempfile.TemporaryDirectory() as TempDirectory:
            TempRoot = Path(TempDirectory)
            Repository = self.CreateRepository(
                TempRoot,
                "0001-unsafe.patch\n",
                {"0001-unsafe.patch": UnsafePatch},
            )
            Evidence = PatchQualify.RunQualification(
                RequestRoot / "valid.json",
                SourceRoot / "base",
                Repository,
                TempRoot / "workspace",
                "unsafe-patch",
            )

        self.assertEqual("UNSAFE_PATH", Evidence["execution"]["failure_class"])

    def test_downstream_new_and_nested_files_materialize(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(TempDirectory, "success")
            OwnedFile = Workspace / "integration" / "securium" / "owned.cc"
            NestedFile = Workspace / "integration" / "securium" / "config" / "defaults.json"

            self.assertEqual("PASS", Evidence["result"])
            self.assertTrue(OwnedFile.is_file())
            self.assertTrue(NestedFile.is_file())
            self.assertEqual(
                ["securium/config/defaults.json", "securium/owned.cc"],
                [Item["path"] for Item in Evidence["inputs"]["downstream_files"]],
            )

    def test_materialization_collision_fails_before_patching(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(TempDirectory, "collision")

            self.assertEqual("FAIL", Evidence["result"])
            self.assertEqual(
                "MATERIALIZATION_COLLISION", Evidence["execution"]["failure_class"]
            )
            self.assertEqual([], Evidence["execution"]["attempted_patches"])
            self.assertFalse((Workspace / "integration").exists())

    def test_traversal_and_absolute_materialization_paths_are_rejected(self):
        UnsafePaths = ("../outside.cc", "/outside.cc", "C:/outside.cc", "server/share.cc")
        ExpectedUnsafe = UnsafePaths[:3]
        for UnsafePath in ExpectedUnsafe:
            with self.subTest(Path=UnsafePath):
                with self.assertRaises(PatchQualify.StageFailure):
                    PatchQualify.ValidateSafeRelativePath(
                        UnsafePath, "test materialization path"
                    )
        self.assertEqual("server/share.cc", PatchQualify.ValidateSafeRelativePath(
            "server/share.cc", "test materialization path"
        ))

    def test_materialization_plan_order_is_deterministic(self):
        SourceFiles, SourceDirectories = PatchQualify.EnumerateSafeTree(
            SourceRoot / "base", "source tree"
        )
        Plan = PatchQualify.BuildMaterializationPlan(
            FixtureRepositoryRoot / "success", SourceFiles, SourceDirectories
        )

        self.assertEqual(
            ["securium/config/defaults.json", "securium/owned.cc"],
            [Item.RelativePath for Item in Plan],
        )

    def test_first_patch_failure_records_no_applied_patches(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, _ = self.RunFixture(
                TempDirectory, "success", SourceName="mismatch"
            )

        self.assertEqual("PATCH_CHECK_FAILED", Evidence["execution"]["failure_class"])
        self.assertEqual("0001-profile-stage-one.patch", Evidence["execution"]["failed_patch"])
        self.assertEqual([], Evidence["execution"]["applied_patches"])
        self.assertEqual(
            ["0001-profile-stage-one.patch"], Evidence["execution"]["attempted_patches"]
        )

    def test_later_patch_failure_records_partial_state_but_never_passes(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(TempDirectory, "failure")
            ResultText = (Workspace / "integration" / "browser" / "profile.cc").read_text(
                encoding="utf-8"
            )

        self.assertEqual("FAIL", Evidence["result"])
        self.assertEqual("0002-profile-context-failure.patch", Evidence["execution"]["failed_patch"])
        self.assertEqual(
            ["0001-profile-stage-one.patch"], Evidence["execution"]["applied_patches"]
        )
        self.assertEqual(
            ["0001-profile-stage-one.patch", "0002-profile-context-failure.patch"],
            Evidence["execution"]["attempted_patches"],
        )
        self.assertNotIn("0003-must-not-run.patch", Evidence["execution"]["attempted_patches"])
        self.assertIn('return "stage-one"', ResultText)
        self.assertNotIn("incorrectly-applied", ResultText)

    def test_patch_failure_writes_bounded_repair_bundle(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(TempDirectory, "failure")
            RepairBundle = json.loads(
                (Workspace / "repair-bundle.json").read_text(encoding="utf-8")
            )

        self.assertEqual("repair-bundle.json", Evidence["repair_bundle"])
        self.assertTrue(RepairBundle["synthetic"])
        self.assertEqual("0002-profile-context-failure.patch", RepairBundle["failed_patch"])
        self.assertEqual(64, len(RepairBundle["failed_patch_sha256"]))
        self.assertEqual(["browser/profile.cc"], RepairBundle["affected_paths"])
        self.assertIn("qualification_request", RepairBundle)
        self.assertIn("evidence", RepairBundle)

    def test_pass_evidence_is_derived_and_validated(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, _ = self.RunFixture(TempDirectory, "success")

        PatchQualify.ValidateEvidence(Evidence)
        self.assertEqual("PASS", Evidence["result"])
        self.assertTrue(Evidence["synthetic"])
        self.assertEqual("SYNTHETIC_FIXTURE_ONLY", Evidence["engine_validation"])
        self.assertIsNone(Evidence["execution"]["failure_class"])

    def test_synthetic_marker_cannot_be_omitted_or_weakened(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, _ = self.RunFixture(TempDirectory, "success")
        AlteredEvidence = copy.deepcopy(Evidence)
        AlteredEvidence["synthetic"] = False

        with self.assertRaisesRegex(ValueError, "marked synthetic"):
            PatchQualify.ValidateEvidence(AlteredEvidence)

    def test_evidence_hashes_are_deterministic(self):
        with tempfile.TemporaryDirectory() as FirstDirectory:
            FirstEvidence, _ = self.RunFixture(FirstDirectory, "success")
        with tempfile.TemporaryDirectory() as SecondDirectory:
            SecondEvidence, _ = self.RunFixture(SecondDirectory, "success")

        self.assertEqual(FirstEvidence, SecondEvidence)

    def test_invalid_request_cannot_create_pass_or_integration_tree(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(
                TempDirectory, "success", RequestName="invalid-sha.json"
            )

            self.assertEqual("FAIL", Evidence["result"])
            self.assertEqual("INVALID_REQUEST", Evidence["execution"]["failure_class"])
            self.assertFalse((Workspace / "integration").exists())

    def test_evidence_write_failure_returns_failure_and_cannot_promote_state(self):
        CanonicalState = RepositoryRoot / "state" / "upstream.json"
        StateBefore = CanonicalState.read_bytes()

        def FailWriter(Destination: Path, Data) -> None:
            raise OSError("simulated evidence failure")

        with tempfile.TemporaryDirectory() as TempDirectory:
            Evidence, Workspace = self.RunFixture(
                TempDirectory, "success", JsonWriterValue=FailWriter
            )

            self.assertEqual("FAIL", Evidence["result"])
            self.assertEqual(
                "EVIDENCE_WRITE_FAILED", Evidence["execution"]["failure_class"]
            )
            self.assertFalse((Workspace / "evidence.json").exists())
        self.assertEqual(StateBefore, CanonicalState.read_bytes())

    def test_success_and_failure_leave_original_sources_and_authority_state_unchanged(self):
        CanonicalState = RepositoryRoot / "state" / "upstream.json"
        StateBefore = CanonicalState.read_bytes()
        BaseBefore = self.TreeDigest(SourceRoot / "base")
        MismatchBefore = self.TreeDigest(SourceRoot / "mismatch")

        with tempfile.TemporaryDirectory() as SuccessDirectory:
            SuccessEvidence, _ = self.RunFixture(SuccessDirectory, "success")
        with tempfile.TemporaryDirectory() as FailureDirectory:
            FailureEvidence, _ = self.RunFixture(
                FailureDirectory, "success", SourceName="mismatch"
            )

        self.assertEqual("PASS", SuccessEvidence["result"])
        self.assertEqual("FAIL", FailureEvidence["result"])
        self.assertEqual(BaseBefore, self.TreeDigest(SourceRoot / "base"))
        self.assertEqual(MismatchBefore, self.TreeDigest(SourceRoot / "mismatch"))
        self.assertEqual(StateBefore, CanonicalState.read_bytes())

    def test_candidate_present_state_cannot_be_promoted_by_engine(self):
        StateData = {
            "schema_version": 1,
            "candidate": {
                "channel": "Stable",
                "platform": "Windows",
                "chrome_version": "123.0.6312.86",
                "chromium_sha": "0123456789abcdef0123456789abcdef01234567",
                "detected_at": "2026-01-02T03:04:05Z",
                "qualification": "UNQUALIFIED",
            },
            "qualified": {
                "channel": "Stable",
                "platform": "Windows",
                "chrome_version": "122.0.6261.128",
                "chromium_sha": "1111111111111111111111111111111111111111",
                "qualification_level": "PATCH-APPLY",
                "qualified_at": "2026-01-01T03:04:05Z",
            },
            "released": {
                "channel": "Stable",
                "platform": "Windows",
                "chrome_version": "121.0.6167.184",
                "chromium_sha": "2222222222222222222222222222222222222222",
                "release_version": "0.0.1-test",
                "released_at": "2025-12-01T03:04:05Z",
            },
        }
        with tempfile.TemporaryDirectory() as TempDirectory:
            TempRoot = Path(TempDirectory)
            StatePath = TempRoot / "upstream.json"
            StatePath.write_text(json.dumps(StateData, indent=2) + "\n", encoding="utf-8")
            StateBefore = StatePath.read_bytes()

            Evidence = PatchQualify.RunQualification(
                RequestRoot / "valid.json",
                SourceRoot / "base",
                FixtureRepositoryRoot / "success",
                TempRoot / "workspace",
                "authority-state",
            )

            self.assertEqual("PASS", Evidence["result"])
            self.assertEqual(StateBefore, StatePath.read_bytes())

    def test_cli_success_and_failure_exit_codes_and_json(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            TempRoot = Path(TempDirectory)
            SuccessWorkspace = TempRoot / "success-workspace"
            FailureWorkspace = TempRoot / "failure-workspace"
            CommonArguments = [
                sys.executable,
                str(ScriptPath),
                "--request",
                str(RequestRoot / "valid.json"),
                "--source-kind",
                "synthetic-fixture",
                "--json",
            ]
            SuccessResult = subprocess.run(
                CommonArguments
                + [
                    "--source",
                    str(SourceRoot / "base"),
                    "--repository-root",
                    str(FixtureRepositoryRoot / "success"),
                    "--workspace",
                    str(SuccessWorkspace),
                    "--fixture-id",
                    "cli-success",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            FailureResult = subprocess.run(
                CommonArguments
                + [
                    "--source",
                    str(SourceRoot / "base"),
                    "--repository-root",
                    str(FixtureRepositoryRoot / "failure"),
                    "--workspace",
                    str(FailureWorkspace),
                    "--fixture-id",
                    "cli-failure",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(0, SuccessResult.returncode, SuccessResult.stderr)
        self.assertEqual("PASS", json.loads(SuccessResult.stdout)["result"])
        self.assertEqual(1, FailureResult.returncode)
        self.assertEqual("FAIL", json.loads(FailureResult.stdout)["result"])


if __name__ == "__main__":
    unittest.main()
