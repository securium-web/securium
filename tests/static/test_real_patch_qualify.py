"""Offline adapter tests using invented Git roots; never Chromium qualification."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import real_patch_qualify as Real


class RealAdapterTests(unittest.TestCase):
    def setUp(self):
        self.Temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.Temporary.cleanup)
        self.Root = Path(self.Temporary.name)
        self.Source = self.Root / "source"
        self.Source.mkdir()
        self.Git("init")
        self.Git("config", "user.email", "fixture@example.invalid")
        self.Git("config", "user.name", "Fixture")
        self.Git("config", "core.autocrlf", "false")
        self.Git("remote", "add", "origin", Real.ChromiumOrigin)
        for Name, Contents in {".gn": "fixture\n", "DEPS": "fixture\n",
                               "chrome/VERSION": "MAJOR=1\nMINOR=0\nBUILD=0\nPATCH=0\n",
                               "google_apis/BUILD.gn": "before\n"}.items():
            File = self.Source / Name
            File.parent.mkdir(parents=True, exist_ok=True)
            File.write_text(Contents, newline="\n")
        self.Git("add", ".")
        self.Git("commit", "-m", "fixture")
        self.Candidate = {"chrome_version": "1.0.0.0", "chromium_sha": self.Git("rev-parse", "HEAD")}
        self.Repository = self.Root / "repository"
        (self.Repository / "patches").mkdir(parents=True)
        (self.Repository / "src/chromium").mkdir(parents=True)
        self.Name = "0001-fixture.patch"
        (self.Repository / "patches/series").write_text(self.Name + "\n")
        (self.Repository / "patches" / self.Name).write_text(
            "diff --git a/google_apis/BUILD.gn b/google_apis/BUILD.gn\n"
            "--- a/google_apis/BUILD.gn\n+++ b/google_apis/BUILD.gn\n"
            "@@ -1 +1 @@\n-before\n+after\n", newline="\n")
        self.Request = self.Root / "request.json"
        self.Request.write_text(json.dumps({"schema_version": 1, "candidate": self.Candidate,
                                           "previous_qualified": None}))

    def Git(self, *Arguments):
        return subprocess.check_output(["git", *Arguments], cwd=self.Source,
                                       stderr=subprocess.DEVNULL, text=True).strip()

    def Execute(self):
        return Real.Run(self.Request, self.Source, self.Repository, self.Root / "run")

    def test_application_and_mutated_follow_on_rejected(self):
        Report = self.Execute()
        self.assertEqual("PASS", Report["result"], Report)
        self.assertFalse(Report["synthetic"])
        Integration = self.Root / "run/integration"
        Real.CheckIntegration(Integration, Report)
        (Integration / "DEPS").write_text("tampered")
        with self.assertRaises(ValueError):
            Real.CheckIntegration(Integration, Report)
        self.assertEqual("", self.Git("status", "--porcelain"))

    def test_dirty_root_rejected(self):
        (self.Source / "DEPS").write_text("dirty")
        self.assertEqual("INVALID_SOURCE", self.Execute()["execution"]["failure_class"])

    def test_wrong_origin_rejected(self):
        self.Git("remote", "set-url", "origin", "https://example.invalid/other")
        self.assertEqual("INVALID_SOURCE", self.Execute()["execution"]["failure_class"])

    def test_wrong_sha_rejected(self):
        self.Candidate["chromium_sha"] = "f" * 40
        with self.assertRaises(Real.Engine.StageFailure):
            Real.CheckIdentity(self.Source, self.Candidate)

    def test_failed_patch_not_promoted(self):
        File = self.Repository / "patches" / self.Name
        File.write_text(File.read_text().replace("-before", "-mismatch"), newline="\n")
        Report = self.Execute()
        self.assertEqual("FAIL", Report["result"])
        self.assertEqual([], Report["execution"]["applied_patches"])

    def test_synthetic_evidence_rejected(self):
        with self.assertRaises(ValueError):
            Real.ValidateEvidence(Real.Engine.BaseEvidence())


if __name__ == "__main__":
    unittest.main()
