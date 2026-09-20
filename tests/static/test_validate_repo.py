"""Unit tests for repository static validation."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


ValidatorPath = Path(__file__).parents[2] / "scripts" / "validate_repo.py"
ModuleSpec = importlib.util.spec_from_file_location("ValidateRepo", ValidatorPath)
assert ModuleSpec is not None and ModuleSpec.loader is not None
ValidateRepo = importlib.util.module_from_spec(ModuleSpec)
ModuleSpec.loader.exec_module(ValidateRepo)


class ValidatorTests(unittest.TestCase):
    def CreateRepository(self, Root: Path) -> None:
        for RelativePath in ValidateRepo.RequiredFiles:
            PathToCreate = Root / RelativePath
            PathToCreate.parent.mkdir(parents=True, exist_ok=True)
            PathToCreate.write_text("placeholder\n", encoding="utf-8")

        (Root / "patches" / "series").write_text("# Empty\n", encoding="utf-8")
        EmptyState = {
            "schema_version": 1,
            "candidate": None,
            "qualified": None,
            "released": None,
        }
        for StateName in ("upstream.example.json", "upstream.json"):
            (Root / "state" / StateName).write_text(
                json.dumps(EmptyState), encoding="utf-8"
            )
        (Root / "state" / "qualification-request.schema.json").write_text(
            json.dumps({"type": "object"}), encoding="utf-8"
        )

    def RunValidator(self, Root: Path):
        Output = io.StringIO()
        with contextlib.redirect_stdout(Output):
            ExitCode = ValidateRepo.Main(["--root", str(Root)])
        return ExitCode, Output.getvalue()

    def test_minimal_valid_repository_passes(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Root = Path(TempDirectory)
            self.CreateRepository(Root)
            ExitCode, Output = self.RunValidator(Root)

        self.assertEqual(0, ExitCode, Output)
        self.assertIn("STATIC validation passed", Output)

    def test_duplicate_series_entry_fails(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Root = Path(TempDirectory)
            self.CreateRepository(Root)
            PatchName = "0001-example.patch"
            (Root / "patches" / PatchName).write_text(
                "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n",
                encoding="utf-8",
            )
            (Root / "patches" / "series").write_text(
                f"{PatchName}\n{PatchName}\n", encoding="utf-8"
            )
            ExitCode, Output = self.RunValidator(Root)

        self.assertEqual(1, ExitCode)
        self.assertIn("duplicate", Output.lower())

    def test_unlisted_patch_fails(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Root = Path(TempDirectory)
            self.CreateRepository(Root)
            (Root / "patches" / "0001-unlisted.patch").write_text(
                "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n",
                encoding="utf-8",
            )
            ExitCode, Output = self.RunValidator(Root)

        self.assertEqual(1, ExitCode)
        self.assertIn("unlisted", Output.lower())

    def test_patch_number_must_match_series_position(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Root = Path(TempDirectory)
            self.CreateRepository(Root)
            PatchName = "0002-out-of-order.patch"
            (Root / "patches" / PatchName).write_text(
                "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n",
                encoding="utf-8",
            )
            (Root / "patches" / "series").write_text(
                f"{PatchName}\n", encoding="utf-8"
            )
            ExitCode, Output = self.RunValidator(Root)

        self.assertEqual(1, ExitCode)
        self.assertIn("order mismatch", Output.lower())

    def test_empty_listed_patch_fails(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Root = Path(TempDirectory)
            self.CreateRepository(Root)
            PatchName = "0001-empty.patch"
            (Root / "patches" / PatchName).write_text("", encoding="utf-8")
            (Root / "patches" / "series").write_text(
                f"{PatchName}\n", encoding="utf-8"
            )
            ExitCode, Output = self.RunValidator(Root)

        self.assertEqual(1, ExitCode)
        self.assertIn("patch is empty", Output.lower())

    def test_invalid_json_fails(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Root = Path(TempDirectory)
            self.CreateRepository(Root)
            (Root / "state" / "broken.json").write_text("{", encoding="utf-8")
            ExitCode, Output = self.RunValidator(Root)

        self.assertEqual(1, ExitCode)
        self.assertIn("invalid JSON", Output)

    def test_unsupported_state_schema_fails(self):
        with tempfile.TemporaryDirectory() as TempDirectory:
            Root = Path(TempDirectory)
            self.CreateRepository(Root)
            (Root / "state" / "upstream.json").write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "candidate": None,
                        "qualified": None,
                        "released": None,
                    }
                ),
                encoding="utf-8",
            )
            ExitCode, Output = self.RunValidator(Root)

        self.assertEqual(1, ExitCode)
        self.assertIn("unsupported project state schema_version", Output)


if __name__ == "__main__":
    unittest.main()
