"""Offline tests for the intended build-policy manifest."""

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


RepositoryRoot = Path(__file__).parents[2]
ScriptPath = RepositoryRoot / "scripts" / "build_policy.py"
ManifestPath = RepositoryRoot / "policy" / "build-policy.json"
SchemaPath = RepositoryRoot / "policy" / "build-policy.schema.json"
NetworkPolicyPath = RepositoryRoot / "policy" / "network-service-policy.json"
CasesPath = RepositoryRoot / "tests" / "fixtures" / "build-policy" / "cases.json"
MalformedPath = (
    RepositoryRoot / "tests" / "fixtures" / "build-policy" / "malformed.json"
)
ModuleSpec = importlib.util.spec_from_file_location("BuildPolicy", ScriptPath)
assert ModuleSpec is not None and ModuleSpec.loader is not None
BuildPolicy = importlib.util.module_from_spec(ModuleSpec)
ModuleSpec.loader.exec_module(BuildPolicy)


class BuildPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.CanonicalManifest = json.loads(ManifestPath.read_text(encoding="utf-8"))
        cls.ApprovedServiceIds = BuildPolicy.LoadApprovedServiceIds(NetworkPolicyPath)

    def test_canonical_manifest_and_schema_are_valid(self) -> None:
        Manifest = BuildPolicy.LoadManifest(
            ManifestPath,
            NetworkPolicyPath=NetworkPolicyPath,
            RequireCanonical=True,
        )
        self.assertEqual(11, len(Manifest["settings"]))
        Schema = json.loads(SchemaPath.read_text(encoding="utf-8"))
        self.assertEqual(
            BuildPolicy.ManifestId,
            Schema["properties"]["manifest_id"]["const"],
        )
        self.assertEqual(
            BuildPolicy.SchemaVersion,
            Schema["properties"]["schema_version"]["const"],
        )

    def test_cli_validates_only_intended_static_policy(self) -> None:
        Result = subprocess.run(
            [sys.executable, str(ScriptPath)],
            cwd=RepositoryRoot,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, Result.returncode, Result.stderr)
        self.assertIn("STATIC intended-policy validation passed", Result.stdout)
        self.assertIn("runtime behavior are unverified", Result.stdout)

    def test_invented_fixture_cases(self) -> None:
        Fixture = json.loads(CasesPath.read_text(encoding="utf-8"))
        self.assertEqual(1, Fixture["schema_version"])
        self.assertEqual(13, len(Fixture["cases"]))
        for Case in Fixture["cases"]:
            with self.subTest(case=Case["case_id"]):
                Manifest = copy.deepcopy(self.CanonicalManifest)
                self.ApplyCase(Manifest, Case)
                if Case["expected_valid"]:
                    Validated = BuildPolicy.ValidateManifestDocument(
                        Manifest, self.ApprovedServiceIds
                    )
                    self.assertEqual(BuildPolicy.ManifestId, Validated["manifest_id"])
                else:
                    with self.assertRaisesRegex(
                        BuildPolicy.BuildPolicyValidationError,
                        Case["expected_error"],
                    ):
                        BuildPolicy.ValidateManifestDocument(
                            Manifest, self.ApprovedServiceIds
                        )

    def test_malformed_json_fixture_fails(self) -> None:
        with self.assertRaisesRegex(
            BuildPolicy.BuildPolicyValidationError,
            "cannot read build policy manifest",
        ):
            BuildPolicy.LoadManifest(MalformedPath)

    def test_unknown_policy_mode_and_fields_fail(self) -> None:
        UnknownMode = copy.deepcopy(self.CanonicalManifest)
        UnknownMode["settings"][0]["requirement"] = "BEST_EFFORT"
        with self.assertRaisesRegex(
            BuildPolicy.BuildPolicyValidationError, "unsupported value"
        ):
            BuildPolicy.ValidateManifestDocument(UnknownMode)

        UnknownField = copy.deepcopy(self.CanonicalManifest)
        UnknownField["settings"][0]["verified"] = True
        with self.assertRaisesRegex(
            BuildPolicy.BuildPolicyValidationError, "unknown field"
        ):
            BuildPolicy.ValidateManifestDocument(UnknownField)

        IncorrectlyVerified = copy.deepcopy(self.CanonicalManifest)
        IncorrectlyVerified["settings"][0][
            "verification_status"
        ] = "VERIFIED_AT_EXACT_SHA"
        with self.assertRaisesRegex(
            BuildPolicy.BuildPolicyValidationError, "unsupported value"
        ):
            BuildPolicy.ValidateManifestDocument(IncorrectlyVerified)

    def test_allowed_set_contract_is_typed_sorted_and_unique(self) -> None:
        BaseSetting = copy.deepcopy(self.CanonicalManifest["settings"][0])
        BaseSetting.update(
            {
                "expected": ["A", "B"],
                "name": "z_future_choice",
                "requirement": "ALLOWED_SET",
            }
        )
        Manifest = copy.deepcopy(self.CanonicalManifest)
        Manifest["settings"].append(BaseSetting)
        BuildPolicy.ValidateManifestDocument(Manifest, self.ApprovedServiceIds)

        for InvalidValues in (["B", "A"], ["A", "A"], ["A", 1]):
            with self.subTest(values=InvalidValues):
                Invalid = copy.deepcopy(Manifest)
                Invalid["settings"][-1]["expected"] = InvalidValues
                with self.assertRaises(BuildPolicy.BuildPolicyValidationError):
                    BuildPolicy.ValidateManifestDocument(
                        Invalid, self.ApprovedServiceIds
                    )

    def test_network_policy_references_must_be_approved(self) -> None:
        Manifest = copy.deepcopy(self.CanonicalManifest)
        Manifest["settings"][0]["related_service_ids"] = ["unknown_service"]
        with self.assertRaisesRegex(
            BuildPolicy.BuildPolicyValidationError, "unapproved service_id"
        ):
            BuildPolicy.ValidateManifestDocument(Manifest, self.ApprovedServiceIds)

    def test_boolean_and_integer_values_are_not_interchangeable(self) -> None:
        Cases = (("is_chrome_branded", 0), ("safe_browsing_mode", True))
        for SettingName, IncorrectValue in Cases:
            with self.subTest(setting=SettingName):
                Manifest = copy.deepcopy(self.CanonicalManifest)
                Setting = next(
                    Item
                    for Item in Manifest["settings"]
                    if Item["name"] == SettingName
                )
                Setting["expected"] = IncorrectValue
                with self.assertRaises(BuildPolicy.BuildPolicyValidationError):
                    BuildPolicy.ValidateManifestDocument(
                        Manifest, self.ApprovedServiceIds
                    )

    def test_digest_is_deterministic(self) -> None:
        First = BuildPolicy.ManifestDigest(self.CanonicalManifest)
        Second = BuildPolicy.ManifestDigest(copy.deepcopy(self.CanonicalManifest))
        self.assertEqual(First, Second)

    def ApplyCase(self, Manifest: dict, Case: dict) -> None:
        Operation = Case["operation"]
        if Operation == "NONE":
            return
        if Operation == "SET_SCHEMA_VERSION":
            Manifest["schema_version"] = Case["value"]
            return
        Setting = next(
            (
                Item
                for Item in Manifest["settings"]
                if Item["name"] == Case.get("setting_name")
            ),
            None,
        )
        if Operation == "REMOVE_SETTING":
            self.assertIsNotNone(Setting)
            Manifest["settings"].remove(Setting)
        elif Operation == "SET_EXPECTED":
            self.assertIsNotNone(Setting)
            Setting["expected"] = Case["value"]
        elif Operation == "DUPLICATE_SETTING":
            self.assertIsNotNone(Setting)
            Manifest["settings"].append(copy.deepcopy(Setting))
        elif Operation == "CONTRADICT_SETTING":
            self.assertIsNotNone(Setting)
            Contradiction = copy.deepcopy(Setting)
            Contradiction["expected"] = Case["value"]
            Manifest["settings"].append(Contradiction)
        elif Operation == "ADD_SPECULATIVE_VERIFIED_SETTING":
            Speculative = copy.deepcopy(Manifest["settings"][0])
            Speculative["name"] = Case["setting_name"]
            Speculative["verification_status"] = "VERIFIED_AT_EXACT_SHA"
            Manifest["settings"].append(Speculative)
        elif Operation == "ASSERT_SETTING":
            self.assertIsNotNone(Setting)
            if "expected_classification" in Case:
                self.assertEqual(
                    Case["expected_classification"], Setting["classification"]
                )
            if "expected_stability" in Case:
                self.assertEqual(Case["expected_stability"], Setting["stability"])
            if "expected_verification_status" in Case:
                self.assertEqual(
                    Case["expected_verification_status"],
                    Setting["verification_status"],
                )
        else:
            self.fail(f"Unknown fixture operation: {Operation}")


if __name__ == "__main__":
    unittest.main()
