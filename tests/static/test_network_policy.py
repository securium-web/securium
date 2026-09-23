"""Offline tests for the network and service policy foundation."""

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


RepositoryRoot = Path(__file__).parents[2]
ScriptPath = RepositoryRoot / "scripts" / "network_policy.py"
PolicyPath = RepositoryRoot / "policy" / "network-service-policy.json"
SchemaPath = RepositoryRoot / "policy" / "network-service-policy.schema.json"
CasesPath = (
    RepositoryRoot / "tests" / "fixtures" / "network-policy" / "comparison-cases.json"
)
ModuleSpec = importlib.util.spec_from_file_location("NetworkPolicy", ScriptPath)
assert ModuleSpec is not None and ModuleSpec.loader is not None
NetworkPolicy = importlib.util.module_from_spec(ModuleSpec)
ModuleSpec.loader.exec_module(NetworkPolicy)


def MakeService(State: str) -> dict:
    ServiceId = {
        "ALLOW_BACKGROUND": "allowed_background",
        "CONDITIONAL": "conditional_service",
        "DENY": "denied_service",
        "EXTENSION_DIRECTED": "extension_service",
        "REPLACED": "replaced_service",
        "SITE_DIRECTED": "site_service",
        "USER_INITIATED": "user_service",
    }[State]
    Initiator = {
        "ALLOW_BACKGROUND": "BROWSER_NATIVE_BACKGROUND",
        "CONDITIONAL": "BROWSER_NATIVE_CONDITIONAL",
        "DENY": "BROWSER_NATIVE_BACKGROUND",
        "EXTENSION_DIRECTED": "EXTENSION_DIRECTED",
        "REPLACED": "BROWSER_NATIVE_BACKGROUND",
        "SITE_DIRECTED": "SITE_DIRECTED",
        "USER_INITIATED": "USER_TRIGGERED_SERVICE",
    }[State]
    DestinationClass = {
        "EXTENSION_DIRECTED": "EXTENSION_CONTROLLED",
        "SITE_DIRECTED": "SITE_CONTROLLED",
    }.get(State, "OTHER_THIRD_PARTY_SERVICE")
    CredentialMode = {
        "EXTENSION_DIRECTED": "EXTENSION_CONTROLLED",
        "SITE_DIRECTED": "SITE_CONTROLLED",
    }.get(State, "NONE")
    return {
        "activation_condition": (
            {
                "description": "The synthetic background mode is enabled.",
                "id": "background_mode_enabled",
            }
            if State == "CONDITIONAL"
            else None
        ),
        "controls": {
            "build_flags": [],
            "features": [],
            "policy_hooks": [],
            "prefs": [],
            "provider_boundaries": [],
        },
        "credential_modes": [CredentialMode],
        "data_categories": ["OTHER"],
        "destination_classes": [DestinationClass],
        "expected_destination_constraints": [],
        "initiator_class": Initiator,
        "name": f"Synthetic {State}",
        "policy_state": State,
        "policy_status": "APPROVED",
        "qualification_scenarios": [],
        "rationale": "Invented fixture used only to test deterministic static policy logic.",
        "replacement_boundary": (
            {
                "enforcement_boundary": "Synthetic provider selection",
                "replacement_service_id": "replacement_service",
                "upstream_provider": "upstream.example.test",
            }
            if State == "REPLACED"
            else None
        ),
        "service_id": ServiceId,
        "source_mapping_hints": {
            "source_paths": [],
            "traffic_annotation_ids": [],
        },
        "trigger": {
            "description": "The synthetic service operation is requested.",
            "id": "service_operation",
        },
        "user_action": (
            {
                "description": "The user requests the synthetic service.",
                "id": "request_service_now",
            }
            if State == "USER_INITIATED"
            else None
        ),
    }


def MakePolicy(State: str = "ALLOW_BACKGROUND") -> dict:
    return {
        "policy_id": NetworkPolicy.PolicyId,
        "schema_version": NetworkPolicy.SchemaVersion,
        "services": [MakeService(State)],
    }


def MakeCapability() -> dict:
    return {
        "activation_gates": {
            "build_flags": [],
            "features": [],
            "policy_hooks": [],
            "prefs": [],
        },
        "capability_id": "synthetic_capability",
        "credential_modes": ["NONE"],
        "data_categories": ["OTHER"],
        "destination_classes": ["OTHER_THIRD_PARTY_SERVICE"],
        "initiator_class": "BROWSER_NATIVE_BACKGROUND",
        "provider_boundary": None,
        "service_id": "allowed_background",
        "source_mapping": {
            "source_paths": ["components/example/service.cc"],
            "traffic_annotation_ids": ["synthetic_annotation"],
        },
        "trigger_id": "service_operation",
    }


def MakeInventory(Capabilities: list, ShaCharacter: str) -> dict:
    return {
        "capabilities": Capabilities,
        "chromium_sha": ShaCharacter * 40,
        "chromium_version": "153.0.0.0",
        "schema_version": 1,
    }


def MakeObservation(Service: dict, Case: dict) -> dict:
    State = Case["service_template"]
    if State == "SITE_DIRECTED":
        ServiceId = None
        Initiator = "SITE_DIRECTED"
        DestinationClass = "SITE_CONTROLLED"
        CredentialModes = ["SITE_CONTROLLED"]
    elif State == "EXTENSION_DIRECTED":
        ServiceId = None
        Initiator = "EXTENSION_DIRECTED"
        DestinationClass = "EXTENSION_CONTROLLED"
        CredentialModes = ["EXTENSION_CONTROLLED"]
    else:
        ServiceId = Service["service_id"]
        Initiator = Service["initiator_class"]
        DestinationClass = Service["destination_classes"][0]
        CredentialModes = Service["credential_modes"]
    return {
        "connections": [
            {
                "connection_id": "synthetic_connection",
                "credential_modes": CredentialModes,
                "data_categories": ["OTHER"],
                "destination": "service.example.test",
                "destination_class": DestinationClass,
                "initiator_class": Initiator,
                "provider_boundary": None,
                "service_id": ServiceId,
                "trigger_id": "service_operation",
            }
        ],
        "satisfied_conditions": Case.get("satisfied_conditions", []),
        "scenario_id": "synthetic_scenario",
        "schema_version": 1,
        "user_actions": Case.get("user_actions", []),
    }


class NetworkPolicyTests(unittest.TestCase):
    def test_canonical_policy_and_schema_are_valid(self) -> None:
        Policy = NetworkPolicy.LoadPolicy(PolicyPath, RequireCanonical=True)
        self.assertEqual(6, len(Policy["services"]))
        Schema = json.loads(SchemaPath.read_text(encoding="utf-8"))
        self.assertEqual(
            NetworkPolicy.PolicyId,
            Schema["properties"]["policy_id"]["const"],
        )
        self.assertEqual(1, Schema["properties"]["schema_version"]["const"])

    def test_lens_requires_disclosed_action_and_rejects_background(self) -> None:
        Policy = NetworkPolicy.LoadPolicy(PolicyPath, RequireCanonical=True)
        Lens = NetworkPolicy.ServiceIndex(Policy)["lens"]
        Observation = MakeObservation(Lens, {"service_template": "USER_INITIATED"})
        Observation["scenario_id"] = "lens_explicit_invocation"
        Connection = Observation["connections"][0]
        Connection["data_categories"] = ["PAGE_CONTENT"]
        Connection["trigger_id"] = Lens["trigger"]["id"]
        Observation["user_actions"] = [Lens["user_action"]["id"]]

        def Compare():
            return NetworkPolicy.ComparePolicyEvidence(
                Policy, MakeInventory([], "b"), ObservationData=[Observation])

        self.assertEqual("PASS", Compare()["result"])
        Observation["user_actions"] = []
        self.assertIn("USER_ACTION_NOT_OBSERVED",
                      {Issue["code"] for Issue in Compare()["issues"]})
        Observation["user_actions"] = [Lens["user_action"]["id"]]
        Connection["initiator_class"] = "BROWSER_NATIVE_BACKGROUND"
        self.assertEqual("FAIL", Compare()["result"])
        Connection["initiator_class"] = Lens["initiator_class"]
        for Scenario in ("lens_background_context", "lens_cold_start", "lens_idle_browsing"):
            Observation["scenario_id"] = Scenario
            self.assertEqual("FAIL", Compare()["result"])

    def test_cli_validates_canonical_policy(self) -> None:
        Result = subprocess.run(
            [sys.executable, str(ScriptPath), "validate", "--policy", str(PolicyPath)],
            cwd=RepositoryRoot,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, Result.returncode, Result.stderr)
        self.assertIn("valid", Result.stdout.lower())

    def test_cross_field_rules_fail_closed(self) -> None:
        Mutations = []
        Conditional = MakePolicy("CONDITIONAL")
        Conditional["services"][0]["activation_condition"] = None
        Mutations.append(Conditional)
        UserInitiated = MakePolicy("USER_INITIATED")
        UserInitiated["services"][0]["user_action"] = None
        Mutations.append(UserInitiated)
        Replaced = MakePolicy("REPLACED")
        Replaced["services"][0]["replacement_boundary"] = None
        Mutations.append(Replaced)
        Unclassified = MakePolicy()
        Unclassified["services"][0]["policy_state"] = "UNCLASSIFIED"
        Mutations.append(Unclassified)
        for Policy in Mutations:
            with self.subTest(state=Policy["services"][0]["policy_state"]):
                with self.assertRaises(NetworkPolicy.PolicyValidationError):
                    NetworkPolicy.ValidatePolicyDocument(Policy)

    def test_unknown_fields_and_taxonomy_values_fail(self) -> None:
        UnknownField = MakePolicy()
        UnknownField["services"][0]["unexpected"] = True
        UnknownTaxonomy = MakePolicy()
        UnknownTaxonomy["services"][0]["data_categories"] = ["UNBOUNDED"]
        for Policy in (UnknownField, UnknownTaxonomy):
            with self.assertRaises(NetworkPolicy.PolicyValidationError):
                NetworkPolicy.ValidatePolicyDocument(Policy)

    def test_invented_comparison_cases(self) -> None:
        Fixture = json.loads(CasesPath.read_text(encoding="utf-8"))
        self.assertEqual(1, Fixture["schema_version"])
        self.assertEqual(14, len(Fixture["cases"]))
        for Case in Fixture["cases"]:
            with self.subTest(case=Case["case_id"]):
                Result = self.RunCase(Case)
                Codes = {Issue["code"] for Issue in Result["issues"]}
                self.assertEqual(Case["expected_result"], Result["result"])
                self.assertTrue(set(Case["expected_issue_codes"]).issubset(Codes))
                DeltaBucket = Case.get("expected_delta_bucket")
                if DeltaBucket is not None:
                    self.assertTrue(Result["inventory_delta"][DeltaBucket])

    def test_absence_fails_only_for_explicit_must_observe(self) -> None:
        Policy = MakePolicy()
        EmptyObservation = {
            "connections": [],
            "satisfied_conditions": [],
            "scenario_id": "synthetic_scenario",
            "schema_version": 1,
            "user_actions": [],
        }
        EmptyInventory = MakeInventory([], "b")
        Result = NetworkPolicy.ComparePolicyEvidence(
            Policy, EmptyInventory, ObservationData=[EmptyObservation]
        )
        self.assertEqual("PASS", Result["result"])
        Policy["services"][0]["qualification_scenarios"] = [
            {"expectation": "MUST_OBSERVE", "scenario_id": "synthetic_scenario"}
        ]
        Result = NetworkPolicy.ComparePolicyEvidence(
            Policy, EmptyInventory, ObservationData=[EmptyObservation]
        )
        self.assertEqual("FAIL", Result["result"])
        self.assertEqual("EXPECTED_SERVICE_NOT_OBSERVED", Result["issues"][0]["code"])

    def test_outputs_are_deterministic_and_marked_synthetic(self) -> None:
        Policy = MakePolicy()
        Inventory = MakeInventory([MakeCapability()], "b")
        First = NetworkPolicy.ComparePolicyEvidence(Policy, Inventory)
        Second = NetworkPolicy.ComparePolicyEvidence(Policy, Inventory)
        self.assertEqual(First, Second)
        self.assertTrue(First["synthetic_comparison_only"])

    def test_every_material_inventory_semantic_blocks_adoption(self) -> None:
        Mutations = {
            "activation_gates": lambda Capability: Capability["activation_gates"][
                "features"
            ].append("changed_feature"),
            "destination_classes": lambda Capability: Capability.update(
                {"destination_classes": ["DYNAMIC_OR_UNKNOWN"]}
            ),
            "initiator_class": lambda Capability: Capability.update(
                {"initiator_class": "BROWSER_NATIVE_CONDITIONAL"}
            ),
            "provider_boundary": lambda Capability: Capability.update(
                {"provider_boundary": "changed-provider"}
            ),
            "service_id": lambda Capability: Capability.update(
                {"service_id": "changed_service"}
            ),
        }
        for Field, Mutate in Mutations.items():
            with self.subTest(field=Field):
                Previous = MakeCapability()
                Current = copy.deepcopy(Previous)
                Mutate(Current)
                Result = NetworkPolicy.ComparePolicyEvidence(
                    MakePolicy(),
                    MakeInventory([Current], "b"),
                    PreviousInventoryData=MakeInventory([Previous], "a"),
                )
                Codes = {Issue["code"] for Issue in Result["issues"]}
                self.assertEqual("FAIL", Result["result"])
                self.assertIn("MATERIAL_CAPABILITY_CHANGE", Codes)

    def test_destination_constraints_are_enforced_semantically(self) -> None:
        Policy = MakePolicy()
        Policy["services"][0]["expected_destination_constraints"] = [
            {"constraint_type": "HOSTNAME_SUFFIX", "value": "example.test"}
        ]
        Case = {
            "satisfied_conditions": [],
            "service_template": "ALLOW_BACKGROUND",
            "user_actions": [],
        }
        Observation = MakeObservation(Policy["services"][0], Case)
        Inventory = MakeInventory([], "b")
        Passing = NetworkPolicy.ComparePolicyEvidence(
            Policy, Inventory, ObservationData=[Observation]
        )
        self.assertEqual("PASS", Passing["result"])
        Observation["connections"][0]["destination"] = "unexpected.invalid"
        Failing = NetworkPolicy.ComparePolicyEvidence(
            Policy, Inventory, ObservationData=[Observation]
        )
        self.assertEqual("FAIL", Failing["result"])
        self.assertEqual("destination_constraint", Failing["issues"][0]["field"])

    def RunCase(self, Case: dict) -> dict:
        Operation = Case["operation"]
        if Operation == "RUNTIME":
            Policy = MakePolicy(Case["service_template"])
            Service = Policy["services"][0]
            Observation = MakeObservation(Service, Case)
            return NetworkPolicy.ComparePolicyEvidence(
                Policy,
                MakeInventory([], "b"),
                ObservationData=[Observation],
            )

        Policy = MakePolicy()
        PreviousCapabilities = [MakeCapability()]
        CurrentCapabilities = [copy.deepcopy(PreviousCapabilities[0])]
        if Operation == "NEW_UNCLASSIFIED":
            PreviousCapabilities = []
            CurrentCapabilities[0]["service_id"] = None
        elif Operation == "CHANGED_TRIGGER":
            CurrentCapabilities[0]["trigger_id"] = "changed_operation"
        elif Operation == "CHANGED_DATA":
            CurrentCapabilities[0]["data_categories"] = ["OTHER", "URL"]
        elif Operation == "CHANGED_CREDENTIAL":
            CurrentCapabilities[0]["credential_modes"] = ["COOKIES", "NONE"]
        elif Operation == "REMOVED_CAPABILITY":
            CurrentCapabilities = []
        elif Operation == "SOURCE_MAPPING_CHANGE":
            CurrentCapabilities[0]["source_mapping"]["source_paths"] = [
                "components/example/moved_service.cc"
            ]
        else:
            self.fail(f"Unknown fixture operation: {Operation}")
        return NetworkPolicy.ComparePolicyEvidence(
            Policy,
            MakeInventory(CurrentCapabilities, "b"),
            PreviousInventoryData=MakeInventory(PreviousCapabilities, "a"),
        )


if __name__ == "__main__":
    unittest.main()
