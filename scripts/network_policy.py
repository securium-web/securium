#!/usr/bin/env python3
"""Validate Securium network-service policy and synthetic comparison inputs."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit


SchemaVersion = 1
PolicyId = "securium-network-service-policy"
IdentifierPattern = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
ShaPattern = re.compile(r"^[0-9a-f]{40}$")

InitiatorClasses = {
    "BROWSER_NATIVE_BACKGROUND",
    "BROWSER_NATIVE_CONDITIONAL",
    "USER_TRIGGERED_SERVICE",
    "USER_REQUESTED_WEB",
    "SITE_DIRECTED",
    "EXTENSION_DIRECTED",
}
NativeInitiatorClasses = {
    "BROWSER_NATIVE_BACKGROUND",
    "BROWSER_NATIVE_CONDITIONAL",
    "USER_TRIGGERED_SERVICE",
}
PolicyStates = {
    "ALLOW_BACKGROUND",
    "CONDITIONAL",
    "USER_INITIATED",
    "SITE_DIRECTED",
    "EXTENSION_DIRECTED",
    "DENY",
    "REPLACED",
    "UNCLASSIFIED",
}
DestinationClasses = {
    "GOOGLE_OWNED_SERVICE",
    "SECURIUM_SERVICE",
    "USER_SELECTED_PROVIDER",
    "SITE_CONTROLLED",
    "EXTENSION_CONTROLLED",
    "LOCAL_OR_LOCAL_NETWORK",
    "OTHER_THIRD_PARTY_SERVICE",
    "DYNAMIC_OR_UNKNOWN",
}
DataCategories = {
    "CLIENT_VERSION",
    "OS_PLATFORM",
    "HARDWARE_CAPABILITIES",
    "COMPONENT_IDENTIFIERS",
    "NETWORK_ADDRESS",
    "URL",
    "URL_HASH_OR_PREFIX",
    "SEARCH_INPUT",
    "PAGE_CONTENT",
    "TEXT_INPUT",
    "GEOLOCATION_NETWORK_DATA",
    "ACCOUNT_IDENTITY",
    "AUTHENTICATION_MATERIAL",
    "EXTENSION_IDENTIFIERS",
    "SECURITY_INCIDENT_DATA",
    "DIAGNOSTIC_DATA",
    "MODEL_REQUEST_METADATA",
    "CONNECTIVITY_PROBE",
    "OTHER",
}
CredentialModes = {
    "NONE",
    "SERVICE_SPECIFIC_API_CREDENTIAL",
    "BROWSER_ACCOUNT_OAUTH",
    "COOKIES",
    "SITE_CONTROLLED",
    "EXTENSION_CONTROLLED",
}
PolicyStatuses = {"APPROVED", "PENDING_REVIEW"}
ScenarioExpectations = {"MAY_OBSERVE", "MUST_OBSERVE", "MUST_NOT_OBSERVE"}
ConstraintTypes = {"HOSTNAME", "HOSTNAME_SUFFIX", "URL_PREFIX", "POLICY_SELECTED"}
ControlFields = (
    "build_flags",
    "features",
    "policy_hooks",
    "prefs",
    "provider_boundaries",
)
GateFields = (
    "build_flags",
    "features",
    "policy_hooks",
    "prefs",
)
SemanticCapabilityFields = (
    "activation_gates",
    "credential_modes",
    "data_categories",
    "destination_classes",
    "initiator_class",
    "provider_boundary",
    "service_id",
    "trigger_id",
)


class PolicyValidationError(ValueError):
    """Raised when policy or synthetic evidence is invalid."""


def CanonicalJson(Data: Any) -> str:
    return json.dumps(Data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def PolicyDigest(Policy: Mapping[str, Any]) -> str:
    return hashlib.sha256(CanonicalJson(Policy).encode("utf-8")).hexdigest()


def RequireObject(Value: Any, Context: str) -> Dict[str, Any]:
    if not isinstance(Value, dict):
        raise PolicyValidationError(f"{Context} must be an object")
    return Value


def RequireExactKeys(
    Value: Mapping[str, Any], Required: Set[str], Context: str
) -> None:
    Actual = set(Value)
    Missing = sorted(Required - Actual)
    Unknown = sorted(Actual - Required)
    if Missing:
        raise PolicyValidationError(f"{Context} missing field(s): {', '.join(Missing)}")
    if Unknown:
        raise PolicyValidationError(f"{Context} has unknown field(s): {', '.join(Unknown)}")


def RequireString(Value: Any, Context: str) -> str:
    if not isinstance(Value, str) or not Value.strip():
        raise PolicyValidationError(f"{Context} must be a non-empty string")
    return Value


def RequireIdentifier(Value: Any, Context: str) -> str:
    Text = RequireString(Value, Context)
    if IdentifierPattern.fullmatch(Text) is None:
        raise PolicyValidationError(f"{Context} must be a lower_snake_case identifier")
    return Text


def RequireEnum(Value: Any, Allowed: Set[str], Context: str) -> str:
    Text = RequireString(Value, Context)
    if Text not in Allowed:
        raise PolicyValidationError(f"{Context} has unsupported value: {Text}")
    return Text


def ValidateSortedStringList(
    Value: Any,
    Context: str,
    Allowed: Optional[Set[str]] = None,
    AllowEmpty: bool = True,
) -> List[str]:
    if not isinstance(Value, list) or any(not isinstance(Item, str) for Item in Value):
        raise PolicyValidationError(f"{Context} must be an array of strings")
    if not AllowEmpty and not Value:
        raise PolicyValidationError(f"{Context} must not be empty")
    if Value != sorted(Value) or len(Value) != len(set(Value)):
        raise PolicyValidationError(f"{Context} must be sorted and unique")
    if Allowed is not None:
        Invalid = [Item for Item in Value if Item not in Allowed]
        if Invalid:
            raise PolicyValidationError(
                f"{Context} has unsupported value(s): {', '.join(Invalid)}"
            )
    return Value


def ValidateDescriptor(Value: Any, Context: str, Nullable: bool = False) -> None:
    if Value is None and Nullable:
        return
    Descriptor = RequireObject(Value, Context)
    RequireExactKeys(Descriptor, {"description", "id"}, Context)
    RequireIdentifier(Descriptor["id"], f"{Context}.id")
    RequireString(Descriptor["description"], f"{Context}.description")


def ValidateControls(Value: Any, Context: str) -> None:
    Controls = RequireObject(Value, Context)
    RequireExactKeys(Controls, set(ControlFields), Context)
    for Field in ControlFields:
        ValidateSortedStringList(Controls[Field], f"{Context}.{Field}")


def ValidateActivationGates(Value: Any, Context: str) -> None:
    Gates = RequireObject(Value, Context)
    RequireExactKeys(Gates, set(GateFields), Context)
    for Field in GateFields:
        ValidateSortedStringList(Gates[Field], f"{Context}.{Field}")


def ValidateSourceMapping(Value: Any, Context: str) -> None:
    MappingValue = RequireObject(Value, Context)
    RequireExactKeys(
        MappingValue, {"source_paths", "traffic_annotation_ids"}, Context
    )
    ValidateSortedStringList(
        MappingValue["traffic_annotation_ids"], f"{Context}.traffic_annotation_ids"
    )
    Paths = ValidateSortedStringList(
        MappingValue["source_paths"], f"{Context}.source_paths"
    )
    for SourcePath in Paths:
        if (
            "\\" in SourcePath
            or SourcePath.startswith("/")
            or re.match(r"^[A-Za-z]:", SourcePath)
            or ".." in Path(SourcePath).parts
        ):
            raise PolicyValidationError(
                f"{Context}.source_paths contains an unsafe path: {SourcePath}"
            )


def ValidateConstraints(Value: Any, Context: str) -> None:
    if not isinstance(Value, list):
        raise PolicyValidationError(f"{Context} must be an array")
    SortKeys: List[Tuple[str, str]] = []
    for Index, Item in enumerate(Value):
        ItemContext = f"{Context}[{Index}]"
        Constraint = RequireObject(Item, ItemContext)
        RequireExactKeys(Constraint, {"constraint_type", "value"}, ItemContext)
        ConstraintType = RequireEnum(
            Constraint["constraint_type"], ConstraintTypes, f"{ItemContext}.constraint_type"
        )
        ConstraintValue = RequireString(Constraint["value"], f"{ItemContext}.value")
        SortKeys.append((ConstraintType, ConstraintValue))
    if SortKeys != sorted(SortKeys) or len(SortKeys) != len(set(SortKeys)):
        raise PolicyValidationError(f"{Context} must be sorted and unique")


def ValidateScenarios(Value: Any, Context: str) -> None:
    if not isinstance(Value, list):
        raise PolicyValidationError(f"{Context} must be an array")
    ScenarioIds: List[str] = []
    for Index, Item in enumerate(Value):
        ItemContext = f"{Context}[{Index}]"
        Scenario = RequireObject(Item, ItemContext)
        RequireExactKeys(Scenario, {"expectation", "scenario_id"}, ItemContext)
        ScenarioIds.append(
            RequireIdentifier(Scenario["scenario_id"], f"{ItemContext}.scenario_id")
        )
        RequireEnum(
            Scenario["expectation"], ScenarioExpectations, f"{ItemContext}.expectation"
        )
    if ScenarioIds != sorted(ScenarioIds) or len(ScenarioIds) != len(set(ScenarioIds)):
        raise PolicyValidationError(f"{Context} must be sorted by unique scenario_id")


def ValidateReplacementBoundary(Value: Any, Context: str, Nullable: bool = False) -> None:
    if Value is None and Nullable:
        return
    Boundary = RequireObject(Value, Context)
    RequireExactKeys(
        Boundary,
        {"enforcement_boundary", "replacement_service_id", "upstream_provider"},
        Context,
    )
    RequireString(Boundary["enforcement_boundary"], f"{Context}.enforcement_boundary")
    RequireIdentifier(
        Boundary["replacement_service_id"], f"{Context}.replacement_service_id"
    )
    RequireString(Boundary["upstream_provider"], f"{Context}.upstream_provider")


def ValidateService(Service: Any, Context: str) -> None:
    ServiceObject = RequireObject(Service, Context)
    RequiredKeys = {
        "activation_condition",
        "controls",
        "credential_modes",
        "data_categories",
        "destination_classes",
        "expected_destination_constraints",
        "initiator_class",
        "name",
        "policy_state",
        "policy_status",
        "qualification_scenarios",
        "rationale",
        "replacement_boundary",
        "service_id",
        "source_mapping_hints",
        "trigger",
        "user_action",
    }
    RequireExactKeys(ServiceObject, RequiredKeys, Context)
    RequireIdentifier(ServiceObject["service_id"], f"{Context}.service_id")
    RequireString(ServiceObject["name"], f"{Context}.name")
    Initiator = RequireEnum(
        ServiceObject["initiator_class"], InitiatorClasses, f"{Context}.initiator_class"
    )
    State = RequireEnum(
        ServiceObject["policy_state"], PolicyStates, f"{Context}.policy_state"
    )
    Status = RequireEnum(
        ServiceObject["policy_status"], PolicyStatuses, f"{Context}.policy_status"
    )
    ValidateSortedStringList(
        ServiceObject["destination_classes"],
        f"{Context}.destination_classes",
        DestinationClasses,
        AllowEmpty=False,
    )
    ValidateConstraints(
        ServiceObject["expected_destination_constraints"],
        f"{Context}.expected_destination_constraints",
    )
    ValidateDescriptor(ServiceObject["trigger"], f"{Context}.trigger")
    ValidateDescriptor(
        ServiceObject["activation_condition"],
        f"{Context}.activation_condition",
        Nullable=True,
    )
    ValidateDescriptor(
        ServiceObject["user_action"], f"{Context}.user_action", Nullable=True
    )
    ValidateSortedStringList(
        ServiceObject["data_categories"],
        f"{Context}.data_categories",
        DataCategories,
        AllowEmpty=False,
    )
    ValidateSortedStringList(
        ServiceObject["credential_modes"],
        f"{Context}.credential_modes",
        CredentialModes,
        AllowEmpty=False,
    )
    ValidateControls(ServiceObject["controls"], f"{Context}.controls")
    ValidateReplacementBoundary(
        ServiceObject["replacement_boundary"],
        f"{Context}.replacement_boundary",
        Nullable=True,
    )
    ValidateSourceMapping(
        ServiceObject["source_mapping_hints"], f"{Context}.source_mapping_hints"
    )
    ValidateScenarios(
        ServiceObject["qualification_scenarios"],
        f"{Context}.qualification_scenarios",
    )
    RequireString(ServiceObject["rationale"], f"{Context}.rationale")

    if Status == "APPROVED" and State == "UNCLASSIFIED":
        raise PolicyValidationError(f"{Context} cannot approve UNCLASSIFIED policy")
    if Status == "PENDING_REVIEW" and State != "UNCLASSIFIED":
        raise PolicyValidationError(
            f"{Context} pending policy must remain UNCLASSIFIED"
        )
    if State == "UNCLASSIFIED" and ServiceObject["qualification_scenarios"]:
        raise PolicyValidationError(
            f"{Context} UNCLASSIFIED policy cannot define passing scenarios"
        )
    if State == "ALLOW_BACKGROUND" and Initiator != "BROWSER_NATIVE_BACKGROUND":
        raise PolicyValidationError(
            f"{Context} ALLOW_BACKGROUND requires BROWSER_NATIVE_BACKGROUND"
        )
    if State == "CONDITIONAL":
        if Initiator != "BROWSER_NATIVE_CONDITIONAL":
            raise PolicyValidationError(
                f"{Context} CONDITIONAL requires BROWSER_NATIVE_CONDITIONAL"
            )
        if ServiceObject["activation_condition"] is None:
            raise PolicyValidationError(
                f"{Context} CONDITIONAL requires activation_condition"
            )
    elif ServiceObject["activation_condition"] is not None:
        raise PolicyValidationError(
            f"{Context} activation_condition is valid only for CONDITIONAL"
        )
    if State == "USER_INITIATED":
        if Initiator != "USER_TRIGGERED_SERVICE":
            raise PolicyValidationError(
                f"{Context} USER_INITIATED requires USER_TRIGGERED_SERVICE"
            )
        if ServiceObject["user_action"] is None:
            raise PolicyValidationError(f"{Context} USER_INITIATED requires user_action")
    elif ServiceObject["user_action"] is not None:
        raise PolicyValidationError(
            f"{Context} user_action is valid only for USER_INITIATED"
        )
    if State == "SITE_DIRECTED" and Initiator != "SITE_DIRECTED":
        raise PolicyValidationError(f"{Context} SITE_DIRECTED initiator mismatch")
    if State == "EXTENSION_DIRECTED" and Initiator != "EXTENSION_DIRECTED":
        raise PolicyValidationError(f"{Context} EXTENSION_DIRECTED initiator mismatch")
    if State == "REPLACED" and ServiceObject["replacement_boundary"] is None:
        raise PolicyValidationError(f"{Context} REPLACED requires replacement_boundary")
    if State != "REPLACED" and ServiceObject["replacement_boundary"] is not None:
        raise PolicyValidationError(
            f"{Context} replacement_boundary is valid only for REPLACED"
        )


def ValidatePolicyDocument(Data: Any) -> Dict[str, Any]:
    Policy = RequireObject(Data, "policy")
    RequireExactKeys(Policy, {"policy_id", "schema_version", "services"}, "policy")
    if Policy["schema_version"] != SchemaVersion:
        raise PolicyValidationError(
            f"unsupported policy schema_version: {Policy['schema_version']}"
        )
    if Policy["policy_id"] != PolicyId:
        raise PolicyValidationError(f"unsupported policy_id: {Policy['policy_id']}")
    Services = Policy["services"]
    if not isinstance(Services, list) or not Services:
        raise PolicyValidationError("policy.services must be a non-empty array")
    ServiceIds: List[str] = []
    for Index, Service in enumerate(Services):
        ValidateService(Service, f"policy.services[{Index}]")
        ServiceIds.append(Service["service_id"])
    if ServiceIds != sorted(ServiceIds):
        raise PolicyValidationError("policy.services must be sorted by service_id")
    if len(ServiceIds) != len(set(ServiceIds)):
        raise PolicyValidationError("policy.service_id values must be unique")
    return Policy


def LoadJson(PathValue: Path, Context: str) -> Any:
    try:
        return json.loads(PathValue.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as Error:
        raise PolicyValidationError(f"cannot read {Context}: {Error}") from Error


def LoadPolicy(PathValue: Path, RequireCanonical: bool = False) -> Dict[str, Any]:
    Data = LoadJson(PathValue, "network service policy")
    Policy = ValidatePolicyDocument(Data)
    if RequireCanonical:
        try:
            Original = PathValue.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as Error:
            raise PolicyValidationError(f"cannot read network service policy: {Error}") from Error
        if Original != CanonicalJson(Policy):
            raise PolicyValidationError(
                "canonical network service policy must use deterministic sorted JSON"
            )
    return Policy


def ValidateCapability(Capability: Any, Context: str) -> None:
    CapabilityObject = RequireObject(Capability, Context)
    RequireExactKeys(
        CapabilityObject,
        {
            "activation_gates",
            "capability_id",
            "credential_modes",
            "data_categories",
            "destination_classes",
            "initiator_class",
            "provider_boundary",
            "service_id",
            "source_mapping",
            "trigger_id",
        },
        Context,
    )
    RequireIdentifier(CapabilityObject["capability_id"], f"{Context}.capability_id")
    if CapabilityObject["service_id"] is not None:
        RequireIdentifier(CapabilityObject["service_id"], f"{Context}.service_id")
    RequireEnum(
        CapabilityObject["initiator_class"], InitiatorClasses, f"{Context}.initiator_class"
    )
    RequireIdentifier(CapabilityObject["trigger_id"], f"{Context}.trigger_id")
    ValidateSortedStringList(
        CapabilityObject["destination_classes"],
        f"{Context}.destination_classes",
        DestinationClasses,
        AllowEmpty=False,
    )
    ValidateSortedStringList(
        CapabilityObject["data_categories"],
        f"{Context}.data_categories",
        DataCategories,
        AllowEmpty=False,
    )
    ValidateSortedStringList(
        CapabilityObject["credential_modes"],
        f"{Context}.credential_modes",
        CredentialModes,
        AllowEmpty=False,
    )
    ValidateActivationGates(
        CapabilityObject["activation_gates"], f"{Context}.activation_gates"
    )
    ProviderBoundary = CapabilityObject["provider_boundary"]
    if ProviderBoundary is not None:
        RequireString(ProviderBoundary, f"{Context}.provider_boundary")
    ValidateSourceMapping(CapabilityObject["source_mapping"], f"{Context}.source_mapping")


def ValidateInventoryDocument(Data: Any, Context: str = "inventory") -> Dict[str, Any]:
    Inventory = RequireObject(Data, Context)
    RequireExactKeys(
        Inventory,
        {"capabilities", "chromium_sha", "chromium_version", "schema_version"},
        Context,
    )
    if Inventory["schema_version"] != SchemaVersion:
        raise PolicyValidationError(
            f"unsupported {Context} schema_version: {Inventory['schema_version']}"
        )
    RequireString(Inventory["chromium_version"], f"{Context}.chromium_version")
    ChromiumSha = RequireString(Inventory["chromium_sha"], f"{Context}.chromium_sha")
    if ShaPattern.fullmatch(ChromiumSha) is None:
        raise PolicyValidationError(f"{Context}.chromium_sha must be 40 lowercase hex")
    Capabilities = Inventory["capabilities"]
    if not isinstance(Capabilities, list):
        raise PolicyValidationError(f"{Context}.capabilities must be an array")
    CapabilityIds: List[str] = []
    for Index, Capability in enumerate(Capabilities):
        ValidateCapability(Capability, f"{Context}.capabilities[{Index}]")
        CapabilityIds.append(Capability["capability_id"])
    if CapabilityIds != sorted(CapabilityIds) or len(CapabilityIds) != len(
        set(CapabilityIds)
    ):
        raise PolicyValidationError(
            f"{Context}.capabilities must be sorted by unique capability_id"
        )
    return Inventory


def ValidateConnection(Connection: Any, Context: str) -> None:
    ConnectionObject = RequireObject(Connection, Context)
    RequireExactKeys(
        ConnectionObject,
        {
            "connection_id",
            "credential_modes",
            "data_categories",
            "destination",
            "destination_class",
            "initiator_class",
            "provider_boundary",
            "service_id",
            "trigger_id",
        },
        Context,
    )
    RequireIdentifier(ConnectionObject["connection_id"], f"{Context}.connection_id")
    if ConnectionObject["service_id"] is not None:
        RequireIdentifier(ConnectionObject["service_id"], f"{Context}.service_id")
    RequireEnum(
        ConnectionObject["initiator_class"], InitiatorClasses, f"{Context}.initiator_class"
    )
    RequireEnum(
        ConnectionObject["destination_class"],
        DestinationClasses,
        f"{Context}.destination_class",
    )
    RequireString(ConnectionObject["destination"], f"{Context}.destination")
    RequireIdentifier(ConnectionObject["trigger_id"], f"{Context}.trigger_id")
    ValidateSortedStringList(
        ConnectionObject["data_categories"],
        f"{Context}.data_categories",
        DataCategories,
        AllowEmpty=False,
    )
    ValidateSortedStringList(
        ConnectionObject["credential_modes"],
        f"{Context}.credential_modes",
        CredentialModes,
        AllowEmpty=False,
    )
    ProviderBoundary = ConnectionObject["provider_boundary"]
    if ProviderBoundary is not None:
        RequireString(ProviderBoundary, f"{Context}.provider_boundary")


def ValidateObservationDocument(Data: Any, Context: str = "observation") -> Dict[str, Any]:
    Observation = RequireObject(Data, Context)
    RequireExactKeys(
        Observation,
        {
            "connections",
            "satisfied_conditions",
            "scenario_id",
            "schema_version",
            "user_actions",
        },
        Context,
    )
    if Observation["schema_version"] != SchemaVersion:
        raise PolicyValidationError(
            f"unsupported {Context} schema_version: {Observation['schema_version']}"
        )
    RequireIdentifier(Observation["scenario_id"], f"{Context}.scenario_id")
    ValidateSortedStringList(
        Observation["satisfied_conditions"], f"{Context}.satisfied_conditions"
    )
    ValidateSortedStringList(Observation["user_actions"], f"{Context}.user_actions")
    Connections = Observation["connections"]
    if not isinstance(Connections, list):
        raise PolicyValidationError(f"{Context}.connections must be an array")
    ConnectionIds: List[str] = []
    for Index, Connection in enumerate(Connections):
        ValidateConnection(Connection, f"{Context}.connections[{Index}]")
        ConnectionIds.append(Connection["connection_id"])
    if ConnectionIds != sorted(ConnectionIds) or len(ConnectionIds) != len(
        set(ConnectionIds)
    ):
        raise PolicyValidationError(
            f"{Context}.connections must be sorted by unique connection_id"
        )
    return Observation


def ServiceIndex(Policy: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {Service["service_id"]: Service for Service in Policy["services"]}


def DestinationHost(Destination: str) -> Optional[str]:
    Candidate = Destination if "://" in Destination else f"//{Destination}"
    try:
        Hostname = urlsplit(Candidate).hostname
    except ValueError:
        return None
    return Hostname.lower().rstrip(".") if Hostname else None


def DestinationMatchesConstraints(
    Destination: str, Constraints: Sequence[Mapping[str, str]]
) -> bool:
    if not Constraints:
        return True
    Hostname = DestinationHost(Destination)
    for Constraint in Constraints:
        ConstraintType = Constraint["constraint_type"]
        Value = Constraint["value"]
        if ConstraintType == "URL_PREFIX" and Destination.startswith(Value):
            return True
        if ConstraintType == "POLICY_SELECTED" and Destination == Value:
            return True
        ExpectedHost = Value.lower().rstrip(".")
        if ConstraintType == "HOSTNAME" and Hostname == ExpectedHost:
            return True
        if ConstraintType == "HOSTNAME_SUFFIX" and Hostname is not None:
            if Hostname == ExpectedHost or Hostname.endswith(f".{ExpectedHost}"):
                return True
    return False


def AddIssue(Issues: List[Dict[str, Any]], Code: str, **Details: Any) -> None:
    Issue = {"code": Code}
    Issue.update({Key: Value for Key, Value in Details.items() if Value is not None})
    Issues.append(Issue)


def CompareCapabilityToPolicy(
    Capability: Mapping[str, Any],
    Services: Mapping[str, Mapping[str, Any]],
    Issues: List[Dict[str, Any]],
) -> None:
    Initiator = Capability["initiator_class"]
    ServiceId = Capability["service_id"]
    if Initiator not in NativeInitiatorClasses:
        return
    Service = Services.get(ServiceId) if ServiceId else None
    if Service is None or Service["policy_status"] != "APPROVED":
        AddIssue(
            Issues,
            "UNCLASSIFIED_NATIVE_CAPABILITY",
            capability_id=Capability["capability_id"],
            service_id=ServiceId,
        )
        return
    Checks = {
        "initiator_class": Capability["initiator_class"] == Service["initiator_class"],
        "trigger_id": Capability["trigger_id"] == Service["trigger"]["id"],
        "destination_classes": set(Capability["destination_classes"]).issubset(
            Service["destination_classes"]
        ),
        "data_categories": set(Capability["data_categories"]).issubset(
            Service["data_categories"]
        ),
        "credential_modes": set(Capability["credential_modes"]).issubset(
            Service["credential_modes"]
        ),
        "provider_boundary": Capability["provider_boundary"] is None
        or Capability["provider_boundary"]
        in Service["controls"]["provider_boundaries"],
    }
    for Field in GateFields:
        Checks[f"activation_gates.{Field}"] = set(
            Capability["activation_gates"][Field]
        ).issubset(Service["controls"][Field])
    for Field, Matches in Checks.items():
        if not Matches:
            AddIssue(
                Issues,
                "CAPABILITY_POLICY_MISMATCH",
                capability_id=Capability["capability_id"],
                field=Field,
                service_id=ServiceId,
            )


def SemanticChanges(
    Previous: Mapping[str, Any], Current: Mapping[str, Any]
) -> List[str]:
    return [Field for Field in SemanticCapabilityFields if Previous[Field] != Current[Field]]


def CompareInventories(
    Policy: Mapping[str, Any],
    PreviousInventory: Optional[Mapping[str, Any]],
    CurrentInventory: Mapping[str, Any],
    Issues: List[Dict[str, Any]],
) -> Dict[str, List[Any]]:
    Services = ServiceIndex(Policy)
    PreviousCapabilities = {
        Item["capability_id"]: Item
        for Item in (PreviousInventory or {"capabilities": []})["capabilities"]
    }
    CurrentCapabilities = {
        Item["capability_id"]: Item for Item in CurrentInventory["capabilities"]
    }
    Added = sorted(set(CurrentCapabilities) - set(PreviousCapabilities))
    Removed = sorted(set(PreviousCapabilities) - set(CurrentCapabilities))
    Changed: List[Dict[str, Any]] = []
    SourceRemapped: List[str] = []

    for CapabilityId in sorted(set(CurrentCapabilities) & set(PreviousCapabilities)):
        Previous = PreviousCapabilities[CapabilityId]
        Current = CurrentCapabilities[CapabilityId]
        Fields = SemanticChanges(Previous, Current)
        if Fields:
            Changed.append({"capability_id": CapabilityId, "fields": Fields})
            AddIssue(
                Issues,
                "MATERIAL_CAPABILITY_CHANGE",
                capability_id=CapabilityId,
                fields=Fields,
            )
        elif Previous["source_mapping"] != Current["source_mapping"]:
            SourceRemapped.append(CapabilityId)

    for Capability in CurrentCapabilities.values():
        CompareCapabilityToPolicy(Capability, Services, Issues)

    return {
        "added": Added,
        "changed": Changed,
        "removed": Removed,
        "source_remapped": SourceRemapped,
    }


def CompareConnectionToPolicy(
    Connection: Mapping[str, Any],
    Observation: Mapping[str, Any],
    Services: Mapping[str, Mapping[str, Any]],
    Issues: List[Dict[str, Any]],
) -> None:
    Initiator = Connection["initiator_class"]
    ServiceId = Connection["service_id"]
    if Initiator == "USER_REQUESTED_WEB":
        return
    if Initiator == "SITE_DIRECTED" and ServiceId is None:
        if Connection["destination_class"] != "SITE_CONTROLLED":
            AddIssue(
                Issues,
                "ATTRIBUTION_CLASS_MISMATCH",
                connection_id=Connection["connection_id"],
            )
        return
    if Initiator == "EXTENSION_DIRECTED" and ServiceId is None:
        if Connection["destination_class"] != "EXTENSION_CONTROLLED":
            AddIssue(
                Issues,
                "ATTRIBUTION_CLASS_MISMATCH",
                connection_id=Connection["connection_id"],
            )
        return

    Service = Services.get(ServiceId) if ServiceId else None
    if Service is None or Service["policy_status"] != "APPROVED":
        AddIssue(
            Issues,
            "UNCLASSIFIED_NATIVE_CONNECTION",
            connection_id=Connection["connection_id"],
            service_id=ServiceId,
        )
        return

    State = Service["policy_state"]
    if State == "DENY":
        AddIssue(
            Issues,
            "DENIED_SERVICE_OBSERVED",
            connection_id=Connection["connection_id"],
            service_id=ServiceId,
        )
    elif State == "REPLACED":
        AddIssue(
            Issues,
            "REPLACED_UPSTREAM_PROVIDER_OBSERVED",
            connection_id=Connection["connection_id"],
            service_id=ServiceId,
        )
    elif State == "CONDITIONAL":
        RequiredCondition = Service["activation_condition"]["id"]
        if RequiredCondition not in Observation["satisfied_conditions"]:
            AddIssue(
                Issues,
                "CONDITION_NOT_SATISFIED",
                connection_id=Connection["connection_id"],
                service_id=ServiceId,
            )
    elif State == "USER_INITIATED":
        RequiredAction = Service["user_action"]["id"]
        if RequiredAction not in Observation["user_actions"]:
            AddIssue(
                Issues,
                "USER_ACTION_NOT_OBSERVED",
                connection_id=Connection["connection_id"],
                service_id=ServiceId,
            )

    Checks = {
        "initiator_class": Initiator == Service["initiator_class"],
        "trigger_id": Connection["trigger_id"] == Service["trigger"]["id"],
        "destination_class": Connection["destination_class"]
        in Service["destination_classes"],
        "data_categories": set(Connection["data_categories"]).issubset(
            Service["data_categories"]
        ),
        "credential_modes": set(Connection["credential_modes"]).issubset(
            Service["credential_modes"]
        ),
        "provider_boundary": Connection["provider_boundary"] is None
        or Connection["provider_boundary"]
        in Service["controls"]["provider_boundaries"],
        "destination_constraint": DestinationMatchesConstraints(
            Connection["destination"], Service["expected_destination_constraints"]
        ),
    }
    for Field, Matches in Checks.items():
        if not Matches:
            AddIssue(
                Issues,
                "RUNTIME_POLICY_MISMATCH",
                connection_id=Connection["connection_id"],
                field=Field,
                service_id=ServiceId,
            )


def CompareObservations(
    Policy: Mapping[str, Any],
    Observations: Sequence[Mapping[str, Any]],
    Issues: List[Dict[str, Any]],
) -> None:
    Services = ServiceIndex(Policy)
    for Observation in Observations:
        ObservedServices = {
            Connection["service_id"]
            for Connection in Observation["connections"]
            if Connection["service_id"] is not None
        }
        for Connection in Observation["connections"]:
            CompareConnectionToPolicy(Connection, Observation, Services, Issues)

        ScenarioId = Observation["scenario_id"]
        for Service in Policy["services"]:
            Expectations = {
                Scenario["scenario_id"]: Scenario["expectation"]
                for Scenario in Service["qualification_scenarios"]
            }
            Expectation = Expectations.get(ScenarioId)
            IsObserved = Service["service_id"] in ObservedServices
            if Expectation == "MUST_OBSERVE" and not IsObserved:
                AddIssue(
                    Issues,
                    "EXPECTED_SERVICE_NOT_OBSERVED",
                    scenario_id=ScenarioId,
                    service_id=Service["service_id"],
                )
            elif Expectation == "MUST_NOT_OBSERVE" and IsObserved:
                AddIssue(
                    Issues,
                    "PROHIBITED_SERVICE_OBSERVED",
                    scenario_id=ScenarioId,
                    service_id=Service["service_id"],
                )


def ComparePolicyEvidence(
    PolicyData: Any,
    CurrentInventoryData: Any,
    PreviousInventoryData: Optional[Any] = None,
    ObservationData: Sequence[Any] = (),
) -> Dict[str, Any]:
    Policy = ValidatePolicyDocument(PolicyData)
    CurrentInventory = ValidateInventoryDocument(CurrentInventoryData, "current_inventory")
    PreviousInventory = None
    if PreviousInventoryData is not None:
        PreviousInventory = ValidateInventoryDocument(
            PreviousInventoryData, "previous_inventory"
        )
    Observations = [
        ValidateObservationDocument(Data, f"observations[{Index}]")
        for Index, Data in enumerate(ObservationData)
    ]
    Issues: List[Dict[str, Any]] = []
    InventoryDelta = CompareInventories(
        Policy, PreviousInventory, CurrentInventory, Issues
    )
    CompareObservations(Policy, Observations, Issues)
    Issues.sort(
        key=lambda Issue: (
            Issue["code"],
            Issue.get("service_id", ""),
            Issue.get("capability_id", ""),
            Issue.get("connection_id", ""),
            Issue.get("field", ""),
        )
    )
    return {
        "inventory_delta": InventoryDelta,
        "issues": Issues,
        "policy_digest": PolicyDigest(Policy),
        "result": "FAIL" if Issues else "PASS",
        "schema_version": SchemaVersion,
        "synthetic_comparison_only": True,
    }


def ParseArguments(Arguments: Sequence[str]) -> argparse.Namespace:
    Root = Path(__file__).resolve().parents[1]
    Parser = argparse.ArgumentParser(description=__doc__)
    Subparsers = Parser.add_subparsers(dest="command", required=True)

    ValidateParser = Subparsers.add_parser("validate", help="validate canonical policy")
    ValidateParser.add_argument(
        "--policy",
        type=Path,
        default=Root / "policy" / "network-service-policy.json",
    )

    CompareParser = Subparsers.add_parser(
        "compare", help="compare synthetic inventory/observation inputs"
    )
    CompareParser.add_argument("--policy", type=Path, required=True)
    CompareParser.add_argument("--current-inventory", type=Path, required=True)
    CompareParser.add_argument("--previous-inventory", type=Path)
    CompareParser.add_argument("--observation", type=Path, action="append", default=[])
    CompareParser.add_argument("--json", action="store_true")
    return Parser.parse_args(Arguments)


def Main(Arguments: Iterable[str] = ()) -> int:
    Options = ParseArguments(list(Arguments))
    try:
        if Options.command == "validate":
            Policy = LoadPolicy(Options.policy, RequireCanonical=True)
            print(
                f"Validated network service policy: {len(Policy['services'])} services; "
                f"digest {PolicyDigest(Policy)}"
            )
            print("STATIC policy validation passed. No runtime behavior is implied.")
            return 0

        Policy = LoadPolicy(Options.policy)
        CurrentInventory = LoadJson(Options.current_inventory, "current inventory")
        PreviousInventory = (
            LoadJson(Options.previous_inventory, "previous inventory")
            if Options.previous_inventory
            else None
        )
        Observations = [LoadJson(PathValue, "runtime observation") for PathValue in Options.observation]
        Result = ComparePolicyEvidence(
            Policy, CurrentInventory, PreviousInventory, Observations
        )
        if Options.json:
            print(CanonicalJson(Result), end="")
        else:
            print(f"Synthetic network comparison result: {Result['result']}")
            for Issue in Result["issues"]:
                print(f"  - {Issue['code']}: {json.dumps(Issue, sort_keys=True)}")
            print("No Chromium runtime behavior is implied.")
        return 0 if Result["result"] == "PASS" else 1
    except PolicyValidationError as Error:
        print(f"Network policy validation failed: {Error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(Main(sys.argv[1:]))
