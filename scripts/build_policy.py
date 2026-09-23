#!/usr/bin/env python3
"""Validate Securium's static intended build-policy manifest."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set


ScriptDirectory = Path(__file__).resolve().parent
if str(ScriptDirectory) not in sys.path:
    sys.path.insert(0, str(ScriptDirectory))

from network_policy import LoadPolicy, PolicyValidationError, ServiceIndex  # noqa: E402


SchemaVersion = 1
ManifestId = "securium-build-policy"
IdentifierPattern = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
Classifications = {
    "EXPLICIT_DEFENSE",
    "PRODUCT_CHOICE",
    "REQUIRED_INVARIANT",
}
Requirements = {
    "ALLOWED_SET",
    "EXACT_VALUE",
    "FORBIDDEN_VALUE",
    "REQUIRED_EMPTY_STRING",
}
Stabilities = {"INVARIANT", "PREFERRED"}
VerificationStatuses = {"PENDING_REAL_SOURCE_VERIFICATION"}
CredentialSettingNames = {
    "google_api_key",
    "google_default_client_id",
    "google_default_client_secret",
    "use_official_google_api_keys",
}
ForbiddenSpeculativeNames = {"enable_glic"}
CredentialNamePattern = re.compile(
    r"(?:api_key|client_id|client_secret|credential|oauth|password|secret|token)"
)
SecretValuePattern = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|AIza[0-9A-Za-z_-]{20,}|"
    r"github_pat_[0-9A-Za-z_]+|gh[pousr]_[0-9A-Za-z]+|AKIA[0-9A-Z]{16})"
)


RequiredBaselineSettings: Dict[str, Dict[str, Any]] = {
    "enable_compose": {
        "classification": "PRODUCT_CHOICE",
        "expected": False,
        "related_service_ids": [],
        "requirement": "EXACT_VALUE",
        "stability": "PREFERRED",
    },
    "enable_rlz": {
        "classification": "EXPLICIT_DEFENSE",
        "expected": False,
        "related_service_ids": [],
        "requirement": "EXACT_VALUE",
        "stability": "INVARIANT",
    },
    "enable_update_notifications": {
        "classification": "EXPLICIT_DEFENSE",
        "expected": False,
        "related_service_ids": ["chrome_browser_updater"],
        "requirement": "EXACT_VALUE",
        "stability": "INVARIANT",
    },
    "enable_updater": {
        "classification": "EXPLICIT_DEFENSE",
        "expected": False,
        "related_service_ids": ["chrome_browser_updater"],
        "requirement": "EXACT_VALUE",
        "stability": "INVARIANT",
    },
    "google_api_key": {
        "classification": "REQUIRED_INVARIANT",
        "expected": "",
        "related_service_ids": [],
        "requirement": "REQUIRED_EMPTY_STRING",
        "stability": "INVARIANT",
    },
    "google_default_client_id": {
        "classification": "REQUIRED_INVARIANT",
        "expected": "",
        "related_service_ids": [],
        "requirement": "REQUIRED_EMPTY_STRING",
        "stability": "INVARIANT",
    },
    "google_default_client_secret": {
        "classification": "REQUIRED_INVARIANT",
        "expected": "",
        "related_service_ids": [],
        "requirement": "REQUIRED_EMPTY_STRING",
        "stability": "INVARIANT",
    },
    "is_chrome_branded": {
        "classification": "REQUIRED_INVARIANT",
        "expected": False,
        "related_service_ids": [],
        "requirement": "EXACT_VALUE",
        "stability": "INVARIANT",
    },
    "safe_browsing_mode": {
        "classification": "REQUIRED_INVARIANT",
        "expected": 1,
        "related_service_ids": ["safe_browsing_standard"],
        "requirement": "EXACT_VALUE",
        "stability": "INVARIANT",
    },
    "use_official_google_api_keys": {
        "classification": "REQUIRED_INVARIANT",
        "expected": False,
        "related_service_ids": [],
        "requirement": "EXACT_VALUE",
        "stability": "INVARIANT",
    },
}


class BuildPolicyValidationError(ValueError):
    """Raised when a build-policy manifest violates the static contract."""


def CanonicalJson(Data: Any) -> str:
    return json.dumps(Data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def ManifestDigest(Manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(CanonicalJson(Manifest).encode("utf-8")).hexdigest()


def RequireObject(Value: Any, Context: str) -> Dict[str, Any]:
    if not isinstance(Value, dict):
        raise BuildPolicyValidationError(f"{Context} must be an object")
    return Value


def RequireExactKeys(
    Value: Mapping[str, Any], Required: Set[str], Context: str
) -> None:
    Actual = set(Value)
    Missing = sorted(Required - Actual)
    Unknown = sorted(Actual - Required)
    if Missing:
        raise BuildPolicyValidationError(
            f"{Context} missing field(s): {', '.join(Missing)}"
        )
    if Unknown:
        raise BuildPolicyValidationError(
            f"{Context} has unknown field(s): {', '.join(Unknown)}"
        )


def RequireString(Value: Any, Context: str) -> str:
    if not isinstance(Value, str) or not Value.strip():
        raise BuildPolicyValidationError(f"{Context} must be a non-empty string")
    return Value


def RequireIdentifier(Value: Any, Context: str) -> str:
    Text = RequireString(Value, Context)
    if IdentifierPattern.fullmatch(Text) is None:
        raise BuildPolicyValidationError(
            f"{Context} must be a lower_snake_case identifier"
        )
    return Text


def RequireEnum(Value: Any, Allowed: Set[str], Context: str) -> str:
    Text = RequireString(Value, Context)
    if Text not in Allowed:
        raise BuildPolicyValidationError(f"{Context} has unsupported value: {Text}")
    return Text


def ValidateSortedStringList(
    Value: Any, Context: str, AllowEmpty: bool = True
) -> List[str]:
    if not isinstance(Value, list) or any(not isinstance(Item, str) for Item in Value):
        raise BuildPolicyValidationError(f"{Context} must be an array of strings")
    if not AllowEmpty and not Value:
        raise BuildPolicyValidationError(f"{Context} must not be empty")
    if Value != sorted(Value) or len(Value) != len(set(Value)):
        raise BuildPolicyValidationError(f"{Context} must be sorted and unique")
    return Value


def IsScalar(Value: Any) -> bool:
    return isinstance(Value, (bool, int, str)) and not isinstance(Value, float)


def JsonValuesEqual(Left: Any, Right: Any) -> bool:
    return json.dumps(Left, sort_keys=True, separators=(",", ":")) == json.dumps(
        Right, sort_keys=True, separators=(",", ":")
    )


def ValidateExpectedValue(Value: Any, Requirement: str, Context: str) -> None:
    if Requirement == "REQUIRED_EMPTY_STRING":
        if Value != "":
            raise BuildPolicyValidationError(
                f"{Context} REQUIRED_EMPTY_STRING must expect an empty string"
            )
        return
    if Requirement == "ALLOWED_SET":
        if not isinstance(Value, list) or not Value:
            raise BuildPolicyValidationError(
                f"{Context} ALLOWED_SET must expect a non-empty array"
            )
        if any(not IsScalar(Item) for Item in Value):
            raise BuildPolicyValidationError(
                f"{Context} ALLOWED_SET values must be strings, integers, or booleans"
            )
        ValueTypes = {type(Item) for Item in Value}
        if len(ValueTypes) != 1:
            raise BuildPolicyValidationError(
                f"{Context} ALLOWED_SET values must have one JSON scalar type"
            )
        if Value != sorted(Value):
            raise BuildPolicyValidationError(
                f"{Context} ALLOWED_SET values must be sorted"
            )
        if len({json.dumps(Item, sort_keys=True) for Item in Value}) != len(Value):
            raise BuildPolicyValidationError(
                f"{Context} ALLOWED_SET values must be unique"
            )
        return
    if not IsScalar(Value):
        raise BuildPolicyValidationError(
            f"{Context} {Requirement} must expect a string, integer, or boolean"
        )


def ContainsSecretLookingValue(Value: Any) -> bool:
    Values = Value if isinstance(Value, list) else [Value]
    return any(
        isinstance(Item, str) and bool(SecretValuePattern.search(Item))
        for Item in Values
    )


def ValidateSetting(
    Setting: Any,
    Context: str,
    ApprovedServiceIds: Optional[Set[str]],
) -> None:
    SettingObject = RequireObject(Setting, Context)
    RequireExactKeys(
        SettingObject,
        {
            "classification",
            "expected",
            "name",
            "rationale",
            "related_service_ids",
            "requirement",
            "requires_real_source_verification",
            "stability",
            "verification_status",
        },
        Context,
    )
    Name = RequireIdentifier(SettingObject["name"], f"{Context}.name")
    if Name in ForbiddenSpeculativeNames:
        raise BuildPolicyValidationError(
            f"{Context}.name is a speculative unsupported setting: {Name}"
        )
    Classification = RequireEnum(
        SettingObject["classification"],
        Classifications,
        f"{Context}.classification",
    )
    Requirement = RequireEnum(
        SettingObject["requirement"], Requirements, f"{Context}.requirement"
    )
    Stability = RequireEnum(
        SettingObject["stability"], Stabilities, f"{Context}.stability"
    )
    RequireEnum(
        SettingObject["verification_status"],
        VerificationStatuses,
        f"{Context}.verification_status",
    )
    if SettingObject["requires_real_source_verification"] is not True:
        raise BuildPolicyValidationError(
            f"{Context}.requires_real_source_verification must be true"
        )
    if Classification == "PRODUCT_CHOICE" and Stability != "PREFERRED":
        raise BuildPolicyValidationError(
            f"{Context} PRODUCT_CHOICE must have PREFERRED stability"
        )
    if Classification != "PRODUCT_CHOICE" and Stability != "INVARIANT":
        raise BuildPolicyValidationError(
            f"{Context} required or defensive policy must have INVARIANT stability"
        )
    Expected = SettingObject["expected"]
    if Name == "use_official_google_api_keys" and Expected is not False:
        raise BuildPolicyValidationError(
            "official Google API keys must remain disabled"
        )
    if Name in CredentialSettingNames - {"use_official_google_api_keys"}:
        if Expected != "":
            raise BuildPolicyValidationError(
                f"global credential setting {Name} must remain empty"
            )
    ValidateExpectedValue(SettingObject["expected"], Requirement, f"{Context}.expected")
    RequireString(SettingObject["rationale"], f"{Context}.rationale")
    ServiceIds = ValidateSortedStringList(
        SettingObject["related_service_ids"], f"{Context}.related_service_ids"
    )
    for ServiceId in ServiceIds:
        RequireIdentifier(ServiceId, f"{Context}.related_service_ids")
        if ApprovedServiceIds is not None and ServiceId not in ApprovedServiceIds:
            raise BuildPolicyValidationError(
                f"{Context} references unknown or unapproved service_id: {ServiceId}"
            )
    if CredentialNamePattern.search(Name) and Expected not in (False, ""):
        raise BuildPolicyValidationError(
            f"{Context}.expected contains a non-empty credential-like value"
        )
    if ContainsSecretLookingValue(Expected):
        raise BuildPolicyValidationError(
            f"{Context}.expected contains a secret-looking value"
        )


def ValidateCredentialPolicy(Value: Any) -> None:
    Context = "manifest.credential_policy"
    Policy = RequireObject(Value, Context)
    Expected = {
        "effective_environment_detection_required": True,
        "global_browser_credentials": "FORBIDDEN",
        "plaintext_repository_secrets": "FORBIDDEN",
        "service_specific_credentials": "EXPLICIT_RETAINED_SERVICES_ONLY",
        "service_specific_documentation_required": True,
        "service_specific_global_reuse_forbidden": True,
        "service_specific_scoping_required": True,
    }
    RequireExactKeys(Policy, set(Expected), Context)
    for Field, ExpectedValue in Expected.items():
        if not JsonValuesEqual(Policy[Field], ExpectedValue):
            raise BuildPolicyValidationError(
                f"{Context}.{Field} must be {json.dumps(ExpectedValue)}"
            )


def ValidateScope(Value: Any) -> None:
    Context = "manifest.scope"
    Scope = RequireObject(Value, Context)
    RequireExactKeys(Scope, {"build_system", "platforms", "product"}, Context)
    if Scope["build_system"] != "GN":
        raise BuildPolicyValidationError(f"{Context}.build_system must be GN")
    if Scope["product"] != "SECURIUM_UNBRANDED_CHROMIUM":
        raise BuildPolicyValidationError(
            f"{Context}.product must be SECURIUM_UNBRANDED_CHROMIUM"
        )
    Platforms = ValidateSortedStringList(
        Scope["platforms"], f"{Context}.platforms", AllowEmpty=False
    )
    if Platforms != ["WINDOWS"]:
        raise BuildPolicyValidationError(
            f"{Context}.platforms must currently be [\"WINDOWS\"]"
        )


def ValidateVerificationContract(Value: Any) -> None:
    Context = "manifest.verification_contract"
    Contract = RequireObject(Value, Context)
    Expected = {
        "compare_effective_gn_values": True,
        "detect_environment_credential_overrides": True,
        "mismatch_result": "FAIL",
        "real_chromium_source_required": True,
        "runtime_behavior_out_of_scope": True,
    }
    RequireExactKeys(Contract, set(Expected), Context)
    for Field, ExpectedValue in Expected.items():
        if not JsonValuesEqual(Contract[Field], ExpectedValue):
            raise BuildPolicyValidationError(
                f"{Context}.{Field} must be {json.dumps(ExpectedValue)}"
            )


def ValidateRequiredBaseline(SettingsByName: Mapping[str, Mapping[str, Any]]) -> None:
    Missing = sorted(set(RequiredBaselineSettings) - set(SettingsByName))
    if Missing:
        raise BuildPolicyValidationError(
            "manifest.settings missing required baseline setting(s): "
            + ", ".join(Missing)
        )
    for Name, Required in RequiredBaselineSettings.items():
        Setting = SettingsByName[Name]
        for Field, ExpectedValue in Required.items():
            if not JsonValuesEqual(Setting[Field], ExpectedValue):
                raise BuildPolicyValidationError(
                    f"manifest setting {Name}.{Field} must be "
                    f"{json.dumps(ExpectedValue, sort_keys=True)}"
                )
    for Name in CredentialSettingNames:
        if Name == "use_official_google_api_keys":
            if SettingsByName[Name]["expected"] is not False:
                raise BuildPolicyValidationError(
                    "official Google API keys must remain disabled"
                )
        elif SettingsByName[Name]["expected"] != "":
            raise BuildPolicyValidationError(
                f"global credential setting {Name} must remain empty"
            )


def ValidateManifestDocument(
    Data: Any, ApprovedServiceIds: Optional[Set[str]] = None
) -> Dict[str, Any]:
    Manifest = RequireObject(Data, "manifest")
    RequireExactKeys(
        Manifest,
        {
            "credential_policy",
            "manifest_id",
            "schema_version",
            "scope",
            "settings",
            "verification_contract",
        },
        "manifest",
    )
    if Manifest["schema_version"] != SchemaVersion:
        raise BuildPolicyValidationError(
            f"unsupported build policy schema_version: {Manifest['schema_version']}"
        )
    if Manifest["manifest_id"] != ManifestId:
        raise BuildPolicyValidationError(
            f"unsupported build policy manifest_id: {Manifest['manifest_id']}"
        )
    ValidateCredentialPolicy(Manifest["credential_policy"])
    ValidateScope(Manifest["scope"])
    ValidateVerificationContract(Manifest["verification_contract"])
    Settings = Manifest["settings"]
    if not isinstance(Settings, list) or not Settings:
        raise BuildPolicyValidationError("manifest.settings must be a non-empty array")
    SettingsByName: Dict[str, Mapping[str, Any]] = {}
    SettingNames: List[str] = []
    for Index, Setting in enumerate(Settings):
        Context = f"manifest.settings[{Index}]"
        ValidateSetting(Setting, Context, ApprovedServiceIds)
        Name = Setting["name"]
        if Name in SettingsByName:
            if Setting == SettingsByName[Name]:
                raise BuildPolicyValidationError(
                    f"duplicate build policy setting: {Name}"
                )
            raise BuildPolicyValidationError(
                f"contradictory build policy setting: {Name}"
            )
        SettingsByName[Name] = Setting
        SettingNames.append(Name)
    if SettingNames != sorted(SettingNames):
        raise BuildPolicyValidationError(
            "manifest.settings must be sorted by unique setting name"
        )
    ValidateRequiredBaseline(SettingsByName)
    return Manifest


def LoadJson(PathValue: Path, Context: str) -> Any:
    try:
        return json.loads(PathValue.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as Error:
        raise BuildPolicyValidationError(f"cannot read {Context}: {Error}") from Error


def LoadApprovedServiceIds(NetworkPolicyPath: Path) -> Set[str]:
    try:
        Policy = LoadPolicy(NetworkPolicyPath, RequireCanonical=True)
    except PolicyValidationError as Error:
        raise BuildPolicyValidationError(
            f"cannot validate canonical network service policy: {Error}"
        ) from Error
    return {
        ServiceId
        for ServiceId, Service in ServiceIndex(Policy).items()
        if Service["policy_status"] == "APPROVED"
    }


def LoadManifest(
    PathValue: Path,
    NetworkPolicyPath: Optional[Path] = None,
    RequireCanonical: bool = False,
) -> Dict[str, Any]:
    ApprovedServiceIds = (
        LoadApprovedServiceIds(NetworkPolicyPath)
        if NetworkPolicyPath is not None
        else None
    )
    Data = LoadJson(PathValue, "build policy manifest")
    Manifest = ValidateManifestDocument(Data, ApprovedServiceIds)
    if RequireCanonical:
        try:
            Original = PathValue.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as Error:
            raise BuildPolicyValidationError(
                f"cannot read build policy manifest: {Error}"
            ) from Error
        if Original != CanonicalJson(Manifest):
            raise BuildPolicyValidationError(
                "canonical build policy manifest must use deterministic sorted JSON"
            )
    return Manifest


def ParseArguments(Arguments: Sequence[str]) -> argparse.Namespace:
    Root = Path(__file__).resolve().parents[1]
    Parser = argparse.ArgumentParser(description=__doc__)
    Parser.add_argument(
        "--manifest",
        type=Path,
        default=Root / "policy" / "build-policy.json",
    )
    Parser.add_argument(
        "--network-policy",
        type=Path,
        default=Root / "policy" / "network-service-policy.json",
    )
    return Parser.parse_args(Arguments)


def Main(Arguments: Iterable[str] = ()) -> int:
    Options = ParseArguments(list(Arguments))
    try:
        Manifest = LoadManifest(
            Options.manifest,
            NetworkPolicyPath=Options.network_policy,
            RequireCanonical=True,
        )
    except BuildPolicyValidationError as Error:
        print(f"Build policy validation failed: {Error}", file=sys.stderr)
        return 1
    print(
        f"Validated build policy manifest: {len(Manifest['settings'])} settings; "
        f"digest {ManifestDigest(Manifest)}"
    )
    print(
        "STATIC intended-policy validation passed. Chromium acceptance, effective "
        "values, environment overrides, and runtime behavior are unverified."
    )
    return 0


if __name__ == "__main__":
    sys.exit(Main(sys.argv[1:]))
