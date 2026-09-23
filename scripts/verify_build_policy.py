#!/usr/bin/env python3
"""Collect exact-SHA GN configuration evidence; never promote qualification state."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ScriptDirectory = Path(__file__).resolve().parent
if str(ScriptDirectory) not in sys.path:
    sys.path.insert(0, str(ScriptDirectory))

from build_policy import (  # noqa: E402
    BuildPolicyValidationError, CanonicalJson, JsonValuesEqual, LoadManifest,
    ManifestDigest,
)
from chromium_update import ValidateQualificationRequest, UpdateError  # noqa: E402


class VerificationError(ValueError):
    """A controlled evidence-collection failure, without raw command output."""


CredentialPattern = re.compile(
    r"(?:GOOGLE.*(?:KEY|CLIENT|SECRET|TOKEN|CREDENTIAL).*|GOOGLE_DEFAULT_.*)", re.I
)
InjectionNames = {"CL", "_CL_", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "GN_ARGS"}


def Digest(Data):
    return hashlib.sha256(Data).hexdigest()


def EnvironmentFindings(Environment):
    # Never retain values or hashes of secrets. Case folding matches Windows.
    return sorted({Name.upper() for Name, Value in Environment.items()
                   if Value and (CredentialPattern.fullmatch(Name)
                                 or Name.upper() in InjectionNames)})


def SavedEnvironmentFindings(Registry=None):
    """Inspect saved Windows launch environments without retaining values."""
    if Registry is None:
        import winreg as Registry
    Results = {}
    for Scope, Hive, KeyName in (
        ("CURRENT_USER", Registry.HKEY_CURRENT_USER, "Environment"),
        ("MACHINE", Registry.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    ):
        try:
            with Registry.OpenKey(Hive, KeyName) as Key:
                Count = Registry.QueryInfoKey(Key)[1]
                Values = {}
                for Index in range(Count):
                    Name, Value, _ = Registry.EnumValue(Key, Index)
                    Values[Name] = Value
                Results[Scope] = EnvironmentFindings(Values)
        except FileNotFoundError as Error:
            if Scope != "CURRENT_USER":
                raise VerificationError("machine environment registry key is missing") from Error
            Results[Scope] = []
        except OSError as Error:
            raise VerificationError("saved Windows environment could not be inspected") from Error
    return Results


def ParseScalar(Text):
    # GN escapes are not JSON escapes. Accept only the bounded literals needed
    # by this manifest and reject interpolation, expressions and complex values.
    if Text == "true":
        return True
    if Text == "false":
        return False
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", Text):
        return int(Text)
    if re.fullmatch(r'"[^"\\$\r\n]*"', Text):
        return Text[1:-1]
    raise VerificationError("unsupported GN scalar encoding")


def Matches(Setting, Value):
    Expected = Setting["expected"]
    Mode = Setting["requirement"]
    if Mode in {"EXACT_VALUE", "REQUIRED_EMPTY_STRING"}:
        return JsonValuesEqual(Value, Expected)
    if Mode == "ALLOWED_SET":
        return any(JsonValuesEqual(Value, Item) for Item in Expected)
    if Mode == "FORBIDDEN_VALUE":
        return not JsonValuesEqual(Value, Expected)
    raise VerificationError("unsupported policy requirement")


def CompareArguments(Manifest, Arguments):
    if not isinstance(Arguments, list):
        raise VerificationError("GN argument inventory must be an array")
    Index = {}
    for Entry in Arguments:
        if not isinstance(Entry, dict) or not isinstance(Entry.get("name"), str):
            raise VerificationError("malformed GN argument entry")
        Name = Entry["name"]
        if Name in Index:
            raise VerificationError("duplicate GN argument")
        Index[Name] = Entry
    Results = []
    for Setting in Manifest["settings"]:
        Name = Setting["name"]
        Result = {"name": Name, "result": "MISSING"}
        Entry = Index.get(Name)
        if Entry is not None:
            Default = Entry.get("default")
            Current = Entry.get("current", Default)
            if (not isinstance(Default, dict) or not isinstance(Current, dict)
                    or not isinstance(Current.get("value"), str)
                    or not isinstance(Default.get("file"), str)
                    or not Default["file"].startswith("//")
                    or type(Default.get("line")) is not int
                    or Default["line"] < 1):
                raise VerificationError("GN argument lacks declaration provenance")
            Value = ParseScalar(Current["value"])
            Result.update({
                "result": "MATCH" if Matches(Setting, Value) else "MISMATCH",
                "declaration": {"file": Default["file"], "line": Default["line"]},
                # A matching credential is empty. Do not serialize unexpected
                # values, including credentials accidentally assigned elsewhere.
                "effective": Value if Matches(Setting, Value) else "REDACTED",
            })
        Results.append(Result)
    return Results


def BuildArguments(Manifest):
    Values = {"target_os": "win", "target_cpu": "x64", "is_debug": False,
              "is_component_build": True, "symbol_level": 0}
    for Setting in Manifest["settings"]:
        if Setting["requirement"] not in {"EXACT_VALUE", "REQUIRED_EMPTY_STRING"}:
            raise VerificationError("policy requires a reviewed concrete GN input")
        Values[Setting["name"]] = Setting["expected"]
    return "".join(f"{Name} = {json.dumps(Value)}\n"
                   for Name, Value in sorted(Values.items()))


def Run(Command, Source, Commands, Environment=None):
    try:
        Result = subprocess.run(
            [str(Item) for Item in Command], cwd=Source, env=Environment,
            capture_output=True, timeout=900, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as Error:
        Commands.append({"command": [str(Item) for Item in Command],
                         "result": type(Error).__name__})
        raise VerificationError("command could not complete; see command metadata") from Error
    Commands.append({"command": [str(Item) for Item in Command],
                     "exit_code": Result.returncode})
    if Result.returncode:
        # GN errors can echo args.gn or credentials. Raw output is intentionally
        # not copied to logs or the console, even on failure.
        raise VerificationError("command failed; see command metadata (raw output withheld)")
    return Result.stdout.decode("utf-8", errors="strict")


def CheckSource(Source, Sha, Commands):
    Top = Path(Run(["git", "rev-parse", "--show-toplevel"], Source, Commands).strip())
    if Top.resolve() != Source:
        raise VerificationError("source must be the Chromium Git root")
    Head = Run(["git", "rev-parse", "HEAD"], Source, Commands).strip()
    if Head != Sha:
        raise VerificationError("checkout HEAD differs from requested Chromium SHA")
    if Run(["git", "status", "--porcelain", "--untracked-files=normal"], Source, Commands).strip():
        raise VerificationError("Chromium checkout must be clean")
    for Name in (".gn", "DEPS", "chrome/VERSION", "google_apis/BUILD.gn"):
        if not (Source / Name).is_file():
            raise VerificationError("required Chromium source file is missing")
    return Head


def Collect(Options, Report):
    Manifest = LoadManifest(Options.manifest, Options.network_policy, RequireCanonical=True)
    Request = json.loads(Options.request.read_text(encoding="utf-8"))
    ValidateQualificationRequest(Request)
    Report["candidate"] = Request["candidate"]
    Report["manifest_sha256"] = ManifestDigest(Manifest)
    Source = Options.source.resolve()
    Report["source"] = str(Source)
    Commands = Report["commands"]
    PatchEvidencePath = getattr(Options, "patch_evidence", None)
    PatchEvidence = None
    if PatchEvidencePath:
        from real_patch_qualify import CheckIntegration as ValidateIntegration, Engine
        def CheckIntegration(PathValue, Evidence):
            try:
                ValidateIntegration(PathValue, Evidence)
            except (ValueError, Engine.StageFailure) as Error:
                raise VerificationError("Real patch integration validation failed") from Error
        PatchEvidence = json.loads(PatchEvidencePath.read_text(encoding="utf-8"))
        if PatchEvidence.get("candidate") != Request["candidate"]:
            raise VerificationError("PATCH-APPLY candidate mismatch")
        CheckIntegration(Source, PatchEvidence)
        Report["patch_evidence_sha256"] = Digest(PatchEvidencePath.read_bytes())
        Report["patch_series"] = PatchEvidence["inputs"]
        Report["evidence_level"] = "PATCH-APPLY"
    else:
        CheckSource(Source, Request["candidate"]["chromium_sha"], Commands)
    Report["source_identity"] = "MATCH"
    # Inspect inherited environment before sanitizing anything. The snapshot
    # covers this invocation, not future browser launches by another process.
    Environment = dict(os.environ)
    Findings = EnvironmentFindings(Environment)
    Report["environment"] = {"scope": "VERIFIER_PROCESS", "nonempty_overrides": Findings}
    if Findings:
        raise VerificationError("credential or build injection environment override detected")
    if sys.platform != "win32":
        raise VerificationError("real collection requires a Windows worker")
    SavedFindings = SavedEnvironmentFindings()
    Report["environment"]["saved_windows_environments"] = SavedFindings
    if any(SavedFindings.values()):
        raise VerificationError("saved Windows environment contains credential or build overrides")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", Options.output_name):
        raise VerificationError("output name must contain only letters, digits, dash or underscore")
    Output = Source / "out" / Options.output_name
    if Output.exists() or Output.is_symlink() or (Source / "out").is_symlink():
        raise VerificationError("GN output must be new and not redirected")
    Gn = Options.gn.resolve()
    if Gn.suffix.lower() != ".exe" or not Gn.is_file():
        raise VerificationError("provide the real gn.exe from the synced Chromium toolchain")
    Report["gn_sha256"] = Digest(Gn.read_bytes())
    Report["gn_version"] = Run([Gn, "--version"], Source, Commands).strip()
    Output.mkdir(parents=True)
    Arguments = BuildArguments(Manifest)
    (Output / "args.gn").write_text(Arguments, encoding="utf-8", newline="\n")
    Report["args_gn"] = Arguments
    Report["output"] = str(Output)
    RelativeOutput = Output.relative_to(Source).as_posix()
    Report["gn_configuration"] = "FAIL"
    Run([Gn, "gen", RelativeOutput, "--fail-on-unused-args"], Source, Commands, Environment)
    Inventory = json.loads(Run([Gn, "args", RelativeOutput, "--list", "--json"],
                               Source, Commands, Environment))
    Results = CompareArguments(Manifest, Inventory)
    Report["settings"] = Results
    Report["gn_configuration"] = "MATCH" if all(
        Item["result"] == "MATCH" for Item in Results) else "FAIL"
    if PatchEvidence:
        CheckIntegration(Source, PatchEvidence)
    else:
        CheckSource(Source, Request["candidate"]["chromium_sha"], Commands)
    if Report["gn_configuration"] != "MATCH":
        raise VerificationError("required GN settings are missing or mismatched")
    # GN's argument inventory does not prove downstream uses or generated
    # defines. Require source/target review instead of treating it as proof.
    Report["status"] = "INCOMPLETE"
    Report["blockers"] = [
        "Exact-SHA semantic and generated-target review is required.",
        "Runtime credential resolution and future launch environments are unverified.",
    ]


def Main(Arguments=None):
    Root = ScriptDirectory.parent
    Parser = argparse.ArgumentParser(description=__doc__)
    Parser.add_argument("--request", type=Path, required=True)
    Parser.add_argument("--source", type=Path, required=True)
    Parser.add_argument("--gn", type=Path, required=True)
    Parser.add_argument("--evidence", type=Path, required=True)
    Parser.add_argument("--patch-evidence", type=Path,
                        help="Bind to a verified real PATCH-APPLY integration instead of a clean root")
    Parser.add_argument("--output-name", default="SecuriumPolicy")
    Parser.add_argument("--manifest", type=Path, default=Root / "policy/build-policy.json")
    Parser.add_argument("--network-policy", type=Path,
                        default=Root / "policy/network-service-policy.json")
    Options = Parser.parse_args(Arguments)
    # Exclusive creation prevents destroying an earlier run or canonical state.
    try:
        Options.evidence.parent.mkdir(parents=True, exist_ok=True)
        Handle = Options.evidence.open("x", encoding="utf-8", newline="\n")
    except OSError:
        print("[Securium:BuildPolicy] Cannot create new evidence file", file=sys.stderr)
        return 1
    Report = {"schema_version": 1, "status": "FAIL", "evidence_level": "STATIC",
              "qualification_promoted": False, "runtime_verified": False,
              "gn_configuration": "NOT_RUN", "commands": [], "blockers": []}
    try:
        Collect(Options, Report)
    except (VerificationError, BuildPolicyValidationError, UpdateError,
            OSError, ValueError) as Error:
        # Only controlled messages are safe to expose. Decoder and OS exceptions
        # can contain arbitrary source/input values.
        Report["blockers"] = [str(Error) if isinstance(Error, VerificationError)
                              else type(Error).__name__]
    with Handle:
        Handle.write(CanonicalJson(Report))
    print(f"[Securium:BuildPolicy] {Report['status']}; GN {Report['gn_configuration']}; "
          "no qualification or runtime claim")
    return 2 if Report["status"] == "INCOMPLETE" else 1


if __name__ == "__main__":
    sys.exit(Main())
