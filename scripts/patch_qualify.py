#!/usr/bin/env python3
"""Materialize and apply Securium patches to a disposable synthetic source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


ScriptDirectory = Path(__file__).resolve().parent
if str(ScriptDirectory) not in sys.path:
    sys.path.insert(0, str(ScriptDirectory))

from chromium_update import (  # noqa: E402
    QualificationRequestError,
    ValidateQualificationRequest,
)


EvidenceSchemaVersion = 1
DefaultRepositoryRoot = Path(__file__).resolve().parents[1]
MaxDiagnosticCharacters = 65536
MaxPatchBytes = 10 * 1024 * 1024
PatchNamePattern = re.compile(r"^(?P<Number>[0-9]{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.patch$")
FixtureIdPattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ShaPattern = re.compile(r"^[0-9a-f]{64}$")
WindowsReservedNames = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{Number}" for Number in range(1, 10)),
    *(f"LPT{Number}" for Number in range(1, 10)),
}


class FailureClass(str, Enum):
    InvalidRequest = "INVALID_REQUEST"
    InvalidSource = "INVALID_SOURCE"
    InvalidWorkspace = "INVALID_WORKSPACE"
    InvalidSeries = "INVALID_SERIES"
    UnsafePath = "UNSAFE_PATH"
    MaterializationCollision = "MATERIALIZATION_COLLISION"
    MaterializationFailure = "MATERIALIZATION_FAILURE"
    PatchCheckFailed = "PATCH_CHECK_FAILED"
    PatchApplyFailed = "PATCH_APPLY_FAILED"
    ToolMissing = "TOOL_MISSING"
    EvidenceWriteFailed = "EVIDENCE_WRITE_FAILED"
    InternalError = "INTERNAL_ERROR"


class StageFailure(Exception):
    def __init__(
        self,
        Failure: FailureClass,
        Message: str,
        *,
        FailedPatch: Optional[str] = None,
        Diagnostics: str = "",
        AffectedPaths: Optional[Sequence[str]] = None,
    ) -> None:
        super().__init__(Message)
        self.Failure = Failure
        self.Message = Message
        self.FailedPatch = FailedPatch
        self.Diagnostics = BoundText(Diagnostics)
        self.AffectedPaths = list(AffectedPaths or ())


@dataclass(frozen=True)
class TreeEntry:
    RelativePath: str
    SourcePath: Path


@dataclass(frozen=True)
class MaterializationItem:
    RelativePath: str
    SourcePath: Path
    Sha256: str


@dataclass(frozen=True)
class PatchItem:
    Name: str
    PatchPath: Path
    Sha256: str
    AffectedPaths: Tuple[str, ...]


CommandRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]
JsonWriter = Callable[[Path, Mapping[str, Any]], None]


def BoundText(Value: str) -> str:
    if len(Value) <= MaxDiagnosticCharacters:
        return Value
    Suffix = "\n[diagnostic truncated]"
    return Value[: MaxDiagnosticCharacters - len(Suffix)] + Suffix


def Sha256Bytes(Value: bytes) -> str:
    return hashlib.sha256(Value).hexdigest()


def Sha256File(FilePath: Path) -> str:
    Hasher = hashlib.sha256()
    with FilePath.open("rb") as InputFile:
        while Chunk := InputFile.read(1024 * 1024):
            Hasher.update(Chunk)
    return Hasher.hexdigest()


def CanonicalJsonBytes(Value: Any) -> bytes:
    return json.dumps(Value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def ValidateSafeRelativePath(RelativePath: str, Context: str) -> str:
    if not isinstance(RelativePath, str) or not RelativePath:
        raise StageFailure(FailureClass.UnsafePath, f"{Context} must not be empty")
    if "\x00" in RelativePath or "\\" in RelativePath:
        raise StageFailure(
            FailureClass.UnsafePath,
            f"{Context} must use safe forward-slash relative paths: {RelativePath!r}",
        )
    PosixPath = PurePosixPath(RelativePath)
    WindowsPath = PureWindowsPath(RelativePath)
    if PosixPath.is_absolute() or WindowsPath.is_absolute() or WindowsPath.drive:
        raise StageFailure(
            FailureClass.UnsafePath,
            f"{Context} must not be absolute or drive-qualified: {RelativePath!r}",
        )
    Parts = PosixPath.parts
    if not Parts or any(Part in {"", ".", ".."} for Part in Parts):
        raise StageFailure(
            FailureClass.UnsafePath,
            f"{Context} contains traversal or an ambiguous segment: {RelativePath!r}",
        )
    for Part in Parts:
        if any(ord(Character) < 32 for Character in Part):
            raise StageFailure(
                FailureClass.UnsafePath,
                f"{Context} contains a control character: {RelativePath!r}",
            )
        if ":" in Part or Part.endswith((" ", ".")):
            raise StageFailure(
                FailureClass.UnsafePath,
                f"{Context} is unsafe on Windows: {RelativePath!r}",
            )
        if Part.split(".", 1)[0].upper() in WindowsReservedNames:
            raise StageFailure(
                FailureClass.UnsafePath,
                f"{Context} uses a Windows reserved name: {RelativePath!r}",
            )
        if Part.casefold() == ".git":
            raise StageFailure(
                FailureClass.UnsafePath,
                f"{Context} must not address Git metadata: {RelativePath!r}",
            )
    return PosixPath.as_posix()


def IsReparsePoint(PathValue: Path) -> bool:
    if PathValue.is_symlink():
        return True
    IsJunction = getattr(PathValue, "is_junction", None)
    if IsJunction is not None and IsJunction():
        return True
    try:
        Attributes = getattr(PathValue.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    ReparseFlag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(ReparseFlag and Attributes & ReparseFlag)


def EnumerateSafeTree(Root: Path, Context: str) -> Tuple[List[TreeEntry], List[str]]:
    if not Root.is_dir() or IsReparsePoint(Root):
        raise StageFailure(
            FailureClass.InvalidSource,
            f"{Context} must be a real directory without a symlink or reparse root: {Root}",
        )
    Files: List[TreeEntry] = []
    Directories: List[str] = []

    def Walk(CurrentPath: Path, Prefix: PurePosixPath) -> None:
        try:
            Entries = sorted(os.scandir(CurrentPath), key=lambda Entry: Entry.name)
        except OSError as Error:
            raise StageFailure(
                FailureClass.InvalidSource,
                f"cannot enumerate {Context}: {Error}",
            ) from Error
        for Entry in Entries:
            Relative = (Prefix / Entry.name).as_posix()
            ValidateSafeRelativePath(Relative, Context)
            EntryPath = Path(Entry.path)
            if Entry.is_symlink() or IsReparsePoint(EntryPath):
                raise StageFailure(
                    FailureClass.UnsafePath,
                    f"{Context} contains a symlink or reparse point: {Relative}",
                )
            if Entry.is_dir(follow_symlinks=False):
                Directories.append(Relative)
                Walk(EntryPath, Prefix / Entry.name)
            elif Entry.is_file(follow_symlinks=False):
                Files.append(TreeEntry(Relative, EntryPath))
            else:
                raise StageFailure(
                    FailureClass.UnsafePath,
                    f"{Context} contains an unsupported filesystem entry: {Relative}",
                )

    Walk(Root, PurePosixPath())
    Files.sort(key=lambda Item: Item.RelativePath)
    Directories.sort()
    return Files, Directories


def EnsureContained(Root: Path, RelativePath: str) -> Path:
    RootResolved = Root.resolve()
    Destination = (RootResolved / Path(*PurePosixPath(RelativePath).parts)).resolve(
        strict=False
    )
    try:
        Common = os.path.commonpath((str(RootResolved), str(Destination)))
    except ValueError as Error:
        raise StageFailure(
            FailureClass.UnsafePath,
            f"destination cannot be contained in integration root: {RelativePath}",
        ) from Error
    if os.path.normcase(Common) != os.path.normcase(str(RootResolved)):
        raise StageFailure(
            FailureClass.UnsafePath,
            f"destination escapes integration root: {RelativePath}",
        )
    return Destination


def TreeSha256(Files: Sequence[TreeEntry]) -> str:
    Hasher = hashlib.sha256()
    for Entry in Files:
        Hasher.update(Entry.RelativePath.encode("utf-8"))
        Hasher.update(b"\0")
        Hasher.update(bytes.fromhex(Sha256File(Entry.SourcePath)))
        Hasher.update(b"\0")
    return Hasher.hexdigest()


def LoadQualificationRequest(RequestPath: Path) -> Tuple[Dict[str, Any], str]:
    try:
        RawBytes = RequestPath.read_bytes()
    except OSError as Error:
        raise StageFailure(
            FailureClass.InvalidRequest,
            f"cannot read qualification request: {Error}",
        ) from Error
    try:
        RequestData = json.loads(RawBytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as Error:
        raise StageFailure(
            FailureClass.InvalidRequest,
            f"qualification request is not valid UTF-8 JSON: {Error}",
        ) from Error
    try:
        ValidateQualificationRequest(RequestData)
    except QualificationRequestError as Error:
        raise StageFailure(FailureClass.InvalidRequest, str(Error)) from Error
    return RequestData, Sha256Bytes(CanonicalJsonBytes(RequestData))


def BuildMaterializationPlan(
    RepositoryRoot: Path,
    SourceFiles: Sequence[TreeEntry],
    SourceDirectories: Sequence[str],
) -> List[MaterializationItem]:
    DownstreamRoot = RepositoryRoot / "src" / "chromium"
    if not DownstreamRoot.exists():
        return []
    DownstreamFiles, _ = EnumerateSafeTree(DownstreamRoot, "downstream source")
    SourceFileKeys = {Entry.RelativePath.casefold() for Entry in SourceFiles}
    SourceDirectoryKeys = {PathValue.casefold() for PathValue in SourceDirectories}
    PlannedKeys: set[str] = set()
    Plan: List[MaterializationItem] = []
    for Entry in DownstreamFiles:
        RelativePath = ValidateSafeRelativePath(
            Entry.RelativePath, "downstream materialization path"
        )
        Key = RelativePath.casefold()
        if Key in PlannedKeys:
            raise StageFailure(
                FailureClass.MaterializationCollision,
                f"downstream paths collide under Windows semantics: {RelativePath}",
            )
        PlannedKeys.add(Key)
        Parts = PurePosixPath(RelativePath).parts
        ParentKeys = {
            PurePosixPath(*Parts[:Index]).as_posix().casefold()
            for Index in range(1, len(Parts))
        }
        if Key in SourceFileKeys or Key in SourceDirectoryKeys or ParentKeys & SourceFileKeys:
            raise StageFailure(
                FailureClass.MaterializationCollision,
                f"downstream file would overwrite or traverse upstream content: {RelativePath}",
            )
        Plan.append(
            MaterializationItem(RelativePath, Entry.SourcePath, Sha256File(Entry.SourcePath))
        )
    Plan.sort(key=lambda Item: Item.RelativePath)
    return Plan


def CopySourceTree(SourceRoot: Path, IntegrationRoot: Path, Files: Sequence[TreeEntry]) -> None:
    try:
        IntegrationRoot.mkdir(parents=True, exist_ok=False)
        for Entry in Files:
            Destination = EnsureContained(IntegrationRoot, Entry.RelativePath)
            Destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(Entry.SourcePath, Destination)
            SourceMode = Entry.SourcePath.stat().st_mode
            os.chmod(Destination, 0o755 if SourceMode & stat.S_IXUSR else 0o644)
    except StageFailure:
        raise
    except OSError as Error:
        raise StageFailure(
            FailureClass.MaterializationFailure,
            f"could not create disposable integration tree: {Error}",
        ) from Error


def MaterializeDownstream(
    IntegrationRoot: Path, Plan: Sequence[MaterializationItem]
) -> None:
    try:
        for Item in Plan:
            Destination = EnsureContained(IntegrationRoot, Item.RelativePath)
            if Destination.exists() or Destination.is_symlink():
                raise StageFailure(
                    FailureClass.MaterializationCollision,
                    f"downstream materialization destination already exists: {Item.RelativePath}",
                )
            Destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(Item.SourcePath, Destination)
            SourceMode = Item.SourcePath.stat().st_mode
            os.chmod(Destination, 0o755 if SourceMode & stat.S_IXUSR else 0o644)
    except StageFailure:
        raise
    except OSError as Error:
        raise StageFailure(
            FailureClass.MaterializationFailure,
            f"downstream materialization failed: {Error}",
        ) from Error


def DefaultCommandRunner(
    Command: Sequence[str], WorkingDirectory: Path
) -> subprocess.CompletedProcess[str]:
    Environment = os.environ.copy()
    Environment["GIT_CONFIG_NOSYSTEM"] = "1"
    Environment["GIT_CONFIG_GLOBAL"] = os.devnull
    Environment["LC_ALL"] = "C"
    return subprocess.run(
        list(Command),
        cwd=WorkingDirectory,
        env=Environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def FindGit(CommandRunnerValue: CommandRunner) -> Tuple[str, str]:
    GitExecutable = shutil.which("git")
    if GitExecutable is None:
        raise StageFailure(FailureClass.ToolMissing, "Git is required but was not found")
    Result = CommandRunnerValue((GitExecutable, "--version"), Path.cwd())
    if Result.returncode != 0:
        raise StageFailure(
            FailureClass.ToolMissing,
            "Git was found but could not be executed",
            Diagnostics=Result.stderr or Result.stdout,
        )
    return GitExecutable, Result.stdout.strip()


def GitApplyCommand(GitExecutable: str, *Arguments: str) -> Tuple[str, ...]:
    return (
        GitExecutable,
        "-c",
        "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab",
        "apply",
        *Arguments,
    )


def ParsePatchPaths(Content: str, PatchName: str) -> Tuple[str, ...]:
    if "GIT binary patch" in Content or " mode 120000" in Content:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"patch uses an unsupported binary or symlink representation: {PatchName}",
        )
    RequiredMarkers = ("diff --git ", "--- ", "+++ ", "@@ ")
    MissingMarkers = [Marker.strip() for Marker in RequiredMarkers if Marker not in Content]
    if MissingMarkers:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"patch appears malformed: {PatchName} missing {', '.join(MissingMarkers)}",
        )
    AffectedPaths: List[str] = []
    for Line in Content.splitlines():
        if Line.startswith("diff --git "):
            try:
                Tokens = shlex.split(Line)
            except ValueError as Error:
                raise StageFailure(
                    FailureClass.InvalidSeries,
                    f"patch has an invalid diff header: {PatchName}",
                ) from Error
            if (
                len(Tokens) != 4
                or not Tokens[2].startswith("a/")
                or not Tokens[3].startswith("b/")
            ):
                raise StageFailure(
                    FailureClass.InvalidSeries,
                    f"patch has an unsupported diff header: {PatchName}",
                )
            for Token in Tokens[2:]:
                ValidateSafeRelativePath(Token[2:], f"path in patch {PatchName}")
            NewPath = ValidateSafeRelativePath(
                Tokens[3][2:], f"path in patch {PatchName}"
            )
            if NewPath not in AffectedPaths:
                AffectedPaths.append(NewPath)
            continue

        for Prefix in ("rename from ", "rename to ", "copy from ", "copy to "):
            if Line.startswith(Prefix):
                ValidateSafeRelativePath(
                    Line[len(Prefix) :], f"extended path in patch {PatchName}"
                )
                break
        else:
            if Line.startswith(("--- ", "+++ ")):
                HeaderPath = Line[4:].split("\t", 1)[0]
                if HeaderPath != "/dev/null":
                    if not HeaderPath.startswith(("a/", "b/")):
                        raise StageFailure(
                            FailureClass.InvalidSeries,
                            f"patch has an unsupported file header: {PatchName}",
                        )
                    ValidateSafeRelativePath(
                        HeaderPath[2:], f"file header in patch {PatchName}"
                    )
    if not AffectedPaths:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"patch contains no diff headers: {PatchName}",
        )
    return tuple(AffectedPaths)


def InspectPatch(
    PatchPath: Path,
    GitExecutable: str,
    CommandRunnerValue: CommandRunner,
) -> PatchItem:
    try:
        RawBytes = PatchPath.read_bytes()
    except OSError as Error:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"cannot read patch {PatchPath.name}: {Error}",
        ) from Error
    if not RawBytes or len(RawBytes) > MaxPatchBytes:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"patch is empty or exceeds the 10 MiB limit: {PatchPath.name}",
        )
    try:
        Content = RawBytes.decode("utf-8")
    except UnicodeDecodeError as Error:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"patch is not valid UTF-8: {PatchPath.name}",
        ) from Error
    AffectedPaths = ParsePatchPaths(Content, PatchPath.name)
    ParseResult = CommandRunnerValue(
        GitApplyCommand(GitExecutable, "--numstat", "-z", str(PatchPath.resolve())),
        PatchPath.parent,
    )
    if ParseResult.returncode != 0:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"Git could not parse patch {PatchPath.name}",
            FailedPatch=PatchPath.name,
            Diagnostics=ParseResult.stderr or ParseResult.stdout,
            AffectedPaths=AffectedPaths,
        )
    return PatchItem(PatchPath.name, PatchPath, Sha256Bytes(RawBytes), AffectedPaths)


def ReadPatchSeries(
    RepositoryRoot: Path,
    GitExecutable: str,
    CommandRunnerValue: CommandRunner,
) -> Tuple[List[PatchItem], str]:
    PatchDirectory = RepositoryRoot / "patches"
    SeriesPath = PatchDirectory / "series"
    try:
        Lines = SeriesPath.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as Error:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"cannot read patches/series: {Error}",
        ) from Error
    Entries = [Line.strip() for Line in Lines if Line.strip() and not Line.lstrip().startswith("#")]
    if len(Entries) != len(set(Entries)):
        raise StageFailure(FailureClass.InvalidSeries, "patches/series contains duplicates")

    ExistingPatchNames = {
        PathValue.name for PathValue in PatchDirectory.glob("*.patch") if PathValue.is_file()
    }
    ListedNames = set(Entries)
    UnlistedNames = sorted(ExistingPatchNames - ListedNames)
    if UnlistedNames:
        raise StageFailure(
            FailureClass.InvalidSeries,
            f"unlisted patch files exist: {', '.join(UnlistedNames)}",
        )

    Patches: List[PatchItem] = []
    for Position, Entry in enumerate(Entries, start=1):
        ValidateSafeRelativePath(Entry, "patches/series entry")
        if "/" in Entry:
            raise StageFailure(
                FailureClass.UnsafePath,
                f"patches/series entries must be filenames: {Entry}",
            )
        Match = PatchNamePattern.fullmatch(Entry)
        if Match is None or int(Match.group("Number")) != Position:
            raise StageFailure(
                FailureClass.InvalidSeries,
                f"patch {Position} must use contiguous 0001-name.patch ordering: {Entry}",
            )
        PatchPath = PatchDirectory / Entry
        if not PatchPath.is_file() or IsReparsePoint(PatchPath):
            raise StageFailure(
                FailureClass.InvalidSeries,
                f"listed patch is missing or unsafe: {Entry}",
            )
        Patches.append(InspectPatch(PatchPath, GitExecutable, CommandRunnerValue))

    SemanticSeries = ("\n".join(Entry.Name for Entry in Patches) + ("\n" if Patches else "")).encode(
        "utf-8"
    )
    return Patches, Sha256Bytes(SemanticSeries)


def BaseEvidence() -> Dict[str, Any]:
    return {
        "schema_version": EvidenceSchemaVersion,
        "stage": "PATCH-APPLY",
        "result": "FAIL",
        "synthetic": True,
        "engine_validation": "SYNTHETIC_FIXTURE_ONLY",
        "candidate": None,
        "source_identity": None,
        "inputs": {
            "qualification_request_sha256": None,
            "patch_series_sha256": None,
            "patches": [],
            "downstream_files": [],
            "git_version": None,
        },
        "execution": {
            "applied_patches": [],
            "attempted_patches": [],
            "failed_patch": None,
            "failure_class": None,
            "diagnostics": "",
            "affected_paths": [],
            "integration_tree_status": "NOT_CREATED",
        },
        "repair_bundle": None,
    }


def SetFailure(Evidence: Dict[str, Any], Failure: StageFailure) -> None:
    Evidence["result"] = "FAIL"
    Evidence["execution"]["failure_class"] = Failure.Failure.value
    Evidence["execution"]["failed_patch"] = Failure.FailedPatch
    Evidence["execution"]["diagnostics"] = BoundText(
        Failure.Message + (f"\n{Failure.Diagnostics}" if Failure.Diagnostics else "")
    )
    Evidence["execution"]["affected_paths"] = sorted(set(Failure.AffectedPaths))
    if Evidence["execution"]["integration_tree_status"] != "NOT_CREATED":
        Evidence["execution"]["integration_tree_status"] = "FAILED"


def ValidateEvidence(Evidence: Any) -> None:
    if not isinstance(Evidence, dict):
        raise ValueError("evidence must be an object")
    ExpectedKeys = {
        "schema_version",
        "stage",
        "result",
        "synthetic",
        "engine_validation",
        "candidate",
        "source_identity",
        "inputs",
        "execution",
        "repair_bundle",
    }
    if set(Evidence) != ExpectedKeys:
        raise ValueError("evidence has missing or unsupported top-level keys")
    if Evidence["schema_version"] != EvidenceSchemaVersion or Evidence["stage"] != "PATCH-APPLY":
        raise ValueError("evidence has an unsupported schema or stage")
    if Evidence["synthetic"] is not True or Evidence["engine_validation"] != "SYNTHETIC_FIXTURE_ONLY":
        raise ValueError("synthetic engine evidence must be unambiguously marked synthetic")
    if Evidence["result"] not in {"PASS", "FAIL"}:
        raise ValueError("evidence result must be PASS or FAIL")
    Inputs = Evidence["inputs"]
    Execution = Evidence["execution"]
    if not isinstance(Inputs, dict) or not isinstance(Execution, dict):
        raise ValueError("evidence inputs and execution must be objects")
    if Evidence["result"] == "PASS":
        if Evidence["candidate"] is None or Evidence["source_identity"] is None:
            raise ValueError("PASS evidence requires candidate and source identity")
        if Execution["failure_class"] is not None or Execution["failed_patch"] is not None:
            raise ValueError("PASS evidence cannot contain failure fields")
        if Execution["integration_tree_status"] != "COMPLETE":
            raise ValueError("PASS evidence requires a complete integration tree")
        OrderedPatches = [Patch["name"] for Patch in Inputs["patches"]]
        if Execution["applied_patches"] != OrderedPatches:
            raise ValueError("PASS evidence must record every ordered patch as applied")
    else:
        if Execution["failure_class"] not in {Value.value for Value in FailureClass}:
            raise ValueError("FAIL evidence requires a known failure class")
        if Execution["integration_tree_status"] == "COMPLETE":
            raise ValueError("FAIL evidence cannot mark the integration tree complete")
    for HashName in ("qualification_request_sha256", "patch_series_sha256"):
        HashValue = Inputs[HashName]
        if HashValue is not None and ShaPattern.fullmatch(HashValue) is None:
            raise ValueError(f"invalid evidence hash: {HashName}")


def AtomicWriteJson(Destination: Path, Data: Mapping[str, Any]) -> None:
    TemporaryPath: Optional[Path] = None
    try:
        Destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=Destination.parent,
            prefix=f".{Destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as TemporaryFile:
            TemporaryPath = Path(TemporaryFile.name)
            json.dump(Data, TemporaryFile, indent=2, sort_keys=True)
            TemporaryFile.write("\n")
            TemporaryFile.flush()
            os.fsync(TemporaryFile.fileno())
        os.replace(TemporaryPath, Destination)
        TemporaryPath = None
    finally:
        if TemporaryPath is not None:
            try:
                TemporaryPath.unlink(missing_ok=True)
            except OSError:
                pass


def PathsOverlap(FirstPath: Path, SecondPath: Path) -> bool:
    First = FirstPath.resolve(strict=False)
    Second = SecondPath.resolve(strict=False)
    try:
        First.relative_to(Second)
        return True
    except ValueError:
        pass
    try:
        Second.relative_to(First)
        return True
    except ValueError:
        return False


def ApplyPatches(
    IntegrationRoot: Path,
    Patches: Sequence[PatchItem],
    GitExecutable: str,
    CommandRunnerValue: CommandRunner,
    Evidence: Dict[str, Any],
) -> None:
    for Patch in Patches:
        Evidence["execution"]["attempted_patches"].append(Patch.Name)
        CheckResult = CommandRunnerValue(
            GitApplyCommand(
                GitExecutable,
                "--check",
                "--whitespace=error-all",
                "--verbose",
                str(Patch.PatchPath.resolve()),
            ),
            IntegrationRoot,
        )
        if CheckResult.returncode != 0:
            raise StageFailure(
                FailureClass.PatchCheckFailed,
                f"patch preflight failed: {Patch.Name}",
                FailedPatch=Patch.Name,
                Diagnostics=CheckResult.stderr or CheckResult.stdout,
                AffectedPaths=Patch.AffectedPaths,
            )
        ApplyResult = CommandRunnerValue(
            GitApplyCommand(
                GitExecutable,
                "--whitespace=error-all",
                "--verbose",
                str(Patch.PatchPath.resolve()),
            ),
            IntegrationRoot,
        )
        if ApplyResult.returncode != 0:
            raise StageFailure(
                FailureClass.PatchApplyFailed,
                f"patch application failed after successful preflight: {Patch.Name}",
                FailedPatch=Patch.Name,
                Diagnostics=ApplyResult.stderr or ApplyResult.stdout,
                AffectedPaths=Patch.AffectedPaths,
            )
        Evidence["execution"]["applied_patches"].append(Patch.Name)


def BuildRepairBundle(
    RequestData: Mapping[str, Any], Evidence: Mapping[str, Any], Patches: Sequence[PatchItem]
) -> Dict[str, Any]:
    FailedPatchName = Evidence["execution"]["failed_patch"]
    FailedPatch = next((Patch for Patch in Patches if Patch.Name == FailedPatchName), None)
    return {
        "schema_version": 1,
        "synthetic": True,
        "qualification_request": RequestData,
        "candidate": Evidence["candidate"],
        "ordered_patches": [Patch.Name for Patch in Patches],
        "applied_patches": Evidence["execution"]["applied_patches"],
        "failed_patch": FailedPatchName,
        "failed_patch_sha256": FailedPatch.Sha256 if FailedPatch else None,
        "affected_paths": Evidence["execution"]["affected_paths"],
        "git_diagnostic": Evidence["execution"]["diagnostics"],
        "evidence": Evidence,
    }


def RunQualification(
    RequestPath: Path,
    SourceRoot: Path,
    RepositoryRoot: Path,
    Workspace: Path,
    FixtureId: str,
    *,
    SourceKind: str = "synthetic-fixture",
    CommandRunnerValue: CommandRunner = DefaultCommandRunner,
    JsonWriterValue: JsonWriter = AtomicWriteJson,
) -> Dict[str, Any]:
    Evidence = BaseEvidence()
    RequestData: Dict[str, Any] = {}
    Patches: List[PatchItem] = []
    WorkspaceCreated = False
    try:
        if SourceKind != "synthetic-fixture":
            raise StageFailure(
                FailureClass.InvalidSource,
                "only synthetic-fixture source identity is implemented",
            )
        if FixtureIdPattern.fullmatch(FixtureId) is None:
            raise StageFailure(FailureClass.InvalidSource, "fixture id is missing or invalid")
        if Workspace.exists():
            raise StageFailure(
                FailureClass.InvalidWorkspace,
                f"workspace must not already exist: {Workspace}",
            )
        if PathsOverlap(Workspace, SourceRoot):
            raise StageFailure(
                FailureClass.InvalidWorkspace,
                "workspace must not overlap the source tree",
            )
        try:
            Workspace.mkdir(parents=True, exist_ok=False)
            WorkspaceCreated = True
        except OSError as Error:
            raise StageFailure(
                FailureClass.InvalidWorkspace,
                f"cannot create workspace: {Error}",
            ) from Error

        RequestData, RequestHash = LoadQualificationRequest(RequestPath)
        Evidence["candidate"] = dict(RequestData["candidate"])
        Evidence["inputs"]["qualification_request_sha256"] = RequestHash

        SourceFiles, SourceDirectories = EnumerateSafeTree(SourceRoot, "source tree")
        Evidence["source_identity"] = {
            "kind": "synthetic_fixture",
            "fixture_id": FixtureId,
            "tree_sha256": TreeSha256(SourceFiles),
        }

        GitExecutable, GitVersion = FindGit(CommandRunnerValue)
        Evidence["inputs"]["git_version"] = GitVersion
        Patches, SeriesHash = ReadPatchSeries(
            RepositoryRoot, GitExecutable, CommandRunnerValue
        )
        Evidence["inputs"]["patch_series_sha256"] = SeriesHash
        Evidence["inputs"]["patches"] = [
            {
                "name": Patch.Name,
                "sha256": Patch.Sha256,
                "affected_paths": list(Patch.AffectedPaths),
            }
            for Patch in Patches
        ]

        MaterializationPlan = BuildMaterializationPlan(
            RepositoryRoot, SourceFiles, SourceDirectories
        )
        Evidence["inputs"]["downstream_files"] = [
            {"path": Item.RelativePath, "sha256": Item.Sha256}
            for Item in MaterializationPlan
        ]

        IntegrationRoot = Workspace / "integration"
        CopySourceTree(SourceRoot, IntegrationRoot, SourceFiles)
        Evidence["execution"]["integration_tree_status"] = "PREPARED"
        MaterializeDownstream(IntegrationRoot, MaterializationPlan)
        ApplyPatches(
            IntegrationRoot,
            Patches,
            GitExecutable,
            CommandRunnerValue,
            Evidence,
        )
        Evidence["result"] = "PASS"
        Evidence["execution"]["integration_tree_status"] = "COMPLETE"
    except StageFailure as Failure:
        SetFailure(Evidence, Failure)
    except Exception as Error:  # pragma: no cover - final safety boundary
        SetFailure(
            Evidence,
            StageFailure(
                FailureClass.InternalError,
                f"unexpected patch engine error: {type(Error).__name__}: {Error}",
            ),
        )

    if Evidence["execution"]["failure_class"] in {
        FailureClass.PatchCheckFailed.value,
        FailureClass.PatchApplyFailed.value,
    }:
        Evidence["repair_bundle"] = "repair-bundle.json"

    try:
        ValidateEvidence(Evidence)
        if WorkspaceCreated:
            if Evidence["repair_bundle"] is not None:
                RepairBundle = BuildRepairBundle(RequestData, Evidence, Patches)
                JsonWriterValue(Workspace / "repair-bundle.json", RepairBundle)
            JsonWriterValue(Workspace / "evidence.json", Evidence)
    except Exception as Error:
        SetFailure(
            Evidence,
            StageFailure(
                FailureClass.EvidenceWriteFailed,
                f"could not validate or write evidence: {Error}",
            ),
        )
        Evidence["repair_bundle"] = None
    return Evidence


def FormatCandidate(Candidate: Optional[Mapping[str, Any]]) -> str:
    if Candidate is None:
        return "unavailable"
    return f"{Candidate['chrome_version']} @ {Candidate['chromium_sha']}"


def PrintHumanResult(Evidence: Mapping[str, Any], Workspace: Path) -> None:
    print(f"Synthetic patch engine result: {Evidence['result']}")
    print(f"Candidate input: {FormatCandidate(Evidence['candidate'])}")
    print(f"Applied patches: {len(Evidence['execution']['applied_patches'])}")
    if Evidence["result"] == "FAIL":
        print(f"Failure class: {Evidence['execution']['failure_class']}")
        print(f"Failed patch: {Evidence['execution']['failed_patch'] or 'none'}")
        print(f"Diagnostic: {Evidence['execution']['diagnostics']}")
    EvidencePath = Workspace / "evidence.json"
    print(f"Evidence: {EvidencePath if EvidencePath.is_file() else 'not written'}")
    print("Project qualification level: STATIC (unchanged)")


def ParseArguments(Arguments: Sequence[str]) -> argparse.Namespace:
    Parser = argparse.ArgumentParser(description=__doc__)
    Parser.add_argument("--request", required=True, type=Path)
    Parser.add_argument("--source", required=True, type=Path)
    Parser.add_argument("--repository-root", type=Path, default=DefaultRepositoryRoot)
    Parser.add_argument("--workspace", required=True, type=Path)
    Parser.add_argument(
        "--source-kind",
        required=True,
        choices=("synthetic-fixture",),
        help="source identity kind; only synthetic fixtures are currently supported",
    )
    Parser.add_argument("--fixture-id", required=True)
    Parser.add_argument("--json", action="store_true", help="emit evidence JSON")
    return Parser.parse_args(Arguments)


def Main(Arguments: Iterable[str] = ()) -> int:
    Options = ParseArguments(list(Arguments))
    Evidence = RunQualification(
        Options.request,
        Options.source,
        Options.repository_root,
        Options.workspace,
        Options.fixture_id,
        SourceKind=Options.source_kind,
    )
    if Options.json:
        print(json.dumps(Evidence, indent=2, sort_keys=True))
    else:
        PrintHumanResult(Evidence, Options.workspace)
    return 0 if Evidence["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(Main(sys.argv[1:]))
