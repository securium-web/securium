#!/usr/bin/env python3
"""Detect an unqualified Windows Stable Chromium candidate from ChromiumDash."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ChromiumDashEndpoint = "https://chromiumdash.appspot.com/fetch_releases"
ChromiumDashQuery = (
    ("channel", "Stable"),
    ("platform", "Windows"),
    ("num", "1"),
    ("offset", "0"),
)
DefaultStatePath = Path(__file__).resolve().parents[1] / "state" / "upstream.json"
MaxResponseBytes = 1024 * 1024
SchemaVersion = 1

VersionPattern = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
ShaPattern = re.compile(r"^[0-9a-f]{40}$")
QualifiedLevels = {
    "PATCH-APPLY",
    "COMPILE",
    "TEST",
    "RUNTIME",
    "SECURITY-QUALIFIED",
    "RELEASE-QUALIFIED",
}


class UpdateError(Exception):
    """Base class for controlled detector failures."""


class FetchError(UpdateError):
    """The upstream response could not be retrieved."""


class UpstreamDataError(UpdateError):
    """The upstream response was malformed, ambiguous, or unexpected."""


class StateValidationError(UpdateError):
    """Local state is malformed or uses an unsupported schema."""


class StateWriteError(UpdateError):
    """A candidate state update could not be completed atomically."""


class QualificationRequestError(UpdateError):
    """A qualification request does not match the versioned contract."""


class Decision(str, Enum):
    NoChange = "NO_CHANGE"
    NewCandidate = "NEW_CANDIDATE"
    CandidateAlreadyQualified = "CANDIDATE_ALREADY_QUALIFIED"
    CandidateAlreadyReleased = "CANDIDATE_ALREADY_RELEASED"
    UpstreamRegression = "UPSTREAM_REGRESSION"
    UpstreamConflict = "UPSTREAM_CONFLICT"
    InvalidUpstream = "INVALID_UPSTREAM"
    InvalidState = "INVALID_STATE"
    FetchFailed = "FETCH_FAILED"
    StateWriteFailed = "STATE_WRITE_FAILED"


@dataclass(frozen=True)
class Candidate:
    Channel: str
    Platform: str
    ChromeVersion: str
    ChromiumSha: str

    def AsDictionary(self) -> Dict[str, str]:
        return {
            "channel": self.Channel,
            "platform": self.Platform,
            "chrome_version": self.ChromeVersion,
            "chromium_sha": self.ChromiumSha,
            "qualification": "UNQUALIFIED",
        }


@dataclass(frozen=True)
class CandidateDecision:
    Name: Decision
    QualificationRequired: bool
    DispatchQualification: bool
    Detail: str


def ChromiumDashUrl() -> str:
    return f"{ChromiumDashEndpoint}?{urlencode(ChromiumDashQuery)}"


def FetchChromiumDash(TimeoutSeconds: float = 20.0) -> str:
    RequestObject = Request(
        ChromiumDashUrl(),
        headers={
            "Accept": "application/json",
            "User-Agent": "Securium-Chromium-candidate-detector/1",
        },
    )
    try:
        with urlopen(RequestObject, timeout=TimeoutSeconds) as Response:
            Status = getattr(Response, "status", 200)
            if Status != 200:
                raise FetchError(f"ChromiumDash returned HTTP {Status}")
            RawBytes = Response.read(MaxResponseBytes + 1)
    except HTTPError as Error:
        raise FetchError(f"ChromiumDash returned HTTP {Error.code}") from Error
    except (URLError, TimeoutError, OSError) as Error:
        raise FetchError(f"could not contact ChromiumDash: {Error}") from Error

    if len(RawBytes) > MaxResponseBytes:
        raise FetchError("ChromiumDash response exceeded the 1 MiB safety limit")
    try:
        return RawBytes.decode("utf-8")
    except UnicodeDecodeError as Error:
        raise UpstreamDataError("ChromiumDash response was not valid UTF-8") from Error


def ParseVersion(Version: Any, Context: str) -> Tuple[int, int, int, int]:
    if not isinstance(Version, str) or VersionPattern.fullmatch(Version) is None:
        raise UpstreamDataError(f"{Context} must be a four-component numeric version")
    return tuple(int(Component) for Component in Version.split("."))  # type: ignore[return-value]


def ValidateSha(Sha: Any, Context: str, ErrorType: type[UpdateError]) -> str:
    if not isinstance(Sha, str) or ShaPattern.fullmatch(Sha) is None:
        raise ErrorType(f"{Context} must be a lowercase 40-character Git SHA")
    return Sha


def ParseChromiumDashResponse(RawResponse: str) -> Candidate:
    try:
        Payload = json.loads(RawResponse)
    except json.JSONDecodeError as Error:
        raise UpstreamDataError(f"ChromiumDash returned malformed JSON: {Error.msg}") from Error

    if not isinstance(Payload, list):
        raise UpstreamDataError("ChromiumDash response must be a JSON array")
    if len(Payload) != 1:
        raise UpstreamDataError(
            "ChromiumDash num=1 response must contain exactly one release; "
            f"received {len(Payload)}"
        )

    Release = Payload[0]
    if not isinstance(Release, dict):
        raise UpstreamDataError("ChromiumDash release entry must be a JSON object")

    Channel = Release.get("channel")
    Platform = Release.get("platform")
    Version = Release.get("version")
    Hashes = Release.get("hashes")
    if Channel != "Stable":
        raise UpstreamDataError(f"expected Stable channel, received {Channel!r}")
    if Platform != "Windows":
        raise UpstreamDataError(f"expected Windows platform, received {Platform!r}")
    ParseVersion(Version, "ChromiumDash version")
    if not isinstance(Hashes, dict):
        raise UpstreamDataError("ChromiumDash release is missing the hashes object")
    ChromiumSha = ValidateSha(
        Hashes.get("chromium"),
        "ChromiumDash hashes.chromium",
        UpstreamDataError,
    )

    return Candidate(
        Channel=Channel,
        Platform=Platform,
        ChromeVersion=Version,
        ChromiumSha=ChromiumSha,
    )


def EmptyProjectState() -> Dict[str, Any]:
    return {
        "schema_version": SchemaVersion,
        "candidate": None,
        "qualified": None,
        "released": None,
    }


def RequireExactKeys(
    Value: Mapping[str, Any], RequiredKeys: set[str], Context: str
) -> None:
    ActualKeys = set(Value)
    MissingKeys = sorted(RequiredKeys - ActualKeys)
    ExtraKeys = sorted(ActualKeys - RequiredKeys)
    if MissingKeys:
        raise StateValidationError(f"{Context} is missing keys: {', '.join(MissingKeys)}")
    if ExtraKeys:
        raise StateValidationError(f"{Context} has unsupported keys: {', '.join(ExtraKeys)}")


def ValidateTimestamp(Value: Any, Context: str) -> None:
    if not isinstance(Value, str) or not Value.endswith("Z"):
        raise StateValidationError(f"{Context} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        Parsed = datetime.fromisoformat(Value[:-1] + "+00:00")
    except ValueError as Error:
        raise StateValidationError(f"{Context} is not a valid timestamp") from Error
    if Parsed.tzinfo is None or Parsed.utcoffset() != timezone.utc.utcoffset(Parsed):
        raise StateValidationError(f"{Context} must use UTC")


def ValidateRevisionIdentity(Revision: Mapping[str, Any], Context: str) -> None:
    if Revision.get("channel") != "Stable":
        raise StateValidationError(f"{Context}.channel must be Stable")
    if Revision.get("platform") != "Windows":
        raise StateValidationError(f"{Context}.platform must be Windows")
    try:
        ParseVersion(Revision.get("chrome_version"), f"{Context}.chrome_version")
    except UpstreamDataError as Error:
        raise StateValidationError(str(Error)) from Error
    ValidateSha(Revision.get("chromium_sha"), f"{Context}.chromium_sha", StateValidationError)


def ValidateOptionalRecord(
    State: Mapping[str, Any], Name: str, RequiredKeys: set[str]
) -> None:
    Record = State.get(Name)
    if Record is None:
        return
    if not isinstance(Record, dict):
        raise StateValidationError(f"state.{Name} must be an object or null")
    RequireExactKeys(Record, RequiredKeys, f"state.{Name}")
    ValidateRevisionIdentity(Record, f"state.{Name}")


def ValidateProjectState(State: Any) -> None:
    if not isinstance(State, dict):
        raise StateValidationError("project state must be a JSON object")
    RequireExactKeys(
        State,
        {"schema_version", "candidate", "qualified", "released"},
        "project state",
    )
    if State.get("schema_version") != SchemaVersion:
        raise StateValidationError(
            f"unsupported project state schema_version {State.get('schema_version')!r}; "
            f"expected {SchemaVersion}"
        )

    ValidateOptionalRecord(
        State,
        "candidate",
        {
            "channel",
            "platform",
            "chrome_version",
            "chromium_sha",
            "detected_at",
            "qualification",
        },
    )
    CandidateRecord = State.get("candidate")
    if CandidateRecord is not None:
        if CandidateRecord.get("qualification") != "UNQUALIFIED":
            raise StateValidationError("state.candidate.qualification must be UNQUALIFIED")
        ValidateTimestamp(CandidateRecord.get("detected_at"), "state.candidate.detected_at")

    ValidateOptionalRecord(
        State,
        "qualified",
        {
            "channel",
            "platform",
            "chrome_version",
            "chromium_sha",
            "qualification_level",
            "qualified_at",
        },
    )
    QualifiedRecord = State.get("qualified")
    if QualifiedRecord is not None:
        if QualifiedRecord.get("qualification_level") not in QualifiedLevels:
            raise StateValidationError(
                "state.qualified.qualification_level must be a revision-linked "
                "qualification level"
            )
        ValidateTimestamp(QualifiedRecord.get("qualified_at"), "state.qualified.qualified_at")

    ValidateOptionalRecord(
        State,
        "released",
        {
            "channel",
            "platform",
            "chrome_version",
            "chromium_sha",
            "release_version",
            "released_at",
        },
    )
    ReleasedRecord = State.get("released")
    if ReleasedRecord is not None:
        if QualifiedRecord is None:
            raise StateValidationError("state.released requires a non-null qualified record")
        if not isinstance(ReleasedRecord.get("release_version"), str) or not ReleasedRecord.get(
            "release_version"
        ):
            raise StateValidationError("state.released.release_version must be a non-empty string")
        ValidateTimestamp(ReleasedRecord.get("released_at"), "state.released.released_at")


def ValidateQualificationRequest(RequestData: Any) -> None:
    if not isinstance(RequestData, dict):
        raise QualificationRequestError("qualification request must be a JSON object")
    ExpectedKeys = {"schema_version", "previous_qualified", "candidate"}
    ActualKeys = set(RequestData)
    MissingKeys = sorted(ExpectedKeys - ActualKeys)
    ExtraKeys = sorted(ActualKeys - ExpectedKeys)
    if MissingKeys:
        raise QualificationRequestError(
            f"qualification request is missing keys: {', '.join(MissingKeys)}"
        )
    if ExtraKeys:
        raise QualificationRequestError(
            f"qualification request has unsupported keys: {', '.join(ExtraKeys)}"
        )
    if RequestData.get("schema_version") != SchemaVersion:
        raise QualificationRequestError(
            f"unsupported qualification request schema_version "
            f"{RequestData.get('schema_version')!r}; expected {SchemaVersion}"
        )

    for Name in ("candidate", "previous_qualified"):
        Revision = RequestData.get(Name)
        if Name == "previous_qualified" and Revision is None:
            continue
        if not isinstance(Revision, dict):
            raise QualificationRequestError(
                f"qualification request {Name} must be an object"
            )
        RevisionKeys = set(Revision)
        ExpectedRevisionKeys = {"chrome_version", "chromium_sha"}
        MissingRevisionKeys = sorted(ExpectedRevisionKeys - RevisionKeys)
        ExtraRevisionKeys = sorted(RevisionKeys - ExpectedRevisionKeys)
        if MissingRevisionKeys:
            raise QualificationRequestError(
                f"qualification request {Name} is missing keys: "
                f"{', '.join(MissingRevisionKeys)}"
            )
        if ExtraRevisionKeys:
            raise QualificationRequestError(
                f"qualification request {Name} has unsupported keys: "
                f"{', '.join(ExtraRevisionKeys)}"
            )
        try:
            ParseVersion(
                Revision.get("chrome_version"),
                f"qualification request {Name}.chrome_version",
            )
        except UpstreamDataError as Error:
            raise QualificationRequestError(str(Error)) from Error
        ValidateSha(
            Revision.get("chromium_sha"),
            f"qualification request {Name}.chromium_sha",
            QualificationRequestError,
        )


def LoadProjectState(StatePath: Path) -> Dict[str, Any]:
    try:
        RawState = StatePath.read_text(encoding="utf-8")
    except OSError as Error:
        raise StateValidationError(f"cannot read state file {StatePath}: {Error}") from Error
    try:
        State = json.loads(RawState)
    except json.JSONDecodeError as Error:
        raise StateValidationError(f"state file contains malformed JSON: {Error.msg}") from Error
    ValidateProjectState(State)
    return State


def RevisionMatches(CandidateValue: Candidate, Revision: Optional[Mapping[str, Any]]) -> bool:
    return bool(
        Revision
        and Revision.get("chrome_version") == CandidateValue.ChromeVersion
        and Revision.get("chromium_sha") == CandidateValue.ChromiumSha
    )


def CompareCandidate(CandidateValue: Candidate, State: Mapping[str, Any]) -> CandidateDecision:
    ValidateProjectState(State)

    for Name in ("candidate", "qualified", "released"):
        Revision = State.get(Name)
        if (
            Revision
            and Revision["chromium_sha"] == CandidateValue.ChromiumSha
            and Revision["chrome_version"] != CandidateValue.ChromeVersion
        ):
            return CandidateDecision(
                Decision.UpstreamConflict,
                False,
                False,
                f"the Chromium SHA is already associated with a different version in {Name} state",
            )

    CandidateVersion = ParseVersion(CandidateValue.ChromeVersion, "candidate chrome_version")
    LocalVersions = [
        ParseVersion(Revision["chrome_version"], f"state.{Name}.chrome_version")
        for Name in ("candidate", "qualified", "released")
        if (Revision := State.get(Name)) is not None
    ]
    if LocalVersions and CandidateVersion < max(LocalVersions):
        return CandidateDecision(
            Decision.UpstreamRegression,
            False,
            False,
            "the detected version is older than a locally recorded revision",
        )

    if RevisionMatches(CandidateValue, State.get("released")):
        return CandidateDecision(
            Decision.CandidateAlreadyReleased,
            False,
            False,
            "the detected revision is already recorded as released",
        )
    if RevisionMatches(CandidateValue, State.get("qualified")):
        return CandidateDecision(
            Decision.CandidateAlreadyQualified,
            False,
            False,
            "the detected revision is already recorded as qualified",
        )
    if RevisionMatches(CandidateValue, State.get("candidate")):
        return CandidateDecision(
            Decision.NoChange,
            True,
            False,
            "the same unqualified candidate is already recorded",
        )
    return CandidateDecision(
        Decision.NewCandidate,
        True,
        True,
        "a new exact Chromium SHA requires qualification",
    )


def CurrentUtcTimestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def CandidateStateRecord(CandidateValue: Candidate, DetectedAt: str) -> Dict[str, str]:
    Record = CandidateValue.AsDictionary()
    Record["detected_at"] = DetectedAt
    return Record


def AtomicWriteJson(
    Destination: Path,
    Data: Mapping[str, Any],
    ReplaceFunction: Optional[Callable[[str, str], None]] = None,
) -> None:
    Destination.parent.mkdir(parents=True, exist_ok=True)
    Replace = ReplaceFunction or os.replace
    TemporaryPath: Optional[Path] = None
    try:
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
        Replace(str(TemporaryPath), str(Destination))
        TemporaryPath = None
    except (OSError, TypeError, ValueError) as Error:
        raise StateWriteError(f"atomic state write failed: {Error}") from Error
    finally:
        if TemporaryPath is not None:
            try:
                TemporaryPath.unlink(missing_ok=True)
            except OSError:
                pass


def UpdateCandidateState(
    StatePath: Path,
    ExpectedState: Mapping[str, Any],
    CandidateValue: Candidate,
    DetectedAt: str,
    ReplaceFunction: Optional[Callable[[str, str], None]] = None,
) -> Dict[str, Any]:
    ValidateTimestamp(DetectedAt, "detected_at")
    CurrentState = LoadProjectState(StatePath)
    if CurrentState != ExpectedState:
        raise StateWriteError("state changed after comparison; refusing to overwrite concurrent data")

    ProposedState = copy.deepcopy(CurrentState)
    OriginalQualified = copy.deepcopy(CurrentState["qualified"])
    OriginalReleased = copy.deepcopy(CurrentState["released"])
    ProposedState["candidate"] = CandidateStateRecord(CandidateValue, DetectedAt)
    if ProposedState["qualified"] != OriginalQualified or ProposedState["released"] != OriginalReleased:
        raise StateWriteError("candidate update attempted to modify qualified or released state")
    ValidateProjectState(ProposedState)
    AtomicWriteJson(StatePath, ProposedState, ReplaceFunction=ReplaceFunction)
    return ProposedState


def BuildQualificationRequest(
    CandidateValue: Candidate, State: Mapping[str, Any]
) -> Dict[str, Any]:
    Qualified = State.get("qualified")
    PreviousQualified = None
    if Qualified is not None:
        PreviousQualified = {
            "chrome_version": Qualified["chrome_version"],
            "chromium_sha": Qualified["chromium_sha"],
        }
    RequestData = {
        "schema_version": SchemaVersion,
        "previous_qualified": PreviousQualified,
        "candidate": {
            "chrome_version": CandidateValue.ChromeVersion,
            "chromium_sha": CandidateValue.ChromiumSha,
        },
    }
    ValidateQualificationRequest(RequestData)
    return RequestData


def BuildReport(
    CandidateValue: Candidate,
    State: Mapping[str, Any],
    CandidateDecisionValue: CandidateDecision,
    StateChanged: bool,
) -> Dict[str, Any]:
    QualificationRequest = None
    if CandidateDecisionValue.DispatchQualification:
        QualificationRequest = BuildQualificationRequest(CandidateValue, State)
    return {
        "schema_version": SchemaVersion,
        "decision": CandidateDecisionValue.Name.value,
        "detail": CandidateDecisionValue.Detail,
        "qualification_required": CandidateDecisionValue.QualificationRequired,
        "dispatch_qualification": CandidateDecisionValue.DispatchQualification,
        "state_changed": StateChanged,
        "candidate": CandidateValue.AsDictionary(),
        "current_candidate": State.get("candidate"),
        "current_qualified": State.get("qualified"),
        "current_released": State.get("released"),
        "qualification_request": QualificationRequest,
    }


def ExecuteCheck(
    RawResponse: str,
    StatePath: Path,
    WriteCandidate: bool = False,
    DetectedAt: Optional[str] = None,
    ReplaceFunction: Optional[Callable[[str, str], None]] = None,
) -> Tuple[Dict[str, Any], Decision]:
    CandidateValue = ParseChromiumDashResponse(RawResponse)
    State = LoadProjectState(StatePath)
    DecisionValue = CompareCandidate(CandidateValue, State)
    StateChanged = False

    WritableDecisions = {
        Decision.NewCandidate,
        Decision.CandidateAlreadyQualified,
        Decision.CandidateAlreadyReleased,
    }
    if WriteCandidate and DecisionValue.Name in WritableDecisions:
        UpdateCandidateState(
            StatePath,
            State,
            CandidateValue,
            DetectedAt or CurrentUtcTimestamp(),
            ReplaceFunction=ReplaceFunction,
        )
        StateChanged = True

    return BuildReport(CandidateValue, State, DecisionValue, StateChanged), DecisionValue.Name


def ErrorReport(DecisionValue: Decision, Error: UpdateError) -> Dict[str, Any]:
    return {
        "schema_version": SchemaVersion,
        "decision": DecisionValue.value,
        "qualification_required": False,
        "dispatch_qualification": False,
        "state_changed": False,
        "error": str(Error),
    }


def FormatRevision(Revision: Optional[Mapping[str, Any]]) -> str:
    if Revision is None:
        return "none"
    return f"{Revision['chrome_version']} @ {Revision['chromium_sha']}"


def PrintHumanReport(Report: Mapping[str, Any]) -> None:
    print(f"Current qualified Chromium: {FormatRevision(Report['current_qualified'])}")
    print(f"Detected Stable Chromium: {FormatRevision(Report['candidate'])}")
    print(f"Decision: {Report['decision']} ({Report['detail']})")
    print(f"Qualification required: {'yes' if Report['qualification_required'] else 'no'}")
    print(f"Dispatch qualification: {'yes' if Report['dispatch_qualification'] else 'no'}")
    print(f"Candidate state changed: {'yes' if Report['state_changed'] else 'no'}")
    print("Evidence level: STATIC only")


def PrintErrorReport(Report: Mapping[str, Any]) -> None:
    print("Current qualified Chromium: unchanged")
    print("Detected Stable Chromium: unavailable")
    print(f"Decision: {Report['decision']}")
    print("Qualification required: no decision")
    print(f"Error: {Report['error']}")
    print("Local state was not modified.")


def ParseArguments(Arguments: Sequence[str]) -> argparse.Namespace:
    Parser = argparse.ArgumentParser(description=__doc__)
    Subparsers = Parser.add_subparsers(dest="Command", required=True)
    CheckParser = Subparsers.add_parser("check", help="detect and compare Stable metadata")
    CheckParser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    CheckParser.add_argument(
        "--offline-fixture",
        type=Path,
        help="read a committed or local ChromiumDash response instead of using the network",
    )
    CheckParser.add_argument(
        "--state",
        type=Path,
        default=DefaultStatePath,
        help=f"project state path (default: {DefaultStatePath})",
    )
    CheckParser.add_argument(
        "--write-candidate",
        action="store_true",
        help="atomically update only candidate state when the decision permits it",
    )
    CheckParser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="live ChromiumDash request timeout in seconds",
    )
    return Parser.parse_args(Arguments)


def Main(Arguments: Iterable[str] = ()) -> int:
    Options = ParseArguments(list(Arguments))
    try:
        if Options.offline_fixture is not None:
            try:
                RawResponse = Options.offline_fixture.read_text(encoding="utf-8")
            except OSError as Error:
                raise FetchError(f"cannot read offline fixture: {Error}") from Error
        else:
            RawResponse = FetchChromiumDash(Options.timeout)

        Report, DecisionValue = ExecuteCheck(
            RawResponse,
            Options.state,
            WriteCandidate=Options.write_candidate,
        )
        if Options.json:
            print(json.dumps(Report, indent=2, sort_keys=True))
        else:
            PrintHumanReport(Report)
        if DecisionValue in {Decision.UpstreamRegression, Decision.UpstreamConflict}:
            return 2
        return 0
    except UpstreamDataError as Error:
        Report = ErrorReport(Decision.InvalidUpstream, Error)
    except FetchError as Error:
        Report = ErrorReport(Decision.FetchFailed, Error)
    except StateValidationError as Error:
        Report = ErrorReport(Decision.InvalidState, Error)
    except StateWriteError as Error:
        Report = ErrorReport(Decision.StateWriteFailed, Error)

    if Options.json:
        print(json.dumps(Report, indent=2, sort_keys=True))
    else:
        PrintErrorReport(Report)
    return 2


if __name__ == "__main__":
    sys.exit(Main(sys.argv[1:]))
