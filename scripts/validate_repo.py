#!/usr/bin/env python3
"""Offline consistency checks for the Chromium Secure patch repository."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, List, Sequence


ScriptDirectory = Path(__file__).resolve().parent
if str(ScriptDirectory) not in sys.path:
    sys.path.insert(0, str(ScriptDirectory))

from chromium_update import StateValidationError, ValidateProjectState  # noqa: E402


RequiredFiles = (
    "AGENTS.md",
    "README.md",
    "LICENSE",
    "patches/README.md",
    "patches/series",
    "src/README.md",
    "tests/README.md",
    "tests/integration/README.md",
    "tests/security/README.md",
    "tests/static/test_chromium_update.py",
    "tests/fixtures/chromiumdash/valid-stable-windows.json",
    "tests/fixtures/chromiumdash/malformed.json",
    "tests/fixtures/chromiumdash/missing-version.json",
    "tests/fixtures/chromiumdash/missing-sha.json",
    "tests/fixtures/chromiumdash/invalid-sha.json",
    "tests/fixtures/chromiumdash/wrong-channel.json",
    "tests/fixtures/chromiumdash/wrong-platform.json",
    "tests/fixtures/chromiumdash/ambiguous.json",
    "tests/fixtures/chromiumdash/unexpected-envelope.json",
    "scripts/README.md",
    "scripts/chromium_update.py",
    "state/README.md",
    "state/upstream.example.json",
    "state/upstream.json",
    "state/qualification-request.schema.json",
    "docs/ARCHITECTURE.md",
    "docs/CANDIDATE_DETECTION.md",
    "docs/SECURITY_MODEL.md",
    "docs/UPSTREAM_POLICY.md",
    "docs/PATCH_POLICY.md",
    "docs/UPDATE_PIPELINE.md",
    "docs/QUALIFICATION.md",
    "build/README.md",
    "updater/README.md",
    "release/README.md",
    ".github/workflows/static-validation.yml",
    ".github/codex/chromium-update-repair.md",
)

PatchNamePattern = re.compile(r"^(?P<Number>[0-9]{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.patch$")
def ReadSeries(SeriesPath: Path, Errors: List[str]) -> List[str]:
    try:
        Lines = SeriesPath.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as Error:
        Errors.append(f"cannot read patches/series: {Error}")
        return []

    Entries = [Line.strip() for Line in Lines if Line.strip() and not Line.lstrip().startswith("#")]
    Seen = set()
    for Entry in Entries:
        if Entry in Seen:
            Errors.append(f"duplicate patches/series entry: {Entry}")
        Seen.add(Entry)
    return Entries


def ValidatePatch(PatchPath: Path, Errors: List[str]) -> None:
    try:
        Content = PatchPath.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as Error:
        Errors.append(f"cannot read patch {PatchPath.name}: {Error}")
        return

    if not Content.strip():
        Errors.append(f"patch is empty: {PatchPath.name}")
        return
    RequiredMarkers = ("diff --git ", "--- ", "+++ ", "@@ ")
    MissingMarkers = [Marker.strip() for Marker in RequiredMarkers if Marker not in Content]
    if MissingMarkers:
        Errors.append(
            f"patch appears invalid: {PatchPath.name} missing " + ", ".join(MissingMarkers)
        )


def ValidatePatches(Root: Path, Errors: List[str]) -> int:
    PatchDirectory = Root / "patches"
    SeriesPath = PatchDirectory / "series"
    Entries = ReadSeries(SeriesPath, Errors) if SeriesPath.is_file() else []
    Listed = set(Entries)
    Existing = {Path.name for Path in PatchDirectory.glob("*.patch")} if PatchDirectory.is_dir() else set()

    for MissingName in sorted(Listed - Existing):
        Errors.append(f"listed patch does not exist: {MissingName}")
    for UnlistedName in sorted(Existing - Listed):
        Errors.append(f"unlisted patch file: {UnlistedName}")

    for Position, Entry in enumerate(Entries, start=1):
        if Path(Entry).name != Entry:
            Errors.append(f"series entry must be a filename, not a path: {Entry}")
            continue
        Match = PatchNamePattern.fullmatch(Entry)
        if Match is None:
            Errors.append(f"invalid patch filename: {Entry}")
        elif int(Match.group("Number")) != Position:
            Errors.append(
                f"patch order mismatch: entry {Position} must start with {Position:04d}-: {Entry}"
            )
        PatchPath = PatchDirectory / Entry
        if PatchPath.is_file():
            ValidatePatch(PatchPath, Errors)

    return len(Entries)


def ValidateState(Root: Path, Errors: List[str]) -> int:
    StateDirectory = Root / "state"
    JsonPaths = sorted(StateDirectory.rglob("*.json")) if StateDirectory.is_dir() else []
    for JsonPath in JsonPaths:
        try:
            Data = json.loads(JsonPath.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as Error:
            Errors.append(f"invalid JSON in {JsonPath.relative_to(Root)}: {Error}")
            continue
        if not isinstance(Data, dict):
            Errors.append(f"state JSON must contain an object: {JsonPath.relative_to(Root)}")
            continue
        if JsonPath.name in {"upstream.example.json", "upstream.json"}:
            try:
                ValidateProjectState(Data)
            except StateValidationError as Error:
                Errors.append(f"invalid project state in {JsonPath.relative_to(Root)}: {Error}")
    return len(JsonPaths)


def ValidateRequiredFiles(Root: Path, Errors: List[str]) -> None:
    for RelativePath in RequiredFiles:
        FullPath = Root / RelativePath
        if not FullPath.is_file():
            Errors.append(f"missing required file: {RelativePath}")
        elif FullPath.stat().st_size == 0:
            Errors.append(f"required file is empty: {RelativePath}")


def ParseArguments(Arguments: Sequence[str]) -> argparse.Namespace:
    Parser = argparse.ArgumentParser(description=__doc__)
    Parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the script's parent repository)",
    )
    return Parser.parse_args(Arguments)


def Main(Arguments: Iterable[str] = ()) -> int:
    Options = ParseArguments(list(Arguments))
    Root = Options.root.resolve()
    Errors: List[str] = []

    ValidateRequiredFiles(Root, Errors)
    PatchCount = ValidatePatches(Root, Errors)
    JsonCount = ValidateState(Root, Errors)

    print(f"Validated repository: {Root}")
    print(f"Ordered patches: {PatchCount}")
    print(f"State JSON files: {JsonCount}")
    print(f"Required files checked: {len(RequiredFiles)}")
    if Errors:
        print(f"STATIC validation failed with {len(Errors)} error(s):")
        for Error in Errors:
            print(f"  - {Error}")
        return 1

    print("STATIC validation passed. No higher qualification is implied.")
    return 0


if __name__ == "__main__":
    sys.exit(Main(sys.argv[1:]))
