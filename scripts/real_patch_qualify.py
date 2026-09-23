#!/usr/bin/env python3
"""Real Chromium identity adapter for the existing strict patch engine."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import patch_qualify as Engine


ChromiumOrigin = "https://chromium.googlesource.com/chromium/src.git"


def Git(Source, *Arguments):
    Result = Engine.DefaultCommandRunner(["git", *Arguments], Source)
    if Result.returncode:
        raise Engine.StageFailure(Engine.FailureClass.InvalidSource,
                                  "Git identity/worktree operation failed",
                                  Diagnostics=Result.stderr)
    return Result.stdout.strip()


def CheckIdentity(Source, Candidate, RequireClean=True):
    if Engine.IsReparsePoint(Source) or Path(Git(Source, "rev-parse", "--show-toplevel")).resolve() != Source.resolve():
        raise Engine.StageFailure(Engine.FailureClass.InvalidSource, "Source must be a real Git root")
    Head = Git(Source, "rev-parse", "HEAD")
    Origin = Git(Source, "remote", "get-url", "origin")
    if Head != Candidate["chromium_sha"] or Origin != ChromiumOrigin:
        raise Engine.StageFailure(Engine.FailureClass.InvalidSource, "Chromium SHA or origin mismatch")
    if RequireClean and Git(Source, "status", "--porcelain", "--untracked-files=normal"):
        raise Engine.StageFailure(Engine.FailureClass.InvalidSource, "Chromium root is dirty")
    Sparse = Engine.DefaultCommandRunner(["git", "config", "--bool", "--get", "core.sparseCheckout"], Source)
    if Sparse.returncode not in (0, 1) or Sparse.stdout.strip() == "true":
        raise Engine.StageFailure(Engine.FailureClass.InvalidSource, "Sparse root is not supported")
    for Name in (".gn", "DEPS", "chrome/VERSION", "google_apis/BUILD.gn"):
        if not (Source / Name).is_file():
            raise Engine.StageFailure(Engine.FailureClass.InvalidSource, "Chromium marker missing")
    Version = dict(Line.split("=", 1) for Line in (Source / "chrome/VERSION").read_text().splitlines())
    ActualVersion = ".".join(Version[Name] for Name in ("MAJOR", "MINOR", "BUILD", "PATCH"))
    if ActualVersion != Candidate["chrome_version"]:
        raise Engine.StageFailure(Engine.FailureClass.InvalidSource, "Chromium version mismatch")
    return {"kind": "chromium_git", "origin": Origin, "head": Head,
            "git_tree": Git(Source, "rev-parse", "HEAD^{tree}"),
            "chrome_version": ActualVersion, "clean_before_integration": RequireClean}


def ValidateEvidence(Report):
    if (Report.get("synthetic") is not False or Report.get("engine_validation") != "REAL_CHROMIUM"
            or Report.get("stage") != "PATCH-APPLY" or Report.get("schema_version") != 1):
        raise ValueError("Not real Chromium PATCH-APPLY evidence")
    if Report.get("result") not in ("PASS", "FAIL"):
        raise ValueError("Invalid result")
    if Report["result"] == "PASS":
        Identity = Report["source_identity"]
        if (Identity["kind"] != "chromium_git" or Identity["origin"] != ChromiumOrigin
                or Identity["head"] != Report["candidate"]["chromium_sha"]
                or Identity["clean_before_integration"] is not True
                or Report["execution"]["integration_tree_status"] != "COMPLETE"
                or Report["execution"]["failure_class"] is not None):
            raise ValueError("Incomplete source/application evidence")
        Names = [Patch["name"] for Patch in Report["inputs"]["patches"]]
        if Report["execution"]["applied_patches"] != Names or Report["execution"]["attempted_patches"] != Names:
            raise ValueError("Patch series did not complete in order")
        for Hash in (Report["integration_diff_sha256"], Report["inputs"]["patch_series_sha256"],
                     Report["inputs"]["qualification_request_sha256"],
                     *(Patch["sha256"] for Patch in Report["inputs"]["patches"])):
            if not isinstance(Hash, str) or Engine.ShaPattern.fullmatch(Hash) is None:
                raise ValueError("Missing evidence digest")


def CheckIntegration(Source, Report):
    """Bind follow-on gates to this exact integration, including untracked files."""
    ValidateEvidence(Report)
    if Report["result"] != "PASS":
        raise ValueError("PATCH-APPLY did not pass")
    CheckIdentity(Source, Report["candidate"], RequireClean=False)
    Actual = Engine.Sha256Bytes(Git(Source, "diff", "--binary", "HEAD").encode())
    if Actual != Report["integration_diff_sha256"] or Git(Source, "diff", "--cached", "--name-only"):
        raise ValueError("Integration diff changed")
    Allowed = set(Report["integration_files"])
    Untracked = set(filter(None, Git(Source, "ls-files", "--others", "--exclude-standard", "-z").split("\0")))
    if not Untracked <= Allowed:
        raise ValueError("Unexpected untracked integration content")
    for Name, Expected in Report["integration_files"].items():
        File = Engine.EnsureContained(Source, Name)
        if Engine.IsReparsePoint(File):
            raise ValueError("Redirected integration file")
        Actual = Engine.Sha256File(File) if File.is_file() else None
        if Actual != Expected:
            raise ValueError("Integration file changed")


def Run(RequestPath, Source, Repository, Workspace):
    Report = Engine.BaseEvidence()
    Report.update(schema_version=1, synthetic=False, engine_validation="REAL_CHROMIUM",
                  integration_files={}, integration_diff_sha256=None,
                  started_utc=datetime.now(timezone.utc).isoformat())
    Created = False
    try:
        if Workspace.exists() or Engine.PathsOverlap(Workspace, Source) or Engine.PathsOverlap(Workspace, Repository):
            raise Engine.StageFailure(Engine.FailureClass.InvalidWorkspace, "New nonoverlapping workspace required")
        Workspace.mkdir(parents=True, exist_ok=False)
        Created = True
        Request, RequestHash = Engine.LoadQualificationRequest(RequestPath)
        Report["candidate"] = Request["candidate"]
        Report["inputs"]["qualification_request_sha256"] = RequestHash
        Report["source_identity"] = CheckIdentity(Source, Request["candidate"])
        Executable, Version = Engine.FindGit(Engine.DefaultCommandRunner)
        Patches, SeriesHash = Engine.ReadPatchSeries(Repository, Executable, Engine.DefaultCommandRunner)
        Report["inputs"].update(git_version=Version, patch_series_sha256=SeriesHash,
            patches=[{"name": P.Name, "sha256": P.Sha256, "affected_paths": list(P.AffectedPaths)} for P in Patches])
        Integration = Workspace / "integration"
        Git(Source, "worktree", "add", "--detach", str(Integration.resolve()), Request["candidate"]["chromium_sha"])
        CheckIdentity(Integration, Request["candidate"])
        Names = Git(Integration, "ls-files", "-z").split("\0")
        Files = [Engine.TreeEntry(Name, Integration / Name) for Name in Names if Name]
        Directories = sorted({Parent.as_posix() for Name in Names if Name
                              for Parent in Path(Name).parents if Parent.as_posix() != "."})
        Plan = Engine.BuildMaterializationPlan(Repository, Files, Directories)
        Report["inputs"]["downstream_files"] = [{"path": Item.RelativePath, "sha256": Item.Sha256} for Item in Plan]
        # Inspect every patch path before Git can traverse it. No reparse targets.
        for Patch in Patches:
            for Name in Patch.AffectedPaths:
                Target = Engine.EnsureContained(Integration, Name)
                for PathValue in (Target, *Target.parents):
                    if PathValue == Integration.parent:
                        break
                    if Engine.IsReparsePoint(PathValue):
                        raise Engine.StageFailure(Engine.FailureClass.UnsafePath, "Patch path is redirected")
        Report["execution"]["integration_tree_status"] = "PREPARED"
        Engine.MaterializeDownstream(Integration, Plan)
        Engine.ApplyPatches(Integration, Patches, Executable, Engine.DefaultCommandRunner, Report)
        Changed = sorted({Name for Patch in Patches for Name in Patch.AffectedPaths} |
                         {Item.RelativePath for Item in Plan})
        Report["integration_files"] = {Name: Engine.Sha256File(Integration / Name)
                                       if (Integration / Name).is_file() else None for Name in Changed}
        Report["integration_diff_sha256"] = Engine.Sha256Bytes(
            Git(Integration, "diff", "--binary", "HEAD").encode())
        CheckIdentity(Source, Request["candidate"])
        Report["result"] = "PASS"
        Report["execution"]["integration_tree_status"] = "COMPLETE"
    except Engine.StageFailure as Error:
        Engine.SetFailure(Report, Error)
    except Exception as Error:
        Engine.SetFailure(Report, Engine.StageFailure(Engine.FailureClass.InternalError,
                          f"{type(Error).__name__}: {Error}"))
    Report["ended_utc"] = datetime.now(timezone.utc).isoformat()
    try:
        ValidateEvidence(Report)
        if Created:
            Engine.AtomicWriteJson(Workspace / "evidence.json", Report)
    except Exception as Error:
        Engine.SetFailure(Report, Engine.StageFailure(Engine.FailureClass.EvidenceWriteFailed, str(Error)))
    return Report


def Main():
    Parser = argparse.ArgumentParser(description=__doc__)
    for Name in ("request", "source", "repository-root", "workspace"):
        Parser.add_argument("--" + Name, type=Path, required=True)
    Options = Parser.parse_args()
    Report = Run(Options.request, Options.source.resolve(), Options.repository_root.resolve(), Options.workspace.resolve())
    print(json.dumps(Report, indent=2, sort_keys=True))
    return 0 if Report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(Main())
