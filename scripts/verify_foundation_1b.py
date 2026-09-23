#!/usr/bin/env python3
"""Finish the reviewed exact-revision Windows build-policy gate (not runtime)."""

import argparse
import json
from pathlib import Path

import real_patch_qualify as Patch
import verify_build_policy as Verify
from build_policy import LoadManifest, ManifestDigest


# Semantic consumers below were reviewed at this revision. A new upstream SHA
# requires review, not an automatic assertion that the old interpretation holds.
ReviewedSha = "a654841425914cbb703a2931e07b70a83aedbafd"
ProductPrefixes = (
    "//chrome/browser/compose:", "//chrome/browser/ui/views/compose:",
    "//chrome/browser/ui/webui/compose:", "//chrome/browser/resources/compose:",
)
Headers = {
    "components/compose/buildflags.h": {"ENABLE_COMPOSE": 0},
    "rlz/buildflags/buildflags.h": {"ENABLE_RLZ": 0},
    "build/branding_buildflags.h": {"GOOGLE_CHROME_BRANDING": 0},
    "chrome/browser/buildflags.h": {"ENABLE_UPDATER": 0, "ENABLE_UPDATE_NOTIFICATIONS": 0},
    "components/safe_browsing/buildflags.h": {
        "SAFE_BROWSING_AVAILABLE": 1, "SAFE_BROWSING_DB_LOCAL": 1,
        "SAFE_BROWSING_DB_REMOTE": 0, "SAFE_BROWSING_DOWNLOAD_PROTECTION": 1},
    "google_apis/buildflags.h": {"SUPPORT_EXTERNAL_GOOGLE_API_KEY": 0},
}


def CheckGraph(Targets, Dependencies):
    for Text in (Targets, Dependencies):
        if any(Line.strip().startswith(ProductPrefixes) for Line in Text.splitlines()):
            raise Verify.VerificationError("Compose product target remains in generated graph")
    return sorted({Line.strip() for Line in Dependencies.splitlines()
                   if "/compose/" in Line or "/compose:" in Line})


def CheckHeader(Text, Expected):
    for Name, Value in Expected.items():
        if f"#define BUILDFLAG_INTERNAL_{Name}() ({Value})" not in Text:
            raise Verify.VerificationError("Generated policy buildflag mismatch")


def Collect(Options, Report):
    Build = json.loads(Options.build_evidence.read_text(encoding="utf-8"))
    Evidence = json.loads(Options.patch_evidence.read_text(encoding="utf-8"))
    Patch.ValidateEvidence(Evidence)
    if (Build.get("candidate") != Evidence["candidate"] or
            Evidence["candidate"]["chromium_sha"] != ReviewedSha or
            Build.get("gn_configuration") != "MATCH" or
            Build.get("patch_evidence_sha256") != Verify.Digest(Options.patch_evidence.read_bytes())):
        raise Verify.VerificationError("Reviewed source and successful GN evidence required")
    Root = Path(__file__).resolve().parents[1]
    Git, _ = Patch.Engine.FindGit(Patch.Engine.DefaultCommandRunner)
    Patches, SeriesHash = Patch.Engine.ReadPatchSeries(Root, Git, Patch.Engine.DefaultCommandRunner)
    CurrentPatches = [{"name": Item.Name, "sha256": Item.Sha256,
                       "affected_paths": list(Item.AffectedPaths)} for Item in Patches]
    if (SeriesHash != Evidence["inputs"]["patch_series_sha256"] or
            CurrentPatches != Evidence["inputs"]["patches"]):
        raise Verify.VerificationError("Canonical patch series differs from integrated series")
    Manifest = LoadManifest(Root / "policy/build-policy.json", Root / "policy/network-service-policy.json",
                            RequireCanonical=True)
    if (Build["manifest_sha256"] != ManifestDigest(Manifest) or
            Build["args_gn"] != Verify.BuildArguments(Manifest) or
            [Item["name"] for Item in Build["settings"]] != [Item["name"] for Item in Manifest["settings"]] or
            any(Item["result"] != "MATCH" for Item in Build["settings"])):
        raise Verify.VerificationError("Build-policy evidence is stale or mismatched")
    Source = Path(Build["source"])
    Output = Path(Build["output"])
    if Output.parent != Source / "out" or (Output / "args.gn").read_text() != Build["args_gn"]:
        raise Verify.VerificationError("Build output or inputs changed")
    Patch.CheckIntegration(Source, Evidence)
    import os
    if Verify.EnvironmentFindings(os.environ) or any(Verify.SavedEnvironmentFindings().values()):
        raise Verify.VerificationError("Credential/build environment override detected")
    Gn = Source / "buildtools/win/gn.exe"
    if Verify.Digest(Gn.read_bytes()) != Build["gn_sha256"]:
        raise Verify.VerificationError("GN tool changed")
    Commands = Report["commands"]
    Relative = Output.relative_to(Source).as_posix()
    Inventory = json.loads(Verify.Run([Gn, "args", Relative, "--list", "--json"], Source, Commands))
    Results = Verify.CompareArguments(Manifest, Inventory)
    if any(Item["result"] != "MATCH" for Item in Results):
        raise Verify.VerificationError("Current effective GN values differ")
    Targets = Verify.Run([Gn, "ls", Relative], Source, Commands)
    Dependencies = Verify.Run([Gn, "desc", Relative, "//chrome:chrome", "deps", "--all"], Source, Commands)
    Retained = CheckGraph(Targets, Dependencies)
    Defines = Verify.Run([Gn, "desc", Relative, "//google_apis:google_apis", "defines"], Source, Commands)
    # Fail on any global key define; never store unexpected credential values.
    if any(Verify.CredentialPattern.fullmatch(Line.strip().split("=", 1)[0]) or
           Line.strip().startswith("USE_OFFICIAL_GOOGLE_API_KEYS") for Line in Defines.splitlines()):
        raise Verify.VerificationError("Global credential define supplied to google_apis")
    HeaderHashes = {}
    for Name, Expected in Headers.items():
        File = Output / "gen" / Name
        CheckHeader(File.read_text(), Expected)
        HeaderHashes[Name] = Verify.Digest(File.read_bytes())
    SourceHashes = {Name: Verify.Digest((Source / Name).read_bytes()) for Name in (
        "google_apis/BUILD.gn", "google_apis/default_api_keys-inc.cc", "google_apis/default_api_keys.h",
        "google_apis/api_key_cache.cc", "components/compose/features.gni",
        "components/lens/features.gni", "components/safe_browsing/buildflags.gni")}
    Patch.CheckIntegration(Source, Evidence)
    Report.update(status="PASS", candidate=Evidence["candidate"], settings=Results,
                  manifest_sha256=Build["manifest_sha256"],
                  build_evidence_sha256=Verify.Digest(Options.build_evidence.read_bytes()),
                  patch_evidence_sha256=Verify.Digest(Options.patch_evidence.read_bytes()),
                  production_graph_sha256=Verify.Digest(Dependencies.encode()),
                  all_targets_sha256=Verify.Digest(Targets.encode()),
                  generated_headers=HeaderHashes, reviewed_sources=SourceHashes,
                  retained_compose_support_targets=Retained,
                  global_credential_defines="ABSENT", environment="NO_NONEMPTY_OVERRIDES",
                  lens="COMPILED_ALLOWED; USER_INITIATED policy only; runtime/disclosure UNVERIFIED",
                  credential_semantics="Unset-token sentinel is not a supplied credential. Runtime overrides unqualified.")
    for Name, Text in (("all-targets.txt", Targets), ("production-deps.txt", Dependencies)):
        (Options.evidence.parent / Name).write_text(Text, encoding="utf-8", newline="\n")


def Main():
    Parser = argparse.ArgumentParser(description=__doc__)
    for Name in ("build-evidence", "patch-evidence", "evidence"):
        Parser.add_argument("--" + Name, type=Path, required=True)
    Options = Parser.parse_args()
    Report = {"schema_version": 1, "stage": "BUILD-POLICY", "scope": "WINDOWS_X64_BUILD_ONLY",
              "status": "FAIL", "evidence_level": "PATCH-APPLY", "runtime_verified": False,
              "qualification_promoted": False, "commands": []}
    with Options.evidence.open("x", encoding="utf-8") as Handle:
        try:
            Collect(Options, Report)
        except Exception as Error:
            Report["failure"] = str(Error) if isinstance(Error, Verify.VerificationError) else type(Error).__name__
        json.dump(Report, Handle, indent=2, sort_keys=True)
        Handle.write("\n")
    print(f"[Securium:Foundation1B] {Report['status']}; build only, runtime unqualified")
    return 0 if Report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(Main())
