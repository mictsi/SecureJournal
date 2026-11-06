#!/usr/bin/env python3
"""Generate a GitHub dependency snapshot from locked NuGet resolutions.

Run after a successful --locked-mode restore. This intentionally supports this
repository's lockfile v2 / net10.0 shape and fails on unsupported formats.
It reads JSON only; submission and credentials stay in the workflow.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.parse import quote


PROJECTS = ("SecureJournal.Core", "SecureJournal.Web", "SecureJournal.Tests")
PACKAGE_TYPES = {"Direct", "Transitive", "CentralTransitive"}
PACKAGE_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
PACKAGE_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?\Z")


def package_url(name, version):
    if not isinstance(name, str) or not PACKAGE_NAME.fullmatch(name):
        raise ValueError(f"Invalid NuGet package name: {name!r}")
    if not isinstance(version, str) or not PACKAGE_VERSION.fullmatch(version):
        raise ValueError(f"Invalid resolved version for {name}: {version!r}")
    return f"pkg:nuget/{quote(name.lower(), safe='')}@{quote(version, safe='')}"


def project_manifest(root, project):
    project_path = Path(project) / f"{project}.csproj"
    lock_path = Path(project) / "packages.lock.json"
    if not (root / project_path).is_file():
        raise ValueError(f"Missing project: {project_path}")
    lock = json.loads((root / lock_path).read_text(encoding="utf-8"))
    if not isinstance(lock, dict) or lock.get("version") != 2:
        raise ValueError(f"Unsupported NuGet lockfile version: {lock_path}")
    frameworks = lock.get("dependencies")
    if not isinstance(frameworks, dict) or set(frameworks) != {"net10.0"}:
        raise ValueError(f"Expected only net10.0 in {lock_path}")
    entries = frameworks["net10.0"]
    if not isinstance(entries, dict):
        raise ValueError(f"Invalid dependencies in {lock_path}")

    names = {}
    urls = {}
    for name, entry in entries.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            raise ValueError(f"Invalid package entry in {lock_path}")
        key = name.lower()
        if key in names:
            raise ValueError(f"Duplicate NuGet package name: {name}")
        names[key] = name
        kind = entry.get("type")
        if kind == "Project":
            continue
        if kind not in PACKAGE_TYPES:
            raise ValueError(f"Unsupported package type for {name}: {kind!r}")
        urls[key] = package_url(name, entry.get("resolved"))

    resolved = {}
    for key, url in sorted(urls.items()):
        entry = entries[names[key]]
        dependencies = entry.get("dependencies", {})
        if not isinstance(dependencies, dict):
            raise ValueError(f"Invalid dependency edges for {names[key]}")
        child_urls = []
        for child in dependencies:
            if not isinstance(child, str) or child.lower() not in names:
                raise ValueError(f"Unresolved dependency edge from {names[key]}: {child!r}")
            # Project references are local code, not packages available on NuGet.
            if child.lower() in urls:
                child_urls.append(urls[child.lower()])
        resolved[url] = {
            "package_url": url,
            "relationship": "direct" if entry["type"] == "Direct" else "indirect",
            "dependencies": sorted(set(child_urls)),
        }
        if project == "SecureJournal.Tests":
            resolved[url]["scope"] = "development"

    location = project_path.as_posix()
    return {
        "name": location,
        # Match GitHub's csproj manifest so fresh data supersedes stale static data.
        "file": {"source_location": location},
        "metadata": {"lockfile": lock_path.as_posix(), "target_framework": "net10.0"},
        "resolved": resolved,
    }


def build_snapshot(root, environment, scanned=None):
    repository = environment["GITHUB_REPOSITORY"]
    sha = environment["GITHUB_SHA"]
    ref = environment["GITHUB_REF"]
    run_id = environment["GITHUB_RUN_ID"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid GITHUB_REPOSITORY")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
        raise ValueError("Invalid GITHUB_SHA")
    if not ref.startswith("refs/heads/") or not run_id.isdigit():
        raise ValueError("Snapshot requires a branch ref and numeric run ID")
    manifests = [project_manifest(root, project) for project in PROJECTS]
    if not any(manifest["resolved"] for manifest in manifests):
        raise ValueError("Refusing to submit an empty dependency inventory")
    return {
        "version": 0,
        "sha": sha,
        "ref": ref,
        "job": {
            "id": run_id,
            "correlator": "securejournal-nuget-lockfiles",
            "html_url": f"https://github.com/{repository}/actions/runs/{run_id}",
        },
        "detector": {
            "name": "SecureJournal NuGet lockfiles",
            "version": "1.0.0",
            "url": f"https://github.com/{repository}/blob/{sha}/scripts/generate-nuget-dependency-snapshot.py",
        },
        "scanned": scanned or datetime.now(timezone.utc).isoformat(),
        "manifests": {manifest["name"]: manifest for manifest in manifests},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = build_snapshot(args.root, os.environ)
    args.output.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    count = sum(len(manifest["resolved"]) for manifest in snapshot["manifests"].values())
    print(f"Prepared {len(snapshot['manifests'])} project manifests with {count} package resolutions.")


if __name__ == "__main__":
    main()
