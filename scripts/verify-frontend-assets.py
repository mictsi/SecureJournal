#!/usr/bin/env python3
"""Verify pinned frontend assets; optionally restage them from trusted local sources.

    python3 scripts/verify-frontend-assets.py
    python3 scripts/verify-frontend-assets.py --sync-tinymce
    python3 scripts/verify-frontend-assets.py --sync-sekura /path/to/SekuraDesignMCP

TinyMCE is restored by dotnet; its automatic copy target is deliberately excluded
because it would overwrite the patched sanitizer. Explicit sync rebuilds the
sanitizer, updates this manifest, and preserves custom language/module files.
Sekura is copied from generated artifacts of the pinned source checkout, with
the recorded hashes checked before copying. This script performs no network requests.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "SecureJournal.Web" / "wwwroot" / "lib"
MANIFEST = ROOT / "scripts" / "frontend-assets.json"


def files_with_hashes(directory):
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def tinymce_version():
    for filename in ("Directory.Packages.props", "SecureJournal.Web/SecureJournal.Web.csproj"):
        path = ROOT / filename
        if not path.exists():
            continue
        for element in ET.parse(path).getroot().iter():
            if element.get("Include", "").lower() == "tinymce":
                version = element.get("Version")
                if version:
                    return version
    raise ValueError("TinyMCE version is missing from the project or central package manifest.")


def sync_tinymce(manifest, packages):
    version = tinymce_version()
    package = packages / "tinymce" / version.lower()
    source = package / "content" / "scripts" / "tinymce"
    if not (source / "tinymce.min.js").is_file():
        raise ValueError(f"Restore TinyMCE {version} with dotnet restore before synchronization.")
    target = LIB / "tinymce"
    source_files = files_with_hashes(source)
    previous = manifest["tinymce"]
    # Only remove obsolete upstream-owned files. Host language/module additions
    # are retained and covered by their own recorded hashes after synchronization.
    for name in previous.get("packageFiles", []):
        if name not in source_files and not name.startswith("langs/"):
            (target / name).unlink(missing_ok=True)
    for name in source_files:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, destination)
    environment = dict(os.environ, NUGET_PACKAGES=str(packages.resolve()))
    subprocess.run(["node", str(ROOT / "scripts/frontend/rebuild-tinymce.mjs")],
                   check=True, env=environment)
    build_inputs = json.loads((ROOT / "scripts/frontend/build-inputs.json").read_text())
    manifest["tinymce"] = {
        "version": version,
        "source": f"https://www.nuget.org/packages/TinyMCE/{version}",
        "packageSha512": (package / f"tinymce.{version.lower()}.nupkg.sha512").read_text().strip(),
        "packageFiles": sorted(source_files),
        "preservedFiles": sorted(set(files_with_hashes(target)) - set(source_files)),
        "sanitizerRebuild": build_inputs,
        "files": files_with_hashes(target),
    }


def sync_sekura(manifest, source):
    entry = manifest["sekura"]
    commit = entry["sourceCommit"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Sekura sourceCommit must be a full Git commit hash.")

    def from_commit(path):
        return subprocess.check_output(["git", "-C", str(source), "show", f"{commit}:{path}"])

    if json.loads(from_commit("package.json"))["version"] != entry["version"]:
        raise ValueError("Sekura source commit and manifest version disagree.")
    if subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"]).decode().strip() != commit:
        raise ValueError("Build Sekura from the pinned commit before synchronizing.")
    for source_path, name in (
        ("dist-css/sekura.css", "sekura.css"),
        ("dist-js/sekura.iife.min.js", "sekura.iife.min.js"),
        ("LICENSE", "LICENSE"),
    ):
        data = (source / source_path).read_bytes()
        expected = entry.get("files", {}).get(name)
        if expected and hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"Sekura generated artifact differs from the pinned release: {name}")
        (LIB / "sekura" / name).write_bytes(data)
    entry["files"] = files_with_hashes(LIB / "sekura")


def verify(manifest):
    errors = []
    if manifest["tinymce"]["version"] != tinymce_version():
        errors.append("TinyMCE package version differs from vendored assets; run --sync-tinymce.")
    for library in ("tinymce", "sekura"):
        entry = manifest[library]
        expected = entry["files"]
        actual = files_with_hashes(LIB / library)
        for name in sorted(set(actual) | set(expected)):
            if actual.get(name) != expected.get(name):
                errors.append(f"{library}/{name}: missing, extra, or changed file")
        print(f"{library} {entry['version']}: {len(actual)} files checked")
    banner = (LIB / "tinymce" / "tinymce.min.js").read_text(encoding="utf-8")[:400]
    if f"TinyMCE {manifest['tinymce']['version']} with official DOMPurify " not in banner:
        errors.append("TinyMCE runtime banner differs from the pinned version.")
    build_inputs = json.loads((ROOT / "scripts/frontend/build-inputs.json").read_text())
    if manifest["tinymce"].get("sanitizerRebuild") != build_inputs:
        errors.append("TinyMCE sanitizer build inputs changed; regenerate and review the bundle.")
    for plugin in build_inputs["omittedPlugins"]:
        if (LIB / "tinymce" / "plugins" / plugin).exists():
            errors.append(f"Unused plugin {plugin} was restored; disable the NuGet copy target.")
    # Product styles must continue to resolve against the updated design system.
    css = (LIB / "sekura" / "sekura.css").read_text(encoding="utf-8")
    available = set(re.findall(r"(--sk-[\w-]+)\s*:", css))
    for path in (ROOT / "SecureJournal.Web").rglob("*"):
        if not path.is_file() or path.suffix not in (".css", ".razor", ".js"):
            continue
        if any(part in ("lib", "obj", "bin") for part in path.relative_to(ROOT).parts):
            continue
        text = path.read_text(encoding="utf-8-sig")
        local = set(re.findall(r"(--sk-[\w-]+)\s*:", text))
        for token in sorted(set(re.findall(r"var\((--sk-[\w-]+)", text)) - available - local):
            errors.append(f"{path.relative_to(ROOT)}: unknown semantic token {token}")
    if errors:
        raise ValueError("\n".join(errors))
    print("Frontend asset integrity, pinned versions, and semantic tokens verified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync-tinymce", action="store_true")
    parser.add_argument("--sync-sekura", type=Path, metavar="SOURCE_REPOSITORY")
    parser.add_argument("--nuget-packages", type=Path,
                        default=Path(os.environ.get("NUGET_PACKAGES", str(Path.home() / ".nuget/packages"))))
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if args.sync_tinymce:
        sync_tinymce(manifest, args.nuget_packages)
    if args.sync_sekura:
        sync_sekura(manifest, args.sync_sekura)
    if args.sync_tinymce or args.sync_sekura:
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    verify(manifest)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Frontend verification failed: {error}", file=sys.stderr)
        sys.exit(1)
