#!/usr/bin/env python3
"""Offline regression tests for GitHub's NuGet inventory payload."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "snapshot", Path(__file__).with_name("generate-nuget-dependency-snapshot.py")
)
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.environment = {
            "GITHUB_REPOSITORY": "mictsi/SecureJournal",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "42",
        }
        for project in SNAPSHOT.PROJECTS:
            folder = self.root / project
            folder.mkdir()
            (folder / f"{project}.csproj").write_text("<Project />")
            self.write_lock(project, {})
        self.entries = {
            "Editor": {"type": "Direct", "resolved": "8.10.1", "dependencies": {"parser": "1.0.0"}},
            "Parser": {"type": "CentralTransitive", "requested": "[1.9.1, )", "resolved": "1.9.1"},
            "Helper": {"type": "Transitive", "resolved": "2.0.0"},
            "SecureJournal.Core": {"type": "Project"},
        }
        self.write_lock("SecureJournal.Web", self.entries)

    def write_lock(self, project, entries, version=2, framework="net10.0"):
        path = self.root / project / "packages.lock.json"
        path.write_text(json.dumps({"version": version, "dependencies": {framework: entries}}))

    def build(self):
        return SNAPSHOT.build_snapshot(self.root, self.environment, "2026-11-06T12:00:00Z")

    def test_maps_every_project_to_csproj_including_empty_core(self):
        snapshot = self.build()
        self.assertEqual(len(snapshot["manifests"]), 3)
        for project in SNAPSHOT.PROJECTS:
            path = f"{project}/{project}.csproj"
            self.assertEqual(snapshot["manifests"][path]["file"]["source_location"], path)
        self.assertEqual(snapshot["manifests"]["SecureJournal.Core/SecureJournal.Core.csproj"]["resolved"], {})
        self.assertEqual(snapshot["sha"], "a" * 40)
        self.assertEqual(snapshot["job"]["correlator"], "securejournal-nuget-lockfiles")

    def test_uses_resolved_versions_for_central_pins_and_edges(self):
        resolved = self.build()["manifests"]["SecureJournal.Web/SecureJournal.Web.csproj"]["resolved"]
        self.assertEqual(resolved["pkg:nuget/editor@8.10.1"]["relationship"], "direct")
        self.assertEqual(resolved["pkg:nuget/editor@8.10.1"]["dependencies"], ["pkg:nuget/parser@1.9.1"])
        self.assertEqual(resolved["pkg:nuget/parser@1.9.1"]["relationship"], "indirect")
        self.assertEqual(resolved["pkg:nuget/helper@2.0.0"]["relationship"], "indirect")
        self.assertEqual(len(resolved), 3)
        self.assertNotIn("pkg:nuget/securejournal.core", str(resolved))

    def test_test_project_dependencies_have_development_scope(self):
        self.write_lock("SecureJournal.Tests", self.entries)
        resolved = self.build()["manifests"]["SecureJournal.Tests/SecureJournal.Tests.csproj"]["resolved"]
        self.assertTrue(all(package["scope"] == "development" for package in resolved.values()))

    def test_purl_encodes_version_metadata_and_normalizes_package_name(self):
        self.assertEqual(SNAPSHOT.package_url("Example.Package", "1.2.3-beta.1+build.5"),
                         "pkg:nuget/example.package@1.2.3-beta.1%2Bbuild.5")

    def test_rejects_unsupported_lock_formats_and_unresolved_versions(self):
        cases = [
            ({}, 3, "net10.0"),
            ({}, 2, "net11.0"),
            ({"A": {"type": "Unknown", "resolved": "1.0.0"}}, 2, "net10.0"),
            ({"A": {"type": "Direct", "resolved": "[1.0.0, )"}}, 2, "net10.0"),
            ({"A": {"type": "Direct"}}, 2, "net10.0"),
            ({"A": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"Missing": "1.0.0"}}}, 2, "net10.0"),
        ]
        for entries, version, framework in cases:
            with self.subTest(entries=entries, version=version, framework=framework):
                self.write_lock("SecureJournal.Web", entries, version, framework)
                with self.assertRaises(ValueError):
                    self.build()

    def test_missing_project_or_lock_cannot_submit_partial_inventory(self):
        project = self.root / "SecureJournal.Tests" / "SecureJournal.Tests.csproj"
        project.unlink()
        with self.assertRaises(ValueError):
            self.build()
        project.write_text("<Project />")
        (project.parent / "packages.lock.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.build()

    def test_empty_inventory_is_rejected(self):
        self.write_lock("SecureJournal.Web", {})
        with self.assertRaisesRegex(ValueError, "empty dependency inventory"):
            self.build()

    def test_invalid_commit_identity_is_rejected(self):
        self.environment["GITHUB_SHA"] = "HEAD"
        with self.assertRaisesRegex(ValueError, "GITHUB_SHA"):
            self.build()


if __name__ == "__main__":
    unittest.main()
