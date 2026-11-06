#!/usr/bin/env python3
"""Exercise clean application, idempotence and fail-closed dependency checks."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("boringssl_recipe", ROOT / "scripts/dependencies/boringssl.py")
RECIPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECIPE)


class RecipeTest(unittest.TestCase):
    def test_integrity_and_reapplication(self):
        with tempfile.TemporaryDirectory(prefix="solaris-recipe-") as temp:
            root = Path(temp).resolve(); project = root / "project"; source = root / "upstream"; output = root / "patched"
            (project / "dependencies").mkdir(parents=True); source.mkdir()
            (source / "hello.txt").write_text("upstream\n")
            patch = project / "change.patch"
            patch.write_text("--- a/hello.txt\n+++ b/hello.txt\n@@ -1 +1 @@\n-upstream\n+patched\n")
            lock = {"source_tree_sha256": RECIPE.tree_hash(source), "patches": [
                {"path": "change.patch", "sha256": hashlib.sha256(patch.read_bytes()).hexdigest()}]}
            lock_path = project / "dependencies/lock.json"
            lock_path.write_text(json.dumps({"boringssl": lock}))
            RECIPE.prepare(project, source, output)
            self.assertEqual((source / "hello.txt").read_text(), "upstream\n")
            self.assertEqual((output / "hello.txt").read_text(), "patched\n")
            modified = (output / "hello.txt").stat().st_mtime_ns
            RECIPE.prepare(project, source, output)
            self.assertEqual((output / "hello.txt").stat().st_mtime_ns, modified)
            (output / "hello.txt").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "patched.*modified"):
                RECIPE.prepare(project, source, output)
            (output / "hello.txt").write_text("patched\n")
            original = patch.read_bytes(); patch.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "patch checksum"):
                RECIPE.prepare(project, source, output)
            patch.write_bytes(original)
            (source / "hello.txt").write_text("wrong version\n")
            with self.assertRaisesRegex(ValueError, "pristine"):
                RECIPE.prepare(project, source, output)
            (source / "hello.txt").write_text("upstream\n")
            # A changed series always starts from pristine, not already patched text.
            patch.write_bytes(original.replace(b"+patched\n", b"+updated\n"))
            lock["patches"][0]["sha256"] = hashlib.sha256(patch.read_bytes()).hexdigest()
            lock_path.write_text(json.dumps({"boringssl": lock}))
            RECIPE.prepare(project, source, output)
            self.assertEqual((output / "hello.txt").read_text(), "updated\n")
            # A correctly hashed but inapplicable patch must not destroy the last tree.
            patch.write_bytes(original.replace(b"-upstream\n", b"-missing\n"))
            lock["patches"][0]["sha256"] = hashlib.sha256(patch.read_bytes()).hexdigest()
            lock_path.write_text(json.dumps({"boringssl": lock}))
            with self.assertRaises(RECIPE.subprocess.CalledProcessError):
                RECIPE.prepare(project, source, output)
            self.assertEqual((output / "hello.txt").read_text(), "updated\n")


if __name__ == "__main__":
    unittest.main()
