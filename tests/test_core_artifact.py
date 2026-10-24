"""Offline security tests for private core transport and its workflow wiring."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import core_artifact as artifact


class PrivateCoreTransportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "build"
        self.source.mkdir()
        self.files = {name: b"PRIVATE-CORE-PROBE:" + name.encode() + os.urandom(256)
                      for name in artifact.HASH_FIELDS}
        manifest = {"repository": "noorelmostafa11-pixel/VPN-Core", "revision": "a" * 40,
                    "source_modified": False}
        manifest.update({field: hashlib.sha256(self.files[name]).hexdigest()
                         for name, field in artifact.HASH_FIELDS.items()})
        self.files["core-build.json"] = json.dumps(manifest).encode()
        for name, data in self.files.items():
            (self.source / name).write_bytes(data)
        self.key = os.urandom(32)
        self.aad = artifact.context("noorelmostafa11-pixel/VPN-Nodes", "12345")
        self.encrypted = self.root / "core.bundle"
        self.output = self.root / "restored"

    def seal(self):
        artifact.seal(self.source, self.encrypted, self.key, self.aad)

    def test_all_tools_and_original_provenance_survive_encrypted_handoff(self):
        self.seal()
        self.assertNotIn(b"PRIVATE-CORE-PROBE", self.encrypted.read_bytes())
        self.assertNotIn(b"core-build.json", self.encrypted.read_bytes())
        artifact.unseal(self.encrypted, self.output, self.key, self.aad)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, self.files)

    def test_repeated_encryption_uses_fresh_nonce(self):
        self.seal()
        second = self.root / "second.bundle"
        artifact.seal(self.source, second, self.key, self.aad)
        self.assertNotEqual(self.encrypted.read_bytes(), second.read_bytes())

    def test_wrong_key_or_other_run_cannot_decrypt_or_create_output(self):
        self.seal()
        for key, aad in ((os.urandom(32), self.aad),
                         (self.key, artifact.context("noorelmostafa11-pixel/VPN-Nodes", "12346"))):
            with self.subTest(aad=aad), self.assertRaises(ValueError):
                artifact.unseal(self.encrypted, self.output, key, aad)
            self.assertFalse(self.output.exists())

    def test_tampered_ciphertext_and_truncation_fail_closed(self):
        self.seal()
        original = self.encrypted.read_bytes()
        for bad in (original[:-1], original[:12], original[:-1] + bytes([original[-1] ^ 1])):
            self.encrypted.write_bytes(bad)
            with self.assertRaises(ValueError):
                artifact.unseal(self.encrypted, self.output, self.key, self.aad)
            self.assertFalse(self.output.exists())

    def test_unencrypted_zip_is_not_a_fallback(self):
        with zipfile.ZipFile(self.encrypted, "w") as bundle:
            for name, data in self.files.items():
                bundle.writestr(name, data)
        with self.assertRaises(ValueError):
            artifact.unseal(self.encrypted, self.output, self.key, self.aad)

    def test_extra_source_files_and_subdirectories_cannot_leak(self):
        for name in ("private-source.go", ".git"):
            extra = self.source / name
            extra.write_text("not an allowed artifact")
            with self.assertRaises(ValueError):
                self.seal()
            extra.unlink()
        (self.source / "directory").mkdir()
        with self.assertRaises(ValueError):
            self.seal()

    def test_changed_tool_bytes_fail_manifest_integrity(self):
        for name in artifact.HASH_FIELDS:
            with self.subTest(name=name):
                (self.source / name).write_bytes(b"substituted")
                with self.assertRaises(ValueError):
                    self.seal()
                (self.source / name).write_bytes(self.files[name])

    def test_authenticated_archive_cannot_escape_destination(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as bundle:
            for name, data in self.files.items():
                bundle.writestr("../escaped" if name == "vpn-core" else name, data)
        nonce = os.urandom(12)
        self.encrypted.write_bytes(artifact.MAGIC + nonce + AESGCM(self.key).encrypt(nonce, buf.getvalue(), self.aad))
        with self.assertRaises(ValueError):
            artifact.unseal(self.encrypted, self.output, self.key, self.aad)
        self.assertFalse((self.root / "escaped").exists())

    def test_existing_destination_cannot_be_overwritten(self):
        self.seal()
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_text("keep")
        with self.assertRaises(ValueError):
            artifact.unseal(self.encrypted, self.output, self.key, self.aad)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_key_validation_does_not_echo_bad_secret(self):
        for value in ("not-a-secret-to-log", base64.b64encode(b"short").decode()):
            with mock.patch.dict(os.environ, {artifact.SECRET: value}), self.assertRaises(ValueError) as raised:
                artifact.key_from_environment()
            self.assertNotIn(value, str(raised.exception))

    def test_foreign_repository_is_not_an_allowed_context(self):
        with self.assertRaises(ValueError):
            artifact.context("someone-else/VPN-Nodes", "12345")

    def test_workflow_cli_roundtrip_and_failed_run_do_not_print_secrets(self):
        secret = base64.b64encode(self.key).decode()
        env = {**os.environ, artifact.SECRET: secret,
               "GITHUB_REPOSITORY": "noorelmostafa11-pixel/VPN-Nodes", "GITHUB_RUN_ID": "12345"}
        cli = [sys.executable, str(ROOT / "scripts/core_artifact.py")]
        for operation, source, destination in (("seal", self.source, self.encrypted),
                                                ("unseal", self.encrypted, self.output)):
            result = subprocess.run(cli + [operation, "--source", str(source), "--destination", str(destination)],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(secret, result.stdout + result.stderr)
        env["GITHUB_RUN_ID"] = "12346"
        result = subprocess.run(cli + ["unseal", "--source", str(self.encrypted),
                                       "--destination", str(self.root / "wrong-run")],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertFalse((self.root / "wrong-run").exists())


class WorkflowProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs = yaml.load((ROOT / ".github/workflows/update.yml").read_text(), Loader=yaml.BaseLoader)["jobs"]

    def test_core_checkout_uses_dedicated_secret_without_persisting_credentials(self):
        steps = self.jobs["owned-core"]["steps"]
        checkouts = [s["with"] for s in steps if s.get("with", {}).get("repository") == "noorelmostafa11-pixel/VPN-Core"]
        self.assertEqual(len(checkouts), 1)
        self.assertEqual(checkouts[0]["token"], "${{ secrets.VPN_CORE_READ_TOKEN }}")
        self.assertEqual(checkouts[0]["persist-credentials"], "false")
        go = next(s for s in steps if s.get("uses", "").startswith("actions/setup-go@"))
        self.assertEqual(go["with"]["cache"], "false")

    def test_only_encrypted_core_is_uploaded(self):
        uploads = [s["with"] for s in self.jobs["owned-core"]["steps"]
                   if s.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["path"], "${{ runner.temp }}/owned-core-sealed/core.bundle")
        self.assertEqual(uploads[0]["compression-level"], "0")

    def test_every_core_consumer_decrypts_before_executing_tools(self):
        for job in ("candidates", "core-check", "speed-check"):
            with self.subTest(job=job):
                steps = self.jobs[job]["steps"]
                downloaded = [s["with"] for s in steps
                              if s.get("uses", "").startswith("actions/download-artifact@")
                              and s.get("with", {}).get("name", "").startswith("owned-core-")]
                self.assertEqual(len(downloaded), 1)
                self.assertEqual(downloaded[0]["path"], "${{ runner.temp }}/owned-core-sealed")
                unseal = next(i for i, s in enumerate(steps) if "scripts/core_artifact.py unseal" in s.get("run", ""))
                self.assertEqual(steps[unseal]["env"][artifact.SECRET], "${{ secrets." + artifact.SECRET + " }}")
                execute = next(i for i, s in enumerate(steps) if any(x in s.get("run", "") for x in
                               ("python scripts/build_sources_candidates.py", "python scripts/xray_matrix/run_shard.py",
                                "python scripts/xray_matrix/run_speed_shard.py")))
                self.assertLess(unseal, execute)

    def test_publication_recovery_does_not_need_private_core(self):
        steps = self.jobs["publish"]["steps"]
        self.assertFalse(any("scripts/core_artifact.py" in s.get("run", "") for s in steps))
        self.assertFalse(any(s.get("with", {}).get("name", "").startswith("owned-core-") for s in steps))


if __name__ == "__main__":
    unittest.main()
