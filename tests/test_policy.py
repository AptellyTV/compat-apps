import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from zipfile import ZipFile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release_policy import REPOSITORY, sha, validate_catalog, validate_release


class ReleasePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        root = Path(cls.keys.name)
        cls.key = root / "key.pem"; cls.cert = root / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cls.key), "-out", str(cls.cert), "-subj", "/CN=Temporary Test Publisher", "-days", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        der = subprocess.check_output(["openssl", "x509", "-in", str(cls.cert), "-outform", "DER"])
        cls.fingerprint = hashlib.sha256(der).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.tag = "test-app-v1.0.0"
        with ZipFile(self.root / (self.tag + ".apk"), "w") as z:
            z.writestr("AndroidManifest.xml", b"temporary binary fixture")
            z.writestr("classes.dex", b"temporary code fixture")
        with ZipFile(self.root / (self.tag + "-source.zip"), "w") as z:
            z.writestr("build.gradle", "// temporary build entry\n")
        (self.root / (self.tag + "-notices.txt")).write_text("Temporary test fixture\n")
        (self.root / (self.tag + "-signer.pem")).write_bytes(self.cert.read_bytes())
        (self.root / (self.tag + ".sha256")).write_text(sha(self.root / (self.tag + ".apk")) + "  " + self.tag + ".apk\n")
        roles = {"apk": ".apk", "source": "-source.zip", "notices": "-notices.txt", "certificate": "-signer.pem", "checksum": ".sha256"}
        self.payload = {"schema_version": 1, "app_id": "test-app", "name": "Test", "package_name": "app.aptelly.test", "version_code": 1, "version_name": "1.0.0", "channel": "stable", "tag": self.tag, "min_api": 26, "abis": ["armeabi-v7a"], "source_revision": "a" * 40, "qualified_profile_ids": ["test-profile"], "signer_certificate_sha256": self.fingerprint, "assets": []}
        for role, suffix in roles.items():
            p = self.root / (self.tag + suffix)
            self.payload["assets"].append({"role": role, "name": p.name, "size": p.stat().st_size, "sha256": sha(p), "url": f"https://github.com/{REPOSITORY}/releases/download/{self.tag}/{p.name}"})
        self.resign()

    def tearDown(self): self.temp.cleanup()

    def resign(self):
        payload = json.dumps(self.payload).encode()
        signature = subprocess.check_output(["openssl", "dgst", "-sha256", "-sign", str(self.key)], input=payload)
        (self.root / (self.tag + ".json")).write_text(json.dumps({"payload": base64.b64encode(payload).decode(), "signature": base64.b64encode(signature).decode()}))

    def update_hash(self, role):
        a = next(a for a in self.payload["assets"] if a["role"] == role)
        p = self.root / a["name"]; a.update(size=p.stat().st_size, sha256=sha(p)); self.resign()

    def test_valid_signed_release_and_pinned_identity(self):
        identity = {k: self.payload[k] for k in ("app_id", "package_name", "signer_certificate_sha256")}
        self.assertEqual(validate_release(self.root, identity), self.payload)

    def test_downloaded_apk_tampering_is_rejected(self):
        (self.root / (self.tag + ".apk")).write_bytes(b"modified")
        with self.assertRaises(ValueError): validate_release(self.root)

    def test_wrong_pinned_app_cannot_share_release(self):
        identity = {k: self.payload[k] for k in ("app_id", "package_name", "signer_certificate_sha256")}
        identity["app_id"] = "other-app"
        with self.assertRaisesRegex(ValueError, "pinned definition"): validate_release(self.root, identity)

    def test_signed_manifest_edit_without_resigning_fails(self):
        manifest = self.root / (self.tag + ".json")
        envelope = json.loads(manifest.read_text()); changed = dict(self.payload, name="Edited")
        envelope["payload"] = base64.b64encode(json.dumps(changed).encode()).decode(); manifest.write_text(json.dumps(envelope))
        with self.assertRaises(subprocess.CalledProcessError): validate_release(self.root)

    def test_private_source_is_rejected_even_with_valid_signature(self):
        with ZipFile(self.root / (self.tag + "-source.zip"), "a") as z: z.writestr("services/private.js", "private source")
        self.update_hash("source")
        with self.assertRaisesRegex(ValueError, "Private development path"): validate_release(self.root)

    def test_private_key_cannot_be_hidden_after_public_certificate(self):
        cert = self.root / (self.tag + "-signer.pem"); cert.write_bytes(cert.read_bytes() + self.key.read_bytes())
        self.update_hash("certificate")
        with self.assertRaisesRegex(ValueError, "Private key material"): validate_release(self.root)

    def test_unlisted_file_cannot_be_uploaded(self):
        (self.root / "raw-evidence.txt").write_text("private")
        with self.assertRaisesRegex(ValueError, "Unreviewed extra"): validate_release(self.root)

    def test_unversioned_or_other_app_url_is_rejected(self):
        self.payload["assets"][0]["url"] = "https://example.com/latest.apk"; self.resign()
        with self.assertRaisesRegex(ValueError, "versioned"): validate_release(self.root)

    def test_account_fields_cannot_enter_public_manifest(self):
        self.payload["license_headers"] = {"Cookie": "fake-private-user"}; self.resign()
        with self.assertRaisesRegex(ValueError, "Unreviewed fields"): validate_release(self.root)

    def test_catalog_prevents_package_collision_and_version_downgrade(self):
        release = {"version_code": 2, "version_name": "1.0.0", "tag": self.tag, "manifest_url": f"https://github.com/{REPOSITORY}/releases/download/{self.tag}/{self.tag}.json", "manifest_sha256": "a" * 64, "channel": "stable"}
        app = {"app_id": "test-app", "package_name": "app.aptelly.test", "signer_certificate_sha256": self.fingerprint, "releases": [release]}
        value = {"schema_version": 1, "repository": REPOSITORY, "apps": [app]}
        validate_catalog(value)
        value["apps"].append(dict(app, app_id="second-app"))
        with self.assertRaisesRegex(ValueError, "Duplicate"): validate_catalog(value)
        value["apps"] = [app]; app["releases"].append(dict(release, version_code=1))
        with self.assertRaisesRegex(ValueError, "increase"): validate_catalog(value)


if __name__ == "__main__": unittest.main()
