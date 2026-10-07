"""Portable release checks. No Android build, accounts or signing keys are needed."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from zipfile import ZipFile

REPOSITORY = "AptellyTV/compat-apps"
HEX = re.compile(r"[a-f0-9]{64}")
APP_ID = re.compile(r"[a-z][a-z0-9-]{1,63}")
PACKAGE = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}")
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?")
ROLES = {"apk", "source", "notices", "certificate", "checksum"}
FORBIDDEN = {".git", ".github", "services", "backups", "dows", "test-evidence", "MEMORY.md", "AGENTS.md", "local.properties", "node_modules"}
SECRET = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|(?:CLOUDFLARE_API_TOKEN|APTELLY_KEYSTORE_PASSWORD)\s*[=:]")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(args):
    return subprocess.check_output(args, stderr=subprocess.PIPE)


def validate_catalog(value):
    require(set(value) == {"schema_version", "repository", "apps"}, "Unexpected catalog fields")
    require(value["schema_version"] == 1 and value["repository"] == REPOSITORY, "Wrong catalog")
    ids, packages = set(), set()
    for app in value["apps"]:
        require(APP_ID.fullmatch(app["app_id"]) and PACKAGE.fullmatch(app["package_name"]), "Invalid application identity")
        require(app["app_id"] not in ids and app["package_name"] not in packages, "Duplicate application")
        ids.add(app["app_id"]); packages.add(app["package_name"])
        require(HEX.fullmatch(app["signer_certificate_sha256"]), "Missing pinned signer")
        previous = 0
        for release in app["releases"]:
            require(type(release["version_code"]) is int and release["version_code"] > previous, "Versions must increase")
            previous = release["version_code"]
            require(VERSION.fullmatch(release["version_name"]), "Invalid version")
            tag = app["app_id"] + "-v" + release["version_name"]
            require(release["tag"] == tag, "Wrong release tag")
            require(release["manifest_url"] == f"https://github.com/{REPOSITORY}/releases/download/{tag}/{tag}.json", "Wrong manifest URL")
            require(HEX.fullmatch(release["manifest_sha256"]), "Missing manifest hash")
            require(release["channel"] in ("stable", "beta"), "Invalid channel")
    return value


def scan_source(path):
    with ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "Duplicate source paths")
        require(any(n.endswith(("build.gradle", "build.gradle.kts", "CMakeLists.txt")) for n in names), "Source has no build entry")
        total = 0
        for info in archive.infolist():
            name = info.filename
            require(not name.startswith("/") and "\\" not in name and ".." not in Path(name).parts, "Unsafe source path")
            require(not any(p in FORBIDDEN or p.startswith(".env") for p in Path(name).parts), "Private development path in source")
            require(not name.endswith((".apk", ".p12", ".jks", ".keystore", ".log")), "Private or binary artifact in source")
            require((info.external_attr >> 16) & 0o170000 != 0o120000, "Source symlinks are not allowed")
            total += info.file_size
            require(total < 2 * 1024**3 and info.file_size < 64 * 1024**2, "Source size exceeds review limit")
            if not info.is_dir():
                require(not SECRET.search(archive.read(info)), "Credential material in source")


def validate_release(directory, expected=None):
    directory = Path(directory)
    manifests = list(directory.glob("*.json"))
    require(len(manifests) == 1, "Exactly one signed manifest is required")
    envelope = json.loads(manifests[0].read_text())
    require(set(envelope) == {"payload", "signature"}, "Wrong signed envelope")
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    require(0 < len(payload) <= 32768, "Invalid payload size")
    value = json.loads(payload)
    allowed = {"schema_version", "app_id", "name", "package_name", "version_code", "version_name", "channel", "tag", "min_api", "abis", "source_revision", "qualified_profile_ids", "signer_certificate_sha256", "assets", "mirrors"}
    require(set(value).issubset(allowed), "Unreviewed fields in public release manifest")
    require(value.get("mirrors", []) == [], "Additional mirrors require a reviewed policy revision")
    require(value["schema_version"] == 1, "Unknown release schema")
    require(APP_ID.fullmatch(value["app_id"]) and PACKAGE.fullmatch(value["package_name"]), "Invalid identity")
    require(value["package_name"].startswith("app.aptelly.") and ".diagnostics." not in value["package_name"], "Only our production compatibility packages may be published")
    require(VERSION.fullmatch(value["version_name"]) and type(value["version_code"]) is int and value["version_code"] > 0, "Invalid version")
    require(value["channel"] in ("stable", "beta"), "Invalid channel")
    tag = value["app_id"] + "-v" + value["version_name"]
    require(value["tag"] == tag and manifests[0].name == tag + ".json", "Manifest/tag mismatch")
    require(HEX.fullmatch(value["signer_certificate_sha256"]), "Invalid signer")
    require(type(value["min_api"]) is int and value["min_api"] >= 26 and isinstance(value["abis"], list) and value["abis"] and all(a in ("armeabi-v7a", "arm64-v8a", "x86", "x86_64") for a in value["abis"]), "Missing platform constraints")
    require(re.fullmatch(r"[a-f0-9]{40}", value["source_revision"]), "Missing exact source revision")
    require(value["qualified_profile_ids"] and all(re.fullmatch(r"[a-z0-9-]{1,100}", p) for p in value["qualified_profile_ids"]), "Missing qualified profiles")
    if expected:
        for field in ("app_id", "package_name", "signer_certificate_sha256"):
            require(value[field] == expected[field], "App/signer does not match its pinned definition")
        require(value["version_code"] > expected.get("last_version_code", 0), "Release is not an upgrade")
    assets = value["assets"]
    require(len(assets) == len(ROLES) and {a["role"] for a in assets} == ROLES, "Wrong release asset set")
    filenames = {manifests[0].name}
    for asset in assets:
        name = asset["name"]
        require(re.fullmatch(r"[A-Za-z0-9._-]+", name) and name not in filenames, "Invalid or duplicate asset name")
        filenames.add(name)
        require(asset["url"] == f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}", "Asset URL is not versioned in the release repository")
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "Missing or unsafe asset")
        require(type(asset["size"]) is int and 0 < asset["size"] < 2 * 1024**3 and path.stat().st_size == asset["size"], "Asset size mismatch")
        require(HEX.fullmatch(asset["sha256"]) and sha(path) == asset["sha256"], "Asset hash mismatch")
    require({p.name for p in directory.iterdir()} == filenames, "Unreviewed extra files in release")
    by_role = {a["role"]: directory / a["name"] for a in assets}
    require(by_role["apk"].suffix == ".apk" and by_role["source"].suffix == ".zip", "Invalid APK/source format")
    require(by_role["checksum"].read_text().strip() == sha(by_role["apk"]) + "  " + by_role["apk"].name, "Checksum file mismatch")
    scan_source(by_role["source"])
    require(not SECRET.search(by_role["notices"].read_bytes()), "Credential material in notices")
    require(not SECRET.search(by_role["certificate"].read_bytes()), "Private key material in certificate asset")
    with ZipFile(by_role["apk"]) as apk:
        require("AndroidManifest.xml" in apk.namelist(), "APK has no Android manifest")
        for item in apk.infolist():
            require(not any(p in FORBIDDEN or p.startswith(".env") for p in Path(item.filename).parts), "Private path in APK")
            require(item.file_size < 128 * 1024**2, "APK entry exceeds review limit")
            if not item.is_dir():
                require(not SECRET.search(apk.read(item)), "Credential material in APK")
    der = run(["openssl", "x509", "-in", str(by_role["certificate"]), "-outform", "DER"])
    require(hashlib.sha256(der).hexdigest() == value["signer_certificate_sha256"], "Certificate differs from pinned signer")
    subject = run(["openssl", "x509", "-in", str(by_role["certificate"]), "-noout", "-subject"])
    require(b"Android Debug" not in subject, "Debug signers cannot be released")
    with tempfile.TemporaryDirectory(prefix="compat-verify-") as work:
        work = Path(work)
        (work / "payload").write_bytes(payload); (work / "signature").write_bytes(signature)
        (work / "public.pem").write_bytes(run(["openssl", "x509", "-in", str(by_role["certificate"]), "-pubkey", "-noout"]))
        run(["openssl", "dgst", "-sha256", "-verify", str(work / "public.pem"), "-signature", str(work / "signature"), str(work / "payload")])
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--release-dir", type=Path)
    args = parser.parse_args()
    if args.catalog:
        validate_catalog(json.loads(args.catalog.read_text()))
    if args.release_dir:
        validate_release(args.release_dir)
    require(args.catalog or args.release_dir, "Provide a catalog or release directory")
    print("Compatibility distribution policy passed")
