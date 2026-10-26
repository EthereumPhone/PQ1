#!/usr/bin/env python3
"""Bind the proof-only word kernel to C10's actual pinned sha2 dependency.

The two Rust modules and licenses are byte-identical members of the sha2 0.10.9
crate authenticated by Cargo.lock. The small module root changes visibility/
reachability only: Charon starts at the original private word-compression body.
This does not authenticate the Digest API, dispatch, byte loop or peripheral.
The default check is offline; --check-archive also rechecks the cached package.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pwd
import shutil
import tarfile
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODEL = Path("contracts/verification/tools/sha256-portable-model")
VENDOR = MODEL / "vendor/sha2-0.10.9"
CRATE_SHA256 = "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283"
CRATE_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
PINS = {
    "src/consts.rs": "2f820349fa7cbf9fecc1d4aabbd1a721bb1badc3f32ef9e903826960b6f42523",
    "src/sha256/soft.rs": "98e765a8e8dfa0af31f2b76570f212e6b3099522bf300e1554cbbd9fd5d02960",
    "LICENSE-MIT": "b4eb00df6e2a4d22518fcaa6a2b4646f249b3a3c9814509b22bd2091f1392ff1",
    "LICENSE-APACHE": "a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5",
}
HARNESS_SHA256 = "61491b6e4187e8330f971fdd46383e8937867b360240fcd52cc186b79ff4263a"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(root: Path = ROOT, archive: Path | None = None) -> list[str]:
    errors: list[str] = []
    try:
        manifest = tomllib.loads((root / "sphincs-c10/Cargo.toml").read_text())
        if manifest["dependencies"].get("sha2") != {"version": "0.10", "default-features": False}:
            errors.append("C10 sha2 dependency configuration changed")
        packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
        consumer = [p for p in packages if p["name"] == "sphincs-c10"]
        if len(consumer) != 1:
            errors.append("C10 lockfile package identity is missing or ambiguous")
        else:
            selected = [d for d in consumer[0]["dependencies"] if d.split()[0] == "sha2"]
            if selected != ["sha2 0.10.9"]:
                errors.append("C10 does not select the pinned sha2 0.10.9 package")
        selected_packages = [p for p in packages if p["name"] == "sha2" and p["version"] == "0.10.9"]
        if len(selected_packages) != 1 or any(
            p.get("source") != CRATE_SOURCE or p.get("checksum") != CRATE_SHA256
            for p in selected_packages
        ):
            errors.append("sha2 package source/checksum identity changed")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        errors.append(f"dependency identity is unreadable: {exc}")

    expected = {VENDOR / name: sha for name, sha in PINS.items()}
    expected[MODEL / "lib.rs"] = HARNESS_SHA256
    for name, sha in expected.items():
        try:
            if digest((root / name).read_bytes()) != sha:
                errors.append(f"source drift: {name}")
        except OSError as exc:
            errors.append(f"source missing/unreadable: {name}: {exc}")

    if archive is not None:
        try:
            if digest(archive.read_bytes()) != CRATE_SHA256:
                errors.append("archive checksum does not match the selected Cargo package")
            else:
                with tarfile.open(archive) as package:
                    for name, sha in PINS.items():
                        member_name = f"sha2-0.10.9/{name}"
                        members = [m for m in package.getmembers() if m.name == member_name]
                        if len(members) != 1 or not members[0].isfile():
                            errors.append(f"archive member missing/ambiguous: {name}")
                            continue
                        stream = package.extractfile(members[0])
                        if stream is None or digest(stream.read()) != sha:
                            errors.append(f"archive source differs from the proof source: {name}")
        except (OSError, KeyError, tarfile.TarError) as exc:
            errors.append(f"archive is unreadable: {exc}")
    return errors


def cached_archive() -> Path:
    # Match the fixed user/tool root of the existing extraction gate. A caller's
    # CARGO_HOME does not select a different source for this correspondence.
    cache = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".cargo/registry/cache"
    for path in sorted(cache.glob("*/sha2-0.10.9.crate")):
        if path.is_file() and digest(path.read_bytes()) == CRATE_SHA256:
            return path
    raise FileNotFoundError("authenticated sha2-0.10.9.crate missing; fetch the locked C10 dependencies first")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="pq-sha256-source-") as tmp:
        root = Path(tmp)
        for rel in [Path("Cargo.lock"), Path("sphincs-c10/Cargo.toml"),
                    MODEL / "lib.rs", *(VENDOR / name for name in PINS)]:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, root / rel)
        if check(root):
            raise RuntimeError("clean source-binding control failed")

        def reject(rel: Path, changed: bytes | None, expected_error: str) -> None:
            path = root / rel
            original = path.read_bytes()
            if changed is None:
                path.unlink()
            else:
                path.write_bytes(changed)
            try:
                errors = check(root)
                if not any(expected_error in e for e in errors):
                    raise RuntimeError(f"control was not rejected at {expected_error}: {errors}")
            finally:
                path.write_bytes(original)

        soft = VENDOR / "src/sha256/soft.rs"
        body = (root / soft).read_bytes()
        if body.count(b"$a.rotate_right(6)") != 1:
            raise RuntimeError("rotation control target changed")
        reject(soft, body.replace(b"$a.rotate_right(6)", b"$a.rotate_right(7)"), "source drift")
        reject(soft, None, "source missing")
        harness = MODEL / "lib.rs"
        reject(harness, (root / harness).read_bytes().replace(b"mod soft;", b"mod changed;"), "source drift")
        manifest = Path("sphincs-c10/Cargo.toml")
        reject(manifest, (root / manifest).read_bytes().replace(b'version = "0.10"', b'version = "0.11"'),
               "dependency configuration")
        lock = (root / "Cargo.lock").read_bytes()
        reject(Path("Cargo.lock"), lock.replace(CRATE_SHA256.encode(), b"0" * 64), "source/checksum")
        start = lock.index(b'name = "sphincs-c10"')
        end = lock.index(b"[[package]]", start)
        old = lock[start:end]
        changed = old.replace(b'"sha2 0.10.9"', b'"sha2 0.11.1"')
        if old == changed:
            raise RuntimeError("consumer lock control target changed")
        reject(Path("Cargo.lock"), lock[:start] + changed + lock[end:], "does not select")
        archive = root / "wrong.crate"
        archive.write_bytes(b"wrong package")
        if not any("archive checksum" in e for e in check(root, archive)):
            raise RuntimeError("wrong-archive control escaped")
        if check(root):
            raise RuntimeError("controls did not restore their isolated baseline")
    print("OK: clean binding and seven intended source/dependency/archive rejection controls")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-archive", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        archive = cached_archive() if args.check_archive else None
        errors = check(archive=archive)
        if errors:
            for error in errors:
                print(f"FAIL: {error}")
            return 1
        if args.self_test:
            self_test()
    except (OSError, RuntimeError) as exc:
        print(f"FAIL: {exc}")
        return 1
    print("OK: portable word-kernel source matches C10's pinned sha2 0.10.9")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
