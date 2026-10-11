#!/usr/bin/env python3
"""Materialize the source adapter in a fresh crate for reproducible extraction.

The build script produces both the literal native source slice and its explicit
state version. Module inclusion is replaced with a normal sibling module so
Charon's source spans do not depend on Cargo's temporary OUT_DIR. Neither the
lifted body nor its dependency declarations are rewritten here.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "contracts/verification/tools/secure-wrapper-model"


def main() -> None:
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(exist_ok=False)
    cargo_target = destination / "build"
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(cargo_target)
    env["RUSTFLAGS"] = ""
    subprocess.run(["cargo", "build", "--locked", "--package", "secure-wrapper-model"],
                   cwd=TOOL, env=env, check=True)
    generated = list(cargo_target.glob("debug/build/secure-wrapper-model-*/out/production.rs"))
    assert len(generated) == 1, "missing or ambiguous fresh source-adapter output"
    expected = TOOL / "generated/production.rs"
    if generated[0].read_bytes() != expected.read_bytes():
        raise SystemExit("source-adapter output differs from committed generated/production.rs")
    crate = destination / "crate"
    (crate / "src").mkdir(parents=True)
    source = (TOOL / "src/lib.rs").read_text()
    inclusion = 'pub mod production {\n    include!(concat!(env!("OUT_DIR"), "/production.rs"));\n}'
    assert source.count(inclusion) == 1, "source-adapter inclusion changed"
    (crate / "src/lib.rs").write_text(source.replace(inclusion, "pub mod production;"))
    shutil.copyfile(generated[0], crate / "src/production.rs")
    shutil.copyfile(generated[0].with_name("native.rs"), destination / "native.rs")
    manifest = (TOOL / "Cargo.toml").read_text()
    members = 'members = ["native"]\n'
    assert manifest.count(members) == 1
    (crate / "Cargo.toml").write_text(manifest.replace(members, ""))
    print(f"MATERIALIZED: literal and lifted production-cfg wrapper; {crate}")


if __name__ == "__main__":
    main()
