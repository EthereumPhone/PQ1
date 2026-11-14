#!/usr/bin/env python3
"""plants_d.py <proto dir> — gate (d) controls: drop the format id from one derivation at a time in the domain
copy; the format tests must fail with the named message; the copy is restored after each plant."""
import subprocess, sys
P = sys.argv[1]
lib = f"{P}/domain/src/lib.rs"
good = open(lib).read()
plants = [
    ("account-0 bootstrap master", 'key[16..48].copy_from_slice(fid);', 'let _ = fid;', "bootstrap master shared"),
    ("account>0 bootstrap master", 'key[21..53].copy_from_slice(fid);', 'let _ = fid;', "bootstrap master shared"),
    ("account-0 slot master", '\n        buf[16..48].copy_from_slice(fid);', '\n        let _ = fid;', "slot master shared"),
    ("account>0 slot master", '\n        buf[21..53].copy_from_slice(fid);', '\n        let _ = fid;', "slot master shared"),
    ("slot sk_seed", '\n    sk_buf[16..48].copy_from_slice(fid);', '\n    let _ = fid;', "slot sk_seed ignores the format"),
    ("descriptor a7", 'b[24..38].copy_from_slice(&f.a7);', 'let _ = &f.a7;', "every_field_moves_the_descriptor_and_the_id"),
    ("slot pk_seed", '\n    pk_buf[16..48].copy_from_slice(fid);', '\n    let _ = fid;', "slot pk_seed ignores the format"),
]
bad = 0
try:
    for name, old, new, want in plants:
        assert good.count(old) == 1, (name, good.count(old))
        open(lib, "w").write(good.replace(old, new))
        r = subprocess.run(["cargo", "test", "--offline", "--release", "-q", "--features", "format-kdf,v2", "--test", "format_kdf"],
                           cwd=f"{P}/domain", env={**__import__("os").environ, "CARGO_TARGET_DIR": "../tgt-dom"},
                           capture_output=True, text=True)
        out = r.stdout + r.stderr
        ok = r.returncode != 0 and want in out
        print(f"plant {name}: {'caught' if ok else 'NOT CAUGHT'} ({want})")
        bad += not ok
finally:
    open(lib, "w").write(good)
sys.exit(1 if bad else 0)
