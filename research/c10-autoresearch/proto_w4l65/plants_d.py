#!/usr/bin/env python3
"""plants_d.py <proto dir> — gate (d) controls: drop the format id from one derivation at a time in the domain
copy; the format tests must fail with the named message; the copy is restored after each plant."""
import subprocess, sys
P = sys.argv[1]
lib = f"{P}/domain/src/lib.rs"
good = open(lib).read()
plants = [
    # binding sites: the format id dropped
    ("account-0 bootstrap key", 'b"pq1-c10-fmt-boot-acc0");\n        key[21..53].copy_from_slice(fid);',
     'b"pq1-c10-fmt-boot-acc0");\n        let _ = fid;', "bootstrap master shared"),
    ("account>0 bootstrap key", 'b"pq1-c10-fmt-boot-acct");\n        key[21..53].copy_from_slice(fid);',
     'b"pq1-c10-fmt-boot-acct");\n        let _ = fid;', "bootstrap master shared"),
    ("account-0 slot master", 'b"pq1-c10-fmt-slot-acc0");\n        buf[21..53].copy_from_slice(fid);',
     'b"pq1-c10-fmt-slot-acc0");\n        let _ = fid;', "slot master shared"),
    ("account>0 slot master", 'b"pq1-c10-fmt-slot-acct");\n        buf[21..53].copy_from_slice(fid);',
     'b"pq1-c10-fmt-slot-acct");\n        let _ = fid;', "slot master shared"),
    ("slot sk_seed", '\n    sk_buf[16..48].copy_from_slice(fid);', '\n    let _ = fid;', "slot sk_seed ignores the format"),
    ("slot pk_seed", '\n    pk_buf[16..48].copy_from_slice(fid);', '\n    let _ = fid;', "slot pk_seed ignores the format"),
    ("descriptor a7", 'b[24..38].copy_from_slice(&f.a7);', 'let _ = &f.a7;', "every_field_moves_the_descriptor_and_the_id"),
    # routing: the public derivations bypass the format-bound helpers
    ("bootstrap route", 'bootstrap_master_with_format(&compiled_format_id(), bip39_seed, account_index)',
     'bootstrap_master_with_format(&[0u8; 32], bip39_seed, account_index)', "public_api_is_the_compiled_format"),
    ("slot-master route", 'return slot_master_with_format(&compiled_format_id(), bip39_seed, account_index);',
     'let _ = slot_master_with_format;', "public_api_is_the_compiled_format"),
    ("slot-seed route", 'return slot_seeds_with_format(&compiled_format_id(), slot_entropy);',
     'let _ = slot_seeds_with_format;', "public_slot_keypair_route_is_format_bound"),
    # encodings: a label byte changed (the independent formulas and the pinned vectors must notice)
    ("bootstrap label", 'b"pq1-c10-fmt-boot-acc0"', 'b"pq1-c10-fmt-boot-acc1"', "kdf_encodings_match_independent_formulas"),
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
