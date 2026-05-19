# ERC-7730 Registry Mirror

Production builds of the ERC-7730 descriptor DB pull templated permits, EIP-712
common fragments, and other shared definitions from a *local mirror* of the
[ethereum/clear-signing-erc7730-registry](https://github.com/ethereum/clear-signing-erc7730-registry).

A local mirror is required when any descriptor under
`secure/data/erc7730/*.json` carries an `"includes"` reference — without it,
`dbgen` rejects the descriptor with:

```
`includes: "<ref>"` requires `--registry-root <dir>`. See secure/data/erc7730/REGISTRY_MIRROR.md.
```

## Set up the mirror

```bash
# 1. Fork the upstream registry to your org and pin to a vetted SHA.
git clone https://github.com/<your-org>/clear-signing-erc7730-registry.git \
    third_party/erc7730-registry
cd third_party/erc7730-registry
git checkout <known-good-sha>

# 2. Wire it as a git submodule on the PQSigner repo (one-time):
cd <pqsigner-repo>
git submodule add https://github.com/<your-org>/clear-signing-erc7730-registry.git \
    third_party/erc7730-registry
git submodule update --init --recursive

# 3. Pass --registry-root on every dbgen invocation that needs includes:
cargo run -p dbgen -- \
    --policy production \
    --registry-root third_party/erc7730-registry
```

## Supported include forms

`dbgen::erc7730::resolve_include_path` accepts three forms:

| Form | Example | Resolution |
|------|---------|------------|
| GitHub blob URL | `https://github.com/ethereum/clear-signing-erc7730-registry/blob/main/templates/erc2612-permit.json` | strip `https://github.com/<owner>/<repo>/blob/<ref>/`, treat the rest as a registry-relative path |
| Relative path | `./templates/permit.json` | resolve relative to the **descriptor file's** directory |
| Registry-relative | `templates/permit.json` | resolve relative to `--registry-root <dir>` |

Any include that resolves OUTSIDE `--registry-root` after canonicalisation
(e.g. via `../../../etc/passwd` escapes) is refused — this is the host-build
sandbox boundary.

## Coordinating SHA bumps

When the upstream registry adds/removes/modifies fragments referenced by our
descriptors:

1. Bump the submodule SHA in the fork.
2. Re-run `cargo run -p dbgen -- --policy production --registry-root …`.
3. The `ERC7730_DESCRIPTORS_ROOT` regenerated into
   `secure/src/db_roots.rs` will change → the companion-side
   `tools/companion-stub/erc7730_db.bin` must be reshipped in lockstep
   with the firmware build that pins the new root.
4. Commit both `db_roots.rs` and the new `erc7730_db.bin` together.

## CI gate

A production CI matrix entry should run:

```bash
cargo run -p dbgen -- --policy production --registry-root third_party/erc7730-registry
cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi \
    --no-default-features --features dual-se,ui-oled,stm32u585,mode-production
```

Both MUST pass before any release tag.
