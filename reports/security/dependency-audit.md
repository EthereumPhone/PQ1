# PQSigner OS — Dependency CVE Audit

**Date:** 2026-05-19 (re-audited after fixes applied same day)
**Scope:** All 289 crates in `Cargo.lock` (workspace, post-fix), cross-checked against three independent advisory sources.
**Configuration audited:** Production target — `stm32u585,dual-se,ui-oled` plus host tooling (`fwsign`, `dbgen`, `xtask`).

## Changelog

| Date | Change | Result |
|---|---|---|
| 2026-05-19 (initial) | Baseline audit | 6 findings (0 exploitable CVEs in firmware) |
| 2026-05-19 (post-fix) | Bumped `fwsign` → `rpassword "7.5"`, `bls12_381_pka` dev-deps → `criterion "0.5"` | **4 findings cleared** (`rpassword`, `atty` ×2, `serde_cbor`); 2 remain — both upstream-owned |

## Tools used

| Tool | Version | Source DB | Coverage |
|---|---|---|---|
| `cargo-audit` | 0.22.1 | [RustSec Advisory DB](https://rustsec.org/) (git-cloned, 1,093 advisories loaded) | Rust-native; first-party Rust ecosystem |
| `cargo-deny` | 0.19.6 | RustSec (same source) + bans/yanked/duplicate-version checks | Rust-native; adds supply-chain hygiene |
| `osv-scanner` | 2.3.8 (osv-scalibr 0.4.5) | [OSV.dev](https://osv.dev/) — aggregates RustSec + GHSA + NVD + Debian | Multi-source; catches GHSA-only advisories |

Raw outputs are committed alongside this report:
- `reports/security/cargo-audit.{txt,json}`
- `reports/security/cargo-deny-advisories.txt`
- `reports/security/cargo-deny-bans.txt`
- `reports/security/osv-scanner.{txt,json}`

## Headline (post-fix)

**Zero exploitable CVEs anywhere in the workspace.** Two unmaintained-crate advisories remain, both rooted in upstream dependencies that we don't control directly (`cortex-m` and `ssd1306`).

| Severity | Count (post-fix) | Was (baseline) | In firmware binary? |
|---|---|---|---|
| Critical (CVSS 9–10) | 0 | 0 | – |
| High (CVSS 7–8.9) | 0 | 0 | – |
| Medium (CVSS 4–6.9) | 0 | 0 | – |
| Low (CVSS < 4) | 0 | 1 | – (fixed: `rpassword` 7.4.0 → 7.5.2) |
| Unmaintained (no CVSS) | 2 | 5 | 1 (`bare-metal` via `cortex-m`); 1 compile-time only (`proc-macro-error` via `ssd1306`) |

## Findings — consolidated (post-fix)

| # | Advisory ID | Crate @ ver | Class | Tools | Firmware impact | Path |
|---|---|---|---|---|---|---|
| 1 | RUSTSEC-2026-0110 | `bare-metal 0.2.5` | unmaintained | audit, deny, osv | **YES** (compiled in) | `cortex-m 0.7.7` → secure + nonsecure + fsbl + fi |
| 2 | RUSTSEC-2024-0370 | `proc-macro-error 1.0.4` | unmaintained | audit, osv | No (proc-macro, compile-time only) | `maybe-async-cfg` → `ssd1306` |

### Resolved on 2026-05-19

| Advisory | Crate @ ver | Fix |
|---|---|---|
| GHSA-2p6r-x3vv-xqm2 | `rpassword 7.4.0` → `7.5.2` | Bumped `fwsign/Cargo.toml`: `rpassword = "7.5"` |
| RUSTSEC-2024-0375 | `atty 0.2.14` (unmaintained) | Bumped `bls12_381_pka/Cargo.toml`: `criterion = "0.5"` (drops `atty`) |
| RUSTSEC-2021-0145 | `atty 0.2.14` (unsound) | Same as above |
| RUSTSEC-2021-0127 | `serde_cbor 0.11.2` | Same as above (Criterion 0.5 uses `ciborium` instead) |

## Detail per remaining finding

### 1. `bare-metal 0.2.5` — RUSTSEC-2026-0110 (unmaintained)

**Status:** [Deprecated and archived upstream](https://github.com/rust-embedded/bare-metal) (RUSTSEC notice 2026-04-23). Reaches the production firmware via the embedded toolchain. Upstream README confirms: *"This crate has been deprecated and archived, and it is not recommended for use in new projects. For `Mutex` and `CriticalSection`, see the [critical-section](https://crates.io/crates/critical-section) crate instead."*

**Path:**
```
bare-metal 0.2.5
└── cortex-m 0.7.7
    ├── sphincs-tz-secure       ← FIRMWARE (secure world)
    ├── sphincs-tz-nonsecure    ← FIRMWARE (non-secure world)
    ├── pqsigner-fsbl           ← FIRMWARE (first-stage bootloader)
    ├── pqsigner-fi             ← FIRMWARE
    ├── cortex-m-semihosting    ← only when ui-semihosting / panic-semihosting
    ├── panic-semihosting       ← excluded in production
    └── synopsys-usb-otg 0.4.0  ← nonsecure (USB stack)
```

**Risk assessment:** No known vulnerability — only a maintenance advisory. The crate's surface (`CriticalSection`, `Mutex`) is small and the code is stable. No exploitation vector identified.

**Upstream status (verified 2026-05-19):**
- We use `cortex-m 0.7.7` (current and latest stable on crates.io, released 2023-01-04 — no release since).
- `cortex-m 0.7.6` added a `critical-section-single-core` feature as an *alternative* API, but **did not remove the `bare-metal` dep**. No published version has dropped it.
- No `0.8.x` exists; the `master` branch shows "Unreleased" changes only.
- This is the state of virtually every Cortex-M Rust project on crates.io today.

**Recommended action:** Cannot be fixed in this workspace. Watch `rust-embedded/cortex-m` for a `0.8` release that drops `bare-metal`. No urgent change required.

### 2. `proc-macro-error 1.0.4` — RUSTSEC-2024-0370 (unmaintained)

**Status:** Compile-time-only proc-macro dependency.

**Path:**
```
proc-macro-error 1.0.4
└── maybe-async-cfg 0.2.4
    └── ssd1306 0.10.0          ← OLED driver (ui-oled feature)
        └── sphincs-tz-secure
```

**Risk assessment:** Proc-macros run only during compilation on the build host. They do not produce code that ends up in the firmware. **No runtime exposure.**

**Recommended action:** Cannot be fixed in this workspace — must wait for upstream `ssd1306` (or its `maybe-async-cfg` dep) to migrate to `proc-macro-error2`.

## `cargo-deny` bans / duplicate versions

`cargo-deny check bans` reported the following duplicate-version findings (informational, not security issues):

| Crate | Versions present | Source of duplication |
|---|---|---|
| `bitflags` | 1.3.2, 2.11.1 | v1 from older transitive deps, v2 from modern deps |
| `windows-sys` | (two versions in host dev-deps) | from host build chain only — not compiled into firmware |
| `syn` | 1.x, 2.x | proc-macro ecosystem mid-migration; compile-time only |

None of these affect the firmware binary. They inflate compile times and host-side dep tree only.

## Tool comparison

| Finding | cargo-audit | cargo-deny | osv-scanner |
|---|---|---|---|
| RUSTSEC-2026-0110 (bare-metal) | ✓ | ✓ | ✓ |
| RUSTSEC-2024-0375 (atty unmaintained) | ✓ | ✓ (collapsed) | ✓ |
| RUSTSEC-2021-0145 (atty unsound) | ✓ | ✗ (collapsed under atty) | ✓ |
| RUSTSEC-2021-0127 (serde_cbor) | ✓ | ✓ | ✓ |
| RUSTSEC-2024-0370 (proc-macro-error) | ✓ | ✗ (default config did not surface) | ✓ |
| GHSA-2p6r-x3vv-xqm2 (rpassword) | **✗** | **✗** | **✓ only** |
| Duplicate-version warnings | ✗ | ✓ | ✗ |

**Conclusion:** `osv-scanner` caught one finding the RustSec-only tools missed (`rpassword`). `cargo-deny` adds duplicate-version intelligence but its default config under-reports advisories versus `cargo-audit`. For ongoing CI, **running all three is the conservative choice**; the marginal cost is small.

## Manual sanity-check — items not covered by any tool

These categories are **outside** the scope of automated CVE scanners and require manual review:

1. **Vendored / forked crates.** `bls12_381_pka` (workspace member, forked from upstream `bls12_381`). Not tracked in any advisory DB. Manual diff against upstream + targeted review of pairing code is required for a complete audit.
2. **First-party crates** (`sphincs-c10`, `pqsigner-domain`, `pqsigner-aa`, etc.). No CVEs apply; covered by code review.
3. **C/Asm code** linked into firmware: `sphincs-c10` includes no C; cortex-m intrinsics are inline asm only. Nothing FFI'd.
4. **Build-script-only deps** (qrcodegen, png, fdeflate, flate2, miniz_oxide, etc.) — these execute on the *build host*, not in firmware. Compromise would affect generated assets but the FW-update manifest signing chain (`fwsign`) provides post-hoc detection.

## Recommendations

| Priority | Action | Status |
|---|---|---|
| ~~Low~~ | ~~Bump `fwsign` → `rpassword 7.5.0`~~ | **Done 2026-05-19** |
| ~~Low~~ | ~~Bump `bls12_381_pka` dev-deps → `criterion 0.5+`~~ | **Done 2026-05-19** |
| Watch | Track upstream `ssd1306` for `proc-macro-error2` migration | open (upstream-owned) |
| Watch | Track upstream `cortex-m` for `bare-metal` removal (currently on `0.7.7`, the latest published; no `0.8` exists) | open (upstream-owned) |
| Operational | Add `cargo audit` + `osv-scanner scan source --lockfile=Cargo.lock` to CI on every PR | open |
| Operational | Re-run this audit at every release; archive `reports/security/<date>-dependency-audit.md` | recurring |

## Reproducing this audit

```bash
# Install (one-off)
cargo install cargo-audit --locked
cargo install cargo-deny  --locked
go   install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest

# Run
mkdir -p reports/security
cargo audit 2>&1 | tee reports/security/cargo-audit.txt
cargo audit --json > reports/security/cargo-audit.json
cargo deny check advisories 2>&1 | tee reports/security/cargo-deny-advisories.txt
cargo deny check bans       2>&1 | tee reports/security/cargo-deny-bans.txt
osv-scanner scan source --lockfile=Cargo.lock --format=table 2>&1 \
  | tee reports/security/osv-scanner.txt
osv-scanner scan source --lockfile=Cargo.lock --format=json  \
  > reports/security/osv-scanner.json
```

**Advisory DB freshness at time of audit:**
- RustSec: 1,093 advisories loaded (git HEAD pulled fresh)
- OSV.dev: live API
