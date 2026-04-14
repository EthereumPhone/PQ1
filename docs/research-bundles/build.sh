#!/usr/bin/env bash
# Generate self-contained research bundles for AI deep-research sessions.
#
# Each bundle file is a standalone attachment: upload it to Claude web
# (or similar) as a single file, paste nothing else, and the session
# starts with all the context it needs.
#
# Run from repo root:  bash docs/research-bundles/build.sh
# Or from this dir:    ./build.sh

set -euo pipefail

# Locate repo root regardless of where script is invoked
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$SCRIPT_DIR"

cd "$REPO_ROOT"

# -------- shared helpers --------

# Append a code file to a bundle with a markdown heading + fenced block.
# Args: $1=bundle_path $2=source_path $3=language (rust|md|toml|...)
append_code() {
  local bundle="$1" src="$2" lang="${3:-rust}"
  if [[ ! -f "$src" ]]; then
    echo "WARNING: $src not found, skipping" >&2
    return 0
  fi
  {
    printf '\n\n### `%s`\n\n' "$src"
    printf '```%s\n' "$lang"
    cat "$src"
    printf '\n```\n'
  } >> "$bundle"
}

# Append a markdown file as-is (no code fence) under a heading.
append_markdown() {
  local bundle="$1" src="$2"
  if [[ ! -f "$src" ]]; then
    echo "WARNING: $src not found, skipping" >&2
    return 0
  fi
  {
    printf '\n\n### From `%s`\n\n' "$src"
    cat "$src"
    printf '\n'
  } >> "$bundle"
}

# Write the condensed project-context preamble used by every bundle.
# Kept DRY in one place; if the project evolves, edit here.
write_preamble() {
  local bundle="$1"
  cat >> "$bundle" <<'EOF'

---

## Project context (condensed — full version in `docs/ai-research-briefing.md`)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Transaction
signatures are **post-quantum SLH-DSA (SPHINCS+ SHA2-128f, migrating
to 192f)**. No commercial secure element currently computes SLH-DSA.
Bootstrap signatures are **ML-DSA-44** (also PQ, also not SE-capable).
The SEs are gated storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets. Non-secure world (flash bank 2,
SRAM2) owns UI, USB, tx parsing. Crossings go through 6 NSC gateway
commands with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 state.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Using NXP default static keys; rotation to per-device
keys + HUK-SAES wrapping is a production-readiness item (work-todo #7).

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---

EOF
}

# ===============================================================
# BUNDLE A — Fault-injection resistance
# ===============================================================

make_bundle_a() {
  local bundle="$OUT_DIR/A-fault-injection.md"
  cat > "$bundle" <<'EOF'
# Research Prompt A — Fault-Injection Resistance for PQ Signing + PIN Path

## Research question

Given the 2024-2025 state of voltage / EMFI / laser fault injection
against STM32 Cortex-M33 designs, what is the minimum set of
**software** glitch countermeasures we should add to these three flows:

1. The seed XOR-reconstruction code path in `DualSecureElement::unlock`
   (reads half_O and half_E from the two SEs, reconstructs full
   entropy, derives master_secret, caches encrypted blob).
2. The SLH-DSA signature verify-before-release guard in
   `sign_and_emit.rs` — currently a single compare that should be
   double-glitch-resistant.
3. The PIN-lockout trigger in `cmd_request_unlock.rs` — a single-
   glitch inversion of the "remaining == 0" check currently blocks
   the factory-reset path.

Give **concrete Rust code patterns** (redundant volatile reads,
complement-storage, magic-constant comparisons, random-delay
templates, NCC-Group-style double-check idioms). For each pattern,
identify which fault classes it defends against (single voltage
glitch, double voltage, EMFI, LFI) and which it doesn't. Rank by
cost/benefit. Out of scope: hardware countermeasures.

Reference the actual code inlined below. Point to specific line numbers
in your recommendations.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant code\n'
  } >> "$bundle"
  append_code "$bundle" "secure/src/dual_se.rs" rust
  append_code "$bundle" "secure/src/nsc/sign_and_emit.rs" rust
  append_code "$bundle" "secure/src/nsc/cmd_request_unlock.rs" rust
  append_code "$bundle" "secure/src/nsc/state.rs" rust
  append_code "$bundle" "secure/src/crypto.rs" rust
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE B — Production key management
# ===============================================================

make_bundle_b() {
  local bundle="$OUT_DIR/B-key-management.md"
  cat > "$bundle" <<'EOF'
# Research Prompt B — Production Key Management (SCP03 + PBS + HUK-SAES)

## Research question

Design a production provisioning + runtime key-management protocol:

1. Rotate SE050 SCP03 static ENC/MAC keys from NXP defaults to per-
   device-unique at chip personalization. Store the new keys on the
   STM32 side HUK-SAES-wrapped (never in plaintext flash).
2. Wrap the OPTIGA Platform Binding Secret the same way.
3. Handle PQSigner firmware upgrade: if a newer firmware includes a
   different HUK-SAES domain tag, how does it recover existing users'
   keys without requiring chip reset?
4. Establish verifiable per-device attestation binding physical
   SE050 + OPTIGA UIDs to the STM32 chip-unique-ID, so that swap
   attacks (move SE from a victim device to attacker's device) fail
   at boot.

Constraints: key rotation happens at one-time factory provisioning (no
field rekey). Out-of-band transport via a secure provisioner machine
is acceptable. Bricked-HUK recovery is NOT required — the wallet can
be considered dead, user restores from 24-word backup.

Deliverables: protocol diagram + flash-layout sketch + the minimum
STM32U585 SAES API usage pattern. Reference implementations from
other hardware wallets are useful.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant code and design\n'
  } >> "$bundle"
  append_code "$bundle" "secure/src/se050/scp03.rs" rust
  append_code "$bundle" "secure/src/optiga/shield.rs" rust
  append_code "$bundle" "secure/src/hw/flash.rs" rust
  append_markdown "$bundle" "docs/se050-factory-reset.md"
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE C — SLH-DSA side-channel landscape
# ===============================================================

make_bundle_c() {
  local bundle="$OUT_DIR/C-slhdsa-side-channel.md"
  cat > "$bundle" <<'EOF'
# Research Prompt C — SLH-DSA Side-Channel Landscape on Cortex-M33

## Research question

What side-channel attacks (power, EM, cache, timing, μarch) have been
demonstrated or are theoretically plausible against hash-based
signature schemes (SPHINCS+ / SLH-DSA) on ARM Cortex-M33-class chips?

Specifically:

1. Does the published academic literature include practical SLH-DSA
   SCA key-recovery attacks? If so, what are the noise thresholds
   (number of traces, signal-to-noise ratios, distance constraints)?
   If not, what's the closest analogue (SPHINCS-variant attacks,
   generic hash-based-sig attacks, WOTS chain extraction)?
2. Which specific operations within an SLH-DSA signature are the
   most leak-prone? (Candidates: FORS leaf computation exposing SK
   bits; WOTS chain walks exposing step counts; HT layer transitions;
   PRF evaluations consuming the master seed.)
3. Is the SHA-256 hardware accelerator on STM32U585 (HASH peripheral)
   SCA-hardened? If we route SLH-DSA's hashing through it instead of
   software SHA-256, does that eliminate the main leak surface or
   just move it?
4. Our design rotates the main signer every ~2^20 signatures. Is
   that already beyond the SCA trace-count threshold for practical
   recovery, or do we need tighter rotation?
5. Does migration from SHA2-128f to SHA2-192f meaningfully improve
   the SCA posture, or is it orthogonal?

Deliverables: catalogued threat list with severity + mitigation per
item, plus specific recommendations on per-signer rotation cadence
and whether to route hashing through the HASH peripheral.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant code\n'
  } >> "$bundle"
  append_code "$bundle" "secure/src/crypto.rs" rust
  append_code "$bundle" "secure/src/nsc/sign_and_emit.rs" rust
  append_code "$bundle" "secure/src/nsc/cmd_sign_userop.rs" rust
  append_code "$bundle" "secure/Cargo.toml" toml
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE D — USB stack hardening
# ===============================================================

make_bundle_d() {
  local bundle="$OUT_DIR/D-usb-hardening.md"
  cat > "$bundle" <<'EOF'
# Research Prompt D — USB Stack Hardening for USB-C-Only Hardware Wallet

## Research question

Audit the known attack surface of USB-stack implementations on STM32
Cortex-M MCUs and recommend hardening for our situation (USB-C only,
custom USB stack handling both HID with Ledger-compatible APDU framing
and a PQSigner-native protocol on a vendor class).

Specifically:

1. Known CVEs and proof-of-concept exploits against STM32 USB
   peripherals 2023-2025 (STM32Cube USB libraries, RTOS drivers, HID
   descriptor parsers). Include Colin O'Flynn's EMFI-on-USB work and
   descendants. Distinguish what applies to our custom stack vs what
   only affects STM32Cube.
2. Highest-risk USB descriptor parsing paths for a custom stack that
   handles HID + custom vendor protocol. Common lurking bugs
   (endpoint count overflow, string descriptor length misparse,
   SETUP-stage DMA corruption, etc.).
3. Minimum set of sanity checks between the USB ISR and our firmware's
   APDU handler to resist malformed/adversarial host behaviour.
4. Architectural evaluation: is there a defensible argument for
   implementing USB in a separate co-processor (tiny MCU beside the
   STM32 with a serial shim) to shrink attack surface on the
   crypto-hosting chip? What do real production wallets do?

Deliverables: CVE catalogue with applicability notes, ranked hardening
checklist, architectural recommendation on co-processor USB.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant code and design\n'
  } >> "$bundle"
  append_code "$bundle" "secure/src/hw/usb_hw.rs" rust
  append_code "$bundle" "nonsecure/src/usb/mod.rs" rust
  append_code "$bundle" "nonsecure/src/usb/transport.rs" rust
  append_code "$bundle" "nonsecure/src/usb/hid.rs" rust
  append_code "$bundle" "nonsecure/src/usb/commands.rs" rust
  append_markdown "$bundle" "docs/usb-protocol-v2.md"
  append_markdown "$bundle" "docs/usb-hid-setup.md"
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# BUNDLE E — Supply-chain + provisioning attestation
# ===============================================================

make_bundle_e() {
  local bundle="$OUT_DIR/E-supply-chain.md"
  cat > "$bundle" <<'EOF'
# Research Prompt E — Supply Chain and Provisioning Attestation

## Research question

Map the supply-chain + provisioning threat model for a hardware wallet
using SE050 + OPTIGA on TrustZone STM32U585, shipping through
conventional retail / e-commerce, and recommend a provisioning +
attestation protocol that defeats each attacker class.

Specifically:

1. Counterfeit STM32U5 supply in 2024-2025: are there confirmed
   clones (GD32/CS32/APM32 style) in the U5 family yet, or only
   older F/L-series? What boot-time probes reliably detect clones?
2. NXP's SE050 UID cert chain up to NXP root CA: how reliable for
   anti-clone? Threat model for SE050 extraction + re-implantation
   in a different physical wallet.
3. Same question for OPTIGA Trust M cert chain.
4. What do Ledger, Trezor, Coinkite, Foundation etc. do at
   provisioning to attest "genuine factory-sealed device" to a
   customer opening the box? Known failure modes (historical + 2024-
   2025).
5. Given our dual-SE architecture, is there an additional attestation
   advantage from cross-binding SE050-UID + OPTIGA-UID + STM32-UID
   in a signed manifest that must match at every boot?

Deliverables: ranked attacker list (opportunistic re-seller;
sophisticated interdictor; nation-state with factory access), the
attestation protocol that defeats each, and a specific "box-opening"
user ceremony that demonstrates genuineness without requiring the
customer to run an independent tool.

EOF
  write_preamble "$bundle"
  {
    printf '\n## Relevant design docs (code footprint small — feature not implemented)\n'
  } >> "$bundle"
  append_markdown "$bundle" "docs/architecture.md"
  append_markdown "$bundle" "docs/pq-aa-wallet-design.md"
  append_markdown "$bundle" "docs/HARDENING.md"
  echo "  built $bundle ($(wc -c < "$bundle") bytes)"
}

# ===============================================================
# run
# ===============================================================

echo "Generating research bundles from $REPO_ROOT"
echo

make_bundle_a
make_bundle_b
make_bundle_c
make_bundle_d
make_bundle_e

echo
echo "Done. Upload any single bundle file to Claude web and paste nothing"
echo "else — each bundle is self-contained. The question is at the top."
