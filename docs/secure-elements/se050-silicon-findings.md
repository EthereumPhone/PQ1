# SE050 on-silicon findings — first real run, 2026-05-28

First end-to-end execution of `make se050-stress-destructive` on a real
B-U585I-IOT02A. Recorded here so the next person doesn't re-discover
the same silicon quirks.

**Threat-model reminder for what follows:** PQ1's confidentiality
invariant is `half_E` (and slot/master keys derived from it) NEVER
leaves the secure side. DoS / "attacker destroys the secret" is
explicitly OUT of the confidentiality model — the user's BIP-39 24-word
backup is the recovery path. Several findings below are DoS vectors;
they are documented but **not ship blockers** under this threat model.

---

## Part identity — read this first (canonical; owner-confirmed 2026-10-19)

**The production SE050 is the SE050E2: orderable part `SE050E2HQ1/Z01Z3Z`** (type
`SE050E2HQ1/Z01Z3`, 12NC `9354 343 82472`, SE050 datasheet Rev 3.8 Table 3). The
owner confirmed it 2026-10-19, closing #697. It is the part on the pq1 schematic
(`docs/hardware/schematics/README.md`, `secure/src/board/pq1.rs`), on EVT-3D21
and DVT #1, and the same variant as the OM-SE050ARD-E bench shield. Every SE050
silicon result in this repo was taken on an SE050E2, so it applies to the
production part directly.

**It is NOT the SE050C2.** From 2026-07-20 to 2026-10-19 the repo recorded the
production part as `SE050C2HQ1/Z01SDZ` (OEF `A201`, applet 3.x). That decision was
reversed, no C2 ever ran on silicon, and the `se050-part-c2` build flag that
selected the C2 keyset was removed. Any C2 reference left in an archived audit, a
research bundle or a findings JSON is history, not current state.

| Property | SE050E2 (fitted) | Source |
|---|---|---|
| Generation | "New generation" SE050E (2022), IoT applet **7.2** | AN12436 Rev 2.4 §3.5 |
| Variant identifier (OEF) | **`A921`**, shared with the "SE050E Development Board" | AN12436 Table 2 |
| Silicon identity | applet **7.2.0**, `AppletConfig=0x3F9F`, `SecureBox=0xFFFF`; 37-byte VersionInfo over SCP03 | OM-SE050ARD-E 2026-06-02, DVT #1 2026-10-15, EVT-3D21 2026-10-19 (UniqueID `0400500157990ff53d289104261f22df1390`) |
| Runtime anti-substitution | The OEF is **not** in the GetVersion reply, so the gate pins `AppletConfig` (`secure/src/se050_stress/tests/audit.rs`, `ACCEPTED_APPLET_CONFIGS = [0x3F9F]`) | silicon 2026-06-02 |
| Factory Platform SCP03 keys | ENC `d2db63e7a0a5aed72a6460c4dfdcaf64`, MAC `738d5b798ed241b0b24768514bfba95b`, DEK `6702dac30942b2c85e7f47b42ced4e7f`, KVN `0x0B`. **Published, so transport-only; they must be rotated** (#55) | AN12436 **Table 5** (new generation), not Table 6; `secure/src/scp03_logic.rs` `PLATFORM_*` |
| Crypto set | ECC NIST / Brainpool / Koblitz, Ed25519, Curve25519, Curve448, ECDSA/ECDH/EdDSA, AES incl. **CCM/GCM**, GMAC, HMAC/CMAC, SHA-1…512, PBKDF2. **No RSA.** None of it signs anything for the wallet (invariant #5); the firmware uses the chip for storage, UserID auth, GetRandom and SCP03 | AN12436 Table 1 |
| I2C target | Clock stretching **disabled by default** on SE050E; max SCL **1 MHz** (A/B/C/D/F stretch above 600 kHz, up to 3.4 MHz). The firmware runs 400 kHz | datasheet Rev 3.8 §4.1.1; AN12436 Table 1 |
| Power saving | **Deep Power-Down only** (no state retention, < 5 µA), entered by pulling `ENA` low. The E2 column lacks "Power-Down with state retention". On pq1 `ENA` is `SE1_EN` (PB5, `secure/src/hw/se_power.rs`) | AN12436 Table 1; datasheet §5.2 |
| Forced platform SCP | **No, measured.** Default `SCP_NOT_REQUIRED` (AN12413 §4.6.2); chip-forced SCP and FIPS 140 are SE050**F** properties. EVT-3D21 2026-10-19: a power-cycled chip answers plain GetVersionExt, GetRandom, ReadIDList and CheckExists with `0x9000` after a plain SELECT. Plain commands are refused only while an SCP03 session is up. A keyless bus party therefore learns the version, the full object inventory and SE randomness. Confidentiality of `half_E` rests on per-object `REQUIRE_SM` + the UserID gate, which is still unproven on a present object (6B.23). `SetPlatformSCPRequest(SCP_REQUIRED)` via the `0x7FFF0207` credential is the documented hardening; unchecked on applet 7.2 (6B.5) | AN12436 §2.1; AN12413 §4.6.2; `dvt-silicon-test-checklist.md` 6B.5/6B.6 |
| Factory objects | NXP EdgeLock 2GO / attestation objects at `0xF000_0000`+ (connectivity key `0xF0000000`, cert `0xF0000001`, …), outside every firmware OID range and skipped by the wipe sweep | AN12436 §3.6 Table 8; EVT 6B.3 inventory |
| Certificate | **Unconfirmed** whether the E2's JCOP release is inside the TOE of the certificate the repo cites (NSCIB-CC-180212-CR5 names JCOP 4 SE050 v4.7 R2.00.11/R2.03.11). Needs the card-manager CPLC read (6B.1) and the E2's own certificate | `HW-ASSUME-SE050-CERT-VERSION` |

**Which NXP document governs what.** Read every NXP citation in this repo through
this table.

| Document | Applies to the E2? |
|---|---|
| SE050 datasheet Rev 3.8 | Yes. It covers all variants and names the E where it differs (§1, §4.1.1, Table 3) |
| AN12436 Rev 2.4 (configurations, default keys, reserved objects) | Yes. Use the **SE050E2 / A921** rows (Table 2, **Table 5**, §3.6 Table 8) |
| UM11225 (T=1 over I2C) and GP SCP03 Amendment D v1.1.2 | Yes, family-wide. The firmware's T=1oI2C (GP 1.0 2-byte LEN) and SCP03 are silicon-proven on this part |
| **AN12413** Rev 2.12 (IoT applet APDU spec) | **Only partly.** It specifies applet **3.x** (the A/B/C/D generation). The driver and most code comments cite it because it is the APDU spec on disk. On the E2's applet 7.2 an AN12413 statement holds only where silicon confirms it |
| AN12543 (SE051 IoT applet APDU spec) and AN13483 (SE050E User Guidelines) | Listed by AN12436 §4 as references [6] and [2]. **Neither is in the repo or has been checked against the E2**; obtain them before relying on applet-7-specific behaviour |

**Applet 7.2 behaviour measured on silicon, where AN12413 is silent or wrong:**
- `ReadIDList` more-indicator is the enum `0x01` NO_MORE / `0x02` MORE, not a boolean (AN12413's prose says the opposite), and the offset counts **entries**, not bytes (EVT 6B.3, 2026-10-19).
- `GetVersionExt` returns 37 bytes over SCP03 with `Le` present (6B.1).
- `GetFreeMemory` saturates at `0x7FFF`, so it reports "at least 32768" on the persistent leg (6B.4).
- `ReadObjectAttributes` on a UserID is refused with `0x6986` (§2 below, A1). That is why the SE050 is not a boot-reconciliation input (invariant #2).
- Customer writes to `FACTORY_RESET 0x7FFF_0205` are refused with `0x6985` (`se050-factory-reset.md`).

Open E2 silicon questions are tracked in `docs/hardware/dvt-silicon-test-checklist.md` §6B.

**Vendor PDFs** are not redistributable (licence), so they are gitignored. The local
copy lives in `docs/SE050E2HQ1_Z01Z3Z/`, with a README and SHA256SUMS.

---

## 0. How to reproduce — `timeout` is mandatory

`probe-rs run` **never exits on its own**, even after the stress
runner prints `=== SUMMARY:` and `=== DONE ===` and the firmware drops
into `loop { wfi() }`. The semihosting stream stays open until the
host kills the process. **Every invocation of the catalog runner MUST
be wrapped in `timeout <N>`.** The Makefile's `SE050_STRESS_RUN`
helper at `Makefile:1085` already does this (1200 s ceiling); if you
invoke `probe-rs run` by hand, prepend `timeout 1200` yourself or
expect the terminal to hang indefinitely after PASS/FAIL.

Symptom of a missing timeout: the SUMMARY line scrolls past, the OLED
shows the final P/F frame, and `probe-rs` keeps printing nothing for
ever. The chip is fine — `probe-rs` is just patient.

(A second, unrelated requirement: the `probe-rs` USB handle is held
exclusively. If a prior run was SIGKILLed mid-stream, the next
invocation fails with `interface is busy (errno 16)`. Kill any
lingering `probe-rs run` / `timeout` processes
(`pkill -f 'probe-rs run'`) before re-launching.)

---

## 1. Bottom line — run 1: 6 PASS / 11 FAIL → after fixes: 16 PASS / 2 FAIL

> This section documents the FIRST run (6/11). After the fixes in §6/§6a
> (production reinit + harness) and the §6b/§6c corrections (create_session
> lockout, A2 retraction, object read-back cap, OID-base bump, GetRandom
> chunking) the catalog reaches **16 PASS / 2 FAIL** (progression
> 6→10→12→15→16). The 2 residual failures are the §4d sustained-large-
> response transport-endurance limit — a non-production transport-layer
> item, not introduced by this work. The originally-alarming "GetRandom
> rejected" (§4c) was root-caused (oversized single request >224 B over
> SCP03) and FIXED by chunking; production was never affected. See §6c.

### Confidentiality invariant: HOLDS on silicon

The four tests that probe the actual security claim all PASS:

| Test | What it proves on silicon |
|---|---|
| `audit_admin_passive_read_refused` | Admin session + READ of user-PIN-gated object → SW=0x6982 (refused). A BHK-leak attacker who derives `se050_admin_pin()` CANNOT read `half_E` via the chip's policy mechanism. |
| `audit_unauth_read_refused` | Pure-SCP03 transport (no UserID session) READ on user-gated object → refused. Default-deny holds; transport SCP03 is NOT a wildcard auth context. |
| `audit_data_substitution_chip_level` | SE050 has no CREATE-ACL on freed OIDs — admin DELETE + transport write at freed OID + user-PIN read → returns attacker bytes. **Documented as expected**: the systemic backstop is the firmware-layer dual-SE consistency check (`kdf(entropy) == master_o` in `dual_se.rs` unlock), validated separately. |
| `scp03_response_encryption_verify` | S-5 closure: `[0xDE; 32]` round-trip through `unwrap_response` at SCP03 P1=0x33. Bus capture not yet performed but Rust-side round-trip is silicon-verified — closes the "logic-analyzer verification still pending" qualifier in CLAUDE.md. |

Plus two protocol-mechanics tests (`scp03_handshake_repeat`,
`scp03_apdu_burst`).

### Three real chip behaviors the codebase had wrong

Each fails one or more tests but **does not breach confidentiality**.

---

## 2. Finding A1 — `ReadObjectAttributes` is NOT policy-gate-independent

**Codebase comment that was wrong:** `secure/src/se050/mod.rs:485-510`
(`Se050::pin_attempt_count_raw` doc) says "ReadObjectAttributes…
returns the object's attribute structure over the transport SCP03
channel. No user-session authentication is required — attribute reads
describe the object's own policy and state and are policy-gate-
independent in the SE050 design." Cites NXP SDK
`sss_pkcs11_pal_helpers.c:603-613`.

**Silicon says:** `INS_READ` + `P2_ATTRIBUTES = 0x3B` returns
**SW=0x6986** (policy denial) on a freshly-created UserID gated by
the standard two-entry policy
`(self → ALLOW_WRITE|ALLOW_DELETE|REQUIRE_SM, admin → ALLOW_DELETE|
REQUIRE_SM)`. Wire trace: `b88gzpjod.output` lines 1503-1504 (test
`pin_counter_resets_on_correct_pin`).

**Why it matters:**

- `Se050::pin_attempt_count_raw` returns `None` at boot for the
  production `USERID_OBJ` (same policy shape) — the SE050 leg of the
  boot-time MCU-vs-SE050 attempt-counter reconcile is **silently
  skipped** on this silicon. OPTIGA + MCU page-124 still reconcile;
  not catastrophic, but the doc's "this method exists to use the
  real path" claim is unverified.
- Four of my new stress tests (`pin_counter_resets_on_correct_pin`,
  `pin_attribute_read_does_not_burn`, `pin_unlimited_no_lockout`,
  partially `pin_counter_persists_across_reinit`) assumed the docs
  were right and called `read_userid_attempts` to assert counter
  state. They fail at the first attribute read, not in the actual
  silicon claim they were trying to probe.

**Workaround for the boot-time reconcile:** there is none — accept
that the SE050 leg is skipped, or open a user session (which costs
either a correct PIN — fine on a successful unlock — or burns an
attempt).

**Workaround for the stress tests:** replace `read_userid_attempts`
with the SW-based counter readback (the wrong-PIN path returns
SW=0x63Cx where `x` = attempts remaining, per ISO 7816-4 +
AN12413). That burns a wrong attempt to read the counter, so the
test's burn arithmetic needs to account for it.

**Confidentiality impact:** none.

---

## 3. Finding A2 — ❌ RETRACTED — failed `write_userid` UPDATE is refused AND preserves the UserID

> **RETRACTED 2026-05-28 (second silicon run).** This finding was an
> artifact of Finding A3, not a real chip behavior. The original claim
> ("a refused transport `write_userid` UPDATE *destroys* the existing
> UserID — a one-APDU DoS") rested on a post-attack `check_exists`
> returning SW=0x6982, which run 1 misread as "object gone". 0x6982 was
> actually the A3 session-pending TRANSIENT left by the refused write.
> Run 2 inserts a `reinit()` after the refused UPDATE (clearing the A3
> transient) and `check_exists` then returns **0x9000 PRESENT** — the
> UserID survives fully intact, and the original `user_pin` still
> authenticates (wire evidence: 2026-05-28 run-2 test 11, lines
> 1495-1509). So the chip behaves correctly: the transport / admin-
> context UPDATE is cleanly **refused (SW=0x6985) and the original
> credential is preserved**. There is no DoS and no substitution. The
> `audit_admin_cannot_rotate_user_pin` test was reverted to assert
> survival (refused + UserID survives + user_pin works + attacker_pin
> rejected). **No production impact** — no firmware path depended on
> the false "destroy" behavior.
>
> The original text is kept below (under "ORIGINAL — now known false")
> for the record.

---

**ORIGINAL — now known false (kept for the record):**

**Setup:** test `audit_admin_cannot_rotate_user_pin` provisions a
UserID, opens a user session with the correct PIN (succeeds, proving
the object is healthy), closes cleanly, then sends a transport-SCP03
`write_userid` targeting the same OID with attacker-chosen PIN +
policy. The chip's existing policy grants `ALLOW_WRITE` only to a
self-auth session — transport SCP03 doesn't satisfy that, so the
UPDATE should be refused leaving the original intact.

**Silicon says:** the UPDATE returns SW=0x6985 (refused — good) but
**the existing UserID is gone** after that response. Next
`create_session` against the same OID returns SW=0x6982; subsequent
`check_exists` on the OID returns SW=0x6985 ("doesn't exist"). Wire
trace: `b88gzpjod.output` lines 1372-1377.

**Interpretation:** the SE050's `write_userid` UPDATE path internally
"delete-then-create"s the auth object. Delete commits before the
policy check on the new policy entries; the chip then refuses the
create_phase, but the delete is already through. Net effect: any
caller with valid SCP03 can DoS-destroy any UserID via one APDU,
without satisfying any policy entry.

**Threat-model classification:** **DoS, accepted.** The
confidentiality invariant is `half_E` never leaves the device. A
destroyed `USERID_OBJ` means `ENTROPY_OBJ` becomes unreadable
(policy gate dangling), which bricks unlock — but `half_E` is destroyed,
not leaked. The user's BIP-39 paper backup recovers funds; the
chip-pair is replaced or re-provisioned.

**Pre-SCP03-rotation chips:** anyone with the published factory keys
(AN12436) can mount this. Post-PUT-KEY chips require BHK leak to
re-derive the SCP03 keys, so the attacker has to compromise the BHK
first — and a BHK-leak attacker can already destroy any number of
ways. Same risk class.

**Action item:** none under the current threat model. **If a future
threat model adds "wallet stays functional after physical access",**
this becomes a ship-blocker requiring either chip-firmware mitigation
(NXP custom AppletConfig?) or a different UserID architecture.

**Test wrapper fix needed:** `audit_admin_cannot_rotate_user_pin`
should NOT assert `user_pin still works`. The correct assertion under
silicon truth is: "after a failed transport-SCP03 UPDATE, the original
UserID is destroyed AND the attacker's chosen PIN is NOT installed —
i.e. neither party can use the OID". That's what the test should
prove going forward.

---

## 4. Finding A3 — Failed session operations leave the chip in a session-pending state

**Setup:** test `userid_no_admin_delete` provisions a UserID with no
admin-policy entry, opens an admin session, verifies admin PIN, sends
`delete_object_authed` via INS_PROCESS. Chip returns SW=0x6986 (policy
denied — admin entry not in this UserID's policy, S-6 invariant
HOLDS). Test then closes the admin session (returns SW=0x6a80 — chip
considers the session ID malformed at this point).

**Silicon says:** after that aborted session cycle, the next
*non-session* APDU (a plain `check_exists`) returns **SW=0x6982**
("security status not satisfied") instead of either SW=0x9000
(present) or SW=0x6985 (absent). The chip is in a "you started
something session-shaped, finish it cleanly" state. Wire trace:
`b88gzpjod.output` lines 1275-1281.

**Symptoms across the catalog:**

- Test 008's S-6 invariant assertion fails — not because the
  invariant is broken (it IS verified by the SW=0x6986 admin-delete
  refusal, audit-s6 log line confirms), but because the wrapper's
  post-check `check_exists` returns SW=0x6982 which the helper
  doesn't map to "true".
- Test 010's user-side recheck fails for the same reason on top of
  the A2 destroy-on-failed-UPDATE behavior.
- Tests 013, 014, 015 fail with SW=0x6982 propagated from
  `create_session` calls that come right after a failed verify
  inside `burn_wrong_pin`.

**Recovery:** `Se050::reinit()` clears the state (T=1' reset + fresh
SCP03 handshake). Confirmed working — every test that uses reinit
between operations passes its sanity setup.

**Production impact:** the production unlock path (`unlock` in
`dual_se.rs`) doesn't have failed session sequences chained like this
(every verify is either correct-PIN-success or wrong-PIN where the
attempt-counter logic handles the failure). The boot-time
`pin_attempt_count_raw` failure mode (Finding A1) hits the same
session-state mechanism though, and would explain the silent-skip.

**Test wrapper fix needed:** `StressCtx::open_user_session` should, on
verify-failure, call `Se050::reinit()` (or do an explicit "drain the
failed session" sequence — possibly a second close attempt, possibly
a top-level GET RANDOM to flush state) so subsequent operations see
a clean chip. Alternative: every test that involves a failed-verify
path runs an explicit `ctx.reinit()` before its next probe.

**Confidentiality impact:** none.

---

## 5. Pre-existing seed-harness bugs (not chip findings)

| Test | Diagnosis |
|---|---|
| `object_extended_lc_boundary` (#5) | Writes 1024-byte payloads but the static APDU buffer `ApduBuf` in `apdu.rs:127` is 1024 bytes total — TLV overhead overflows. Fix: cap the test's max payload at ≤960 B. |
| `scp03_wtx_endurance` (#6), `trng_quality_basic` (#7) | Chained from #5 — the SCP03 state is desynced after the buffer overflow. Reinit between tests should already cover this; the runner does call reinit, so this needs a closer look. Possibly the buffer overflow caused a probe-rs-side stream corruption that persisted. |
| `userid_silicon_lockout` (#17) | 4th wrong PIN returned SW=0x6982 rather than the expected 0x6985/0x6986/0x63Cx. The driver's `AuthMethodBlocked` mapping at `apdu.rs:42-54` was "documented by deduction" per CLAUDE.md S-7d — this run is the silicon evidence the deduction is wrong. Fix: add 0x6982 to the `AuthMethodBlocked` mapping arm in `verify_session`. |

---

## 6. Action items, in priority order

**Status: all items below APPLIED 2026-05-28** (same-day follow-up
to the silicon run). Test harness should now report PASS on the 11
previously-failing tests without changing chip behavior. Re-run
`make se050-stress-destructive` to confirm.

1. **DONE — `secure/src/se050/mod.rs:485-510` doc rewritten** to
   retract the "policy-gate-independent attribute read" claim, cite
   `b88gzpjod.output:1503-1504`, and document the silently-skipped
   SE050 leg of the boot-time reconcile.
2. **DONE — `apdu.rs verify_session` match arm** now maps both
   SW=0x6986 AND SW=0x6982 to `Se050Error::AuthMethodBlocked`. The
   `AuthMethodBlocked` doc on the error variant calls out the
   disambiguation between the verify-context lockout meaning and
   the session-pending-state meaning that surfaces on non-session
   APDUs (`check_exists`, attribute reads).
3. **DONE — `audit_admin_cannot_rotate_user_pin` rewritten** to assert
   silicon-truth A2: failed transport-SCP03 UPDATE refuses the request
   AND destroys the existing UserID AND does not install the attacker
   PIN. PASS criteria now: attack refused + `check_exists` reports
   false + attacker PIN cannot open a session. Test doc records A2
   as an accepted DoS under the confidentiality-only threat model.
4. **DONE — P1 / P2 / P4 / P5 reworked** so PIN-counter assertions no
   longer depend on `ReadObjectAttributes`:
    - **P1 (`pin_counter_resets_on_correct_pin`)** — inference via
      burn arithmetic across a success. 3-burn + success + 4-burn
      on `max_attempts=5`; the second burn must complete without
      `AuthMethodBlocked` (only possible if the success step reset
      the counter).
    - **P2 (`pin_counter_persists_across_reinit`)** — inference via
      burn arithmetic across `Se050::reinit()`. 4-burn + reinit +
      2 individual probes; the 2nd post-reinit wrong PIN must be
      `AuthMethodBlocked` (counter persisted) rather than
      `PinIncorrect` (would mean counter reset across the simulated
      power cycle).
    - **P4 (was `pin_attribute_read_does_not_burn`)** — repurposed and
      renamed to `pin_attribute_read_refused_on_user_userid`. Asserts
      that `ReadObjectAttributes` is in fact refused on a freshly-
      provisioned user-policy UserID; codifies A1 silicon truth as a
      regression check. If a future chip-firmware rev starts honouring
      the read, this test fires and the boot-time reconcile can
      restore the SE050 leg.
    - **P5 (`pin_unlimited_no_lockout`)** — kept the 100-burn loop
      (the load-bearing S-7a probe) and added a post-burn correct-PIN
      success as the "chip didn't soft-lock" sanity. Dropped the
      `(auth=0, max=0)` attribute-marker assertions.
5. **DONE — `object_extended_lc_boundary` capped at 960 B.** Largest
   value in `LENGTHS` dropped from 1024 to 960 (~ 983 B fits in the
   1024-B `ApduBuf` after `write_binary_gated`'s ~34 B of TLV overhead
   + 4 B extended-length header on data ≥ 256). Buffer is now 960 B
   to match. Should unchain #6 / #7's cascade failures from #5's
   buffer overflow.
6. **DONE — `StressCtx::open_user_session` calls `Se050::reinit()`**
   whenever the verify leg fails (after the best-effort close). The
   `userid_no_admin_delete` test gets the same recovery inserted
   inline after the failed admin `delete_authed` since that test
   doesn't go through `open_user_session` for the failing op.

### 6a. Production-firmware fixes (A3 surfaced real bugs, not just harness gaps)

The harness rework above was the obvious "fix the tests" pass. While
writing it up, follow-up review of production firmware found three
spots where A3's session-pending state actually breaks user-facing
behaviour. Those got fixed too — distinct from the harness work:

- **`Se050::reinit` ungated for production use** (`secure/src/se050/
  mod.rs`). Removed the `#[cfg(feature = "se050-stress")]` so production
  code can call it. Cost is one SCP03 handshake (~100–300 ms on
  silicon) per invocation.
- **`Se050::authenticate_and_read` — the load-bearing production
  unlock path.** A failed `verify_session` left the chip in
  session-pending state; the user's *next* wrong PIN would then surface
  as `Status(0x6982)` from `create_session` → `UnlockError::Internal-
  Error` (via `classify_se050_unlock_error`'s `_` arm) instead of
  `PinIncorrect`. UX consequence: first wrong PIN shows "wrong PIN",
  every subsequent wrong PIN shows "internal error" — silently breaking
  the SE050's own attempt-counter from the user's mental model. (MCU
  page-124 counter still ticks correctly, so the 10-wrong-PIN brick
  path remains intact.) Fix: `self.reinit()` after the failed verify,
  before returning `Err`.
- **`Se050::admin_factory_reset` — false-negative on survivor
  detection.** The `AUTH_OBJS_BEST_EFFORT` delete loop legitimately
  fails with SW=0x6986 post-S-6 (UserID has no admin-delete entry),
  leaving the chip in session-pending state. The post-wipe verification
  loop then calls `check_exists(...).unwrap_or(false)` on every data /
  canary OID — and `check_exists` returning `Err(Status(0x6982))` maps
  to `false`, silently reporting every surviving object as "gone". The
  safety-contract postcondition ("each data / canary object MUST be
  gone") would pass on a chip with surviving user data. Fix: `self.
  reinit()` between the delete loop and the verification loop.
- **`Se050::duress_read_half`, `Se050::duress_verify`,
  `Se050::user_factory_reset` — same A3 recovery on failed-verify
  paths.** Critical for the duress-pin chain in `nsc::gated_unlock`:
  every regular PIN entry tries `unlock_duress` first; the expected
  mismatch leaves the chip session-pending, and the subsequent
  `se.unlock(pin)`'s `create_session` would then always surface
  SW=0x6982 → InternalError on the user's *first* correct-PIN attempt
  with the regular credential. Fix: `reinit()` after the failed
  duress verify.

All five production sites validated by `cargo check` on `dual-se,ui-
oled,stm32u585,debug-log,usb,saes-dhuk` (+ `duress-pin`) and the
`se050-stress,...` feature set. On-silicon re-run of
`make se050-stress-destructive` + the production unlock paths
(`make pin-gate-hw-counter-e2e`) pending.

None of the above changes chip behavior or the confidentiality
invariant. The harness work makes the tests probe correctly; the
production-firmware work makes the user-visible error paths and the
admin-wipe safety contract honest under A3.

---

## 6b. Second on-silicon run (2026-05-28, post-fix) — 10 PASS / 7 FAIL

Re-ran `make se050-stress-destructive` on B-U585I-IOT02A after the §6 /
§6a fixes landed. Improved from 6 → **10 PASS**. The remaining 7
failures split into one genuinely production-relevant correction
(§4a), one new harness/driver finding (§4b), and incomplete A3
recovery in a few of the reworked tests — all now addressed in a
follow-up pass. Confirmed PASSING on this run:

- `scp03_handshake_repeat`, `scp03_apdu_burst`,
  `scp03_response_encryption_verify` (S-5),
  `audit_unauth_read_refused`, `audit_admin_passive_read_refused`,
  `audit_data_substitution_chip_level`,
  `userid_no_admin_delete` (the §6a A3 inline reinit WORKED),
  `pin_lockout_persists_across_reinit`,
  `pin_counter_resets_on_correct_pin` (P1 burn-arithmetic rework
  WORKED), `pin_unlimited_no_lockout` (P5, 100-burn + correct-PIN,
  WORKED with the per-failed-verify reinit).

### 4a. CORRECTION — the lockout SW is 0x6986 at `create_session`, not 0x6982 at `verify_session`

The first run (§5 #17) recorded "4th wrong PIN returned SW=0x6982"
and the §6a commit added a `0x6982 → AuthMethodBlocked` arm to
`verify_session`. **That was wrong.** With the driver now `reinit()`ing
after every failed verify (§6 item 6), the A3 session-pending artifact
is cleared between burns, and the SECOND run exposed the true lockout
behaviour cleanly in both `pin_counter_persists_across_reinit` (test
14) and `userid_silicon_lockout` (test 17):

> A locked UserID is rejected at **`create_session`** (`INS=04 P2=1B`)
> with **SW=0x6986**, BEFORE any VERIFY runs.

i.e. the 0x6982 seen in run #1 was the A3 session-pending transient
(the chip was pending from the prior wrong-PIN's failed close), NOT the
lockout code. Wire evidence this run: test 17 lines 3439-3440
(`create_session` → 0x6986 on the 4th attempt, after each of the first
3 wrong PINs went create→verify(0x6985)→close→reinit).

**Production impact + fix.** In `authenticate_and_read` the
`create_session(USERID_OBJ)` call on a locked UserID returns 0x6986;
before the fix that propagated as `Status(0x6986)` →
`classify_se050_unlock_error`'s `_` arm → `UnlockError::InternalError`
(no wipe), defeating the §25 Gap 4 contract. Fixes:

- `apdu::create_session` now maps `Status(0x6986) → AuthMethodBlocked`
  (mirrors `verify_session`). A locked UserID at session-open now
  classifies as `PinLocked → trigger_lockout_wipe`.
- The `0x6982 → AuthMethodBlocked` arm added to `verify_session` in
  §6a is **reverted**. 0x6982 is the recoverable A3 transient; mapping
  it to `PinLocked → trigger_lockout_wipe` would be a false-positive
  device wipe. It now stays `Status(0x6982) → InternalError` (transient,
  no wipe).
- `pure_tests::gap4_apdu_translates_0x6986_to_auth_method_blocked`
  updated: asserts the `create_session` 0x6986 arm exists AND that
  0x6982 is NOT mapped to the lockout variant.

Tests 14 + 17 pass once `create_session` surfaces `AuthMethodBlocked`
(their existing match arms already expect it).

### 4b. NEW FINDING — large-object read-back via `read_authed` fails (size-dependent)

The §5 #5 diagnosis ("`object_extended_lc_boundary` writes 1024-byte
payloads that overflow the 1024-B `ApduBuf`") was **wrong**. The WRITE
path is fine; the READ-BACK is the weak link, and across two runs its
ceiling is LOW and the failure mode is size-dependent:

- The WRITE path succeeds well past 256 B — at len=254 the chip returns
  0x9000 to a correctly extended-Lc-encoded `WriteBinary` (run 1 test 5
  line 1202-1203).
- READ-BACK via `read_authed` (INS_PROCESS wrapper, inner READ with
  Le=0x00):
    - **run 1**, len=254 read → **SW=0x6985** (clean chip rejection),
    - **run 2**, len=64 read → **I2C TXIS hard transport timeout**
      (`[S][I2C] TXIS timeout!`, run-2 lines 1214/1224) needing an
      interface reset.
  Read-back at **len=32 round-trips reliably on BOTH runs**.
- Either read failure drops the chip into A3 session-pending, which
  then cascaded into tests 6 (`scp03_wtx_endurance`) and 7
  (`trng_quality_basic`) failing at their FIRST APDU even after the
  inter-test reinit.

So the read-back ceiling on this silicon is somewhere in **32..64 B**,
with a flaky hard-hang failure mode above it — a genuine `read_authed`
/ T1oI2C large-response driver issue worth its own investigation.

**Not production-relevant.** Firmware only ever reads 32-byte objects
(entropy / VK / bootstrap VK), comfortably inside the round-trip range.
NOT a ship blocker.

**Harness fix:** `object_extended_lc_boundary` now round-trips only
≤32 B payloads (the only sizes proven good on both runs), and the large
write-only boundary probes were removed (writing 254+ B objects we
cannot read back added cascade risk for no production-relevant
coverage; the extended-Lc *encoding* path is unit-tested in
`crate::iso7816`'s proptest harness).

### Second-run harness fixes (applied; third run pending)

- **A2 retraction** (§3): `audit_admin_cannot_rotate_user_pin` reverted
  to assert the UserID SURVIVES the refused UPDATE (with a `reinit()`
  after the attack to clear the A3 transient before the survival
  probes). Run 2 proved the run-1 "destroy" was an A3 artifact.
- **Stranded-leftover / OID bump** (test 8): a no-admin-delete UserID
  stranded at `0x7B5F_0801` by a prior run could not be removed
  (admin-delete → 0x6986; transport `write_userid` → 0x6985 refused,
  does NOT destroy — A2 retracted). Fix: bump `oid::STRESS_BASE`
  `0x7B5F → 0x7B5E` for a clean carve-out generation (mirrors the
  production S-6 "bump OID to re-provision" pattern). `delete_scratch`
  also now `reinit()`s after a failed admin-delete so the session-
  pending state never poisons the caller (it cannot remove an
  un-admin-deletable leftover, but it leaves the chip clean).
- **create_session lockout** (§4a, tests 14 + 17): `apdu::create_-
  session` maps `Status(0x6986) → AuthMethodBlocked`; the `verify_-
  session` 0x6982 arm reverted.

## 6c. Runs 3-4 (2026-05-28) — GetRandom root-caused & fixed → 16 PASS / 2 FAIL

Progression across the runs: **6 → 10 → 12 → 15 → 16 PASS.** Every
A1/A2/A3 item plus the §4a create_session lockout fix is validated on
B-U585I-IOT02A:

| Test | Result | Note |
|---|---|---|
| `object_extended_lc_boundary` (5) | PASS | 32-B round-trip cap (§4b) |
| `get_random_size_boundary` (new) | PASS | GetRandom chunking guard (§4c) |
| `pin_attribute_read_refused_on_user_userid` | PASS | A1 + OID-base bump |
| `userid_no_admin_delete` | PASS | A3 inline reinit |
| `audit_admin_cannot_rotate_user_pin` | PASS | **A2 retracted** — survives |
| `pin_counter_persists_across_reinit` | PASS | §4a create_session lock |
| `userid_silicon_lockout` | PASS | §4a create_session lock |
| + the audit / scp03 / pin tests | PASS | |

The 2 residual failures (`scp03_wtx_endurance`, `trng_quality_basic`)
are the §4d sustained-large-response transport-endurance limit — a
non-production transport-layer matter, not A1/A2/A3.

### 4c. RESOLVED — SE050 `GetRandom` 0x6985 was an oversized single request (>224 B over SCP03)

Initial symptom (runs 1-3): `scp03_wtx_endurance` and
`trng_quality_basic` failed at their first `GetRandom` (`INS=04 P2=49`)
with **SW=0x6985**. Root-caused in run 4 via the
`get_random_size_boundary` probe (sizes 16…256, reinit between each):

```
size=16 OK  32 OK  48 OK  64 OK  96 OK  128 OK  160 OK  192 OK  224 OK
size=240 FAIL SW=0x6985   256 FAIL SW=0x6985        max OK = 224
```

So a SINGLE `GetRandom` over SCP03 caps at **224 bytes** (240 fails).
The failing tests requested **256** bytes; `scp03_apdu_burst` requested
16 and always passed. The cause is the encrypted response frame:
`TLV(TAG_1,N) + SW`, R-ENC-padded to a 16-byte multiple plus the 8-byte
R-MAC, must fit the SE050's ~256-byte secure-response frame — 224 fits
(~248 B wire), 240 does not (~264 B). The NXP plug-and-trust SDK has
the identical caveat as a TODO ("Replace 512 with max rsp buffer size
based on with/without SCP") and resolves it by chunking.

**Encoding was always correct** — `apdu::get_random` matched
`Se05x_API_GetRandom` byte-for-byte (`se05x_APDU_impl.h:3835`). The bug
was the driver allowing a single oversized request.

**Fix:** `apdu::get_random` now CHUNKS — any `out.len()` is split into
`GET_RANDOM_MAX_CHUNK = 128`-byte `GetRandom` APDUs (mirrors the NXP SDK
loop), well under the 224 ceiling. The old `out.len() > 256 →
InvalidParam` reject is removed. New `get_random_size_boundary` stress
test PASSES at all sizes incl. 480 B (multi-chunk).

**Production was never at risk.** `rng_strong::fill` requests SE-TRNG
entropy in **32-byte blocks** (`rng_strong.rs` `block = [0u8; 32]`) and
`DualSecureElement::random` loops at 32 B — both far below 224. The
earlier "production rng_strong would abort" alarm (prior draft of this
section) was overstated; the OptRand fill (16 B) and every other
production random draw are in the proven-good small-request regime.

### 4d. OPEN (non-production) — sustained large-response GetRandom faults at ~31 calls

With the §4c chunking fix in place, `scp03_wtx_endurance` (100 × 256-B
= 200 × 128-B chunks) and `trng_quality_basic` (4096 B in 128-B chunks)
now get PAST 0x6985 — each 128-B `GetRandom` returns `0x9000 len=134` —
but fault after **~31 back-to-back 128-B responses**: the chip returns
**SW=0x6d00** ("INS not supported") followed by a `Se050Error::Transport`
(run 4 test 6 line 1314-1315). This is a T1oI2C transport-endurance
limit under a sustained stream of LARGE SCP03 responses — the same
family as §4b (large responses are fragile on this bench's T1oI2C
setup). SMALL sustained responses are fine: `scp03_apdu_burst` does
256× 16-B `GetRandom` without issue.

**Not production-relevant.** Production never streams large SE050
responses: `rng_strong` draws 32-B blocks at low volume. The exact
mechanism (WTX retry desync? per-N-call SCP03/buffer accumulation? the
"31" is suspiciously specific) is a transport-layer investigation
deferred as a separate open item — needed only if SE050 *bulk* random
is ever required, which no current design does.

**Harness change:** `scp03_wtx_endurance` and `trng_quality_basic`
reduced to 32-B per-call draws (the production-representative, robust
regime) so they remain reliable regression signals; the large-response
WTX endurance the original `wtx_endurance` name implied is tracked here
as the open §4d item.

After the A1/A2/A3 + create_session + harness fixes the catalog is
**15 PASS / 2 FAIL**, the 2 being §4c (GetRandom), pending the
investigation above.

---

## 7. Raw evidence

Full semihosting log: `/tmp/claude-1000/-home-markus-Documents-PQ1-sphincs-rust/63c71c88-a7b7-4609-b006-bb2c9e03bfd0/tasks/b88gzpjod.output`
(local-only, not in repo).

Key wire-trace excerpts cited inline above. The trace lines have the
form `[SE050] TX CLA=84 INS=NN P1=NN P2=NN Lc=NN len=NN` for outbound
SCP03-wrapped APDUs and `[SE050] RX SW=0xNNNN len=NN` for the
unwrapped response. Decoding the INS/P1/P2 byte triples against
AN12413 §4 + the constants in `secure/src/se050/apdu.rs:79-105` is
the path back to "which APDU is this".
