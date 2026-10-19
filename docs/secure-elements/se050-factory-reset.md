# SE050 Factory Reset — Design and Production Checklist

> **OID range note (2026-04-30 audit).** The OID values shown throughout this doc
> (`0x7B06_xxxx`) are from the **v3 era** and have since been retired. The shipping
> range is **v6 = `0x7B10_xxxx`**:
>
> | Symbol             | This doc (v3)   | Shipping (v6)   |
> |--------------------|-----------------|-----------------|
> | `USERID_OBJ`       | `0x7B06_0000`   | `0x7B10_0000`   |
> | `ENTROPY_OBJ`      | `0x7B06_0001`   | `0x7B10_0001`   |
> | `VK_OBJ`           | `0x7B06_0002`   | `0x7B10_0002`   |
> | `BOOTSTRAP_VK_OBJ` | `0x7B06_0003`   | `0x7B10_0003`   |
> | `ADMIN_WIPE_OBJ`   | `0x7B06_00A0`   | `0x7B10_00A0`   |
> | Canary objs        | `0x7B06_00B0…`  | `0x7B10_00B0…`  |
>
> Authoritative constants: `secure/src/se050/mod.rs:53,56,59,62,83`. Range
> history (v1 → v2 → v3 `0x7B06_xxxx` → v4 `0x7B0C_xxxx` → v5 → v6) is
> documented at `secure/src/se050/mod.rs:23-30`.
>
> **Admin PIN derivation has also evolved.** Historical §2 text described a
> TRNG-generated admin PIN persisted to flash page 125. The current PIN is
> root-derived via `secure/src/hw/secret_keys.rs::se050_admin_pin()` on the
> BHK axis (DHUK fallback when `bhk` is disabled).
> Page 125 still hosts the wipe flag, but the admin PIN no longer needs flash
> persistence — it's deterministic per device and re-derives on every boot.
> §2a's "future optimisation — HUK-SAES derivation" has effectively landed.
>
> The two-entry TAG_POLICY design, the wipe flow, and the round-trip selftest
> remain in the current implementation. The old page-125 PIN storage described
> in the historical section below is retired.
>
> **Current first-field credential axes (2026-07-15).** Factory transport
> credentials are derived from the factory-burned per-device OTP master via
> the `transport_*` helpers. The implemented `rdp2-self-lock` candidate rotates
> SE050 SCP03 and admin credentials to final BHK-axis derivations, and rotates
> the OPTIGA E140 PBS to a final DHUK derivation bound to a fresh TRNG salt
> persisted in the page-127 journal. It is implementation evidence, not a
> production-approved ceremony. Authenticated per-unit handoff and
> authenticate-before-rotate, durable old/new/KVN recovery, the exact E140
> lifecycle-versus-final-rotation order, and silicon receipts remain gates.

## Why this document exists

The PQSigner wallet uses a hardware-enforced PIN on the NXP SE050 secure
element (UserID at `0x7B06_0000`, max 10 attempts before permanent
lockout). After lockout, firmware must be able to wipe every stored
secret so the user can restore from their 24-word BIP-39 backup on the
same physical device. This file explains how that wipe is structured,
why the obvious alternatives don't work, and what needs to change when
moving from dev boards to production silicon.

## What we tried that did NOT work

### Approach 1 — bare `DeleteAll` APDU via `RESERVED_ID_FACTORY_RESET`

NXP's SE05x spec defines a single-APDU nuclear wipe:
`CLA=0x80 INS=0x04 P1=0x00 P2=0x2A`. It wipes everything in one shot but
requires an authenticated session against
`kSE05x_AppletResID_FACTORY_RESET = 0x7FFF_0205`. On the
OM-SE050ARD-E dev shield (SE050E2HQ1/Z01Z3), **customer writes to
`0x7FFF_0205` are rejected with `SW=0x6985`** ("conditions not
satisfied"). The slot is reserved for NXP personalisation at the chip
factory, and we get no access to it on dev parts.

Evidence: no example in `plug-and-trust` anywhere creates
`0x7FFF_0205`. The SetPlatformSCPRequest API at
`hostlib/hostLib/se05x_03_xx_xx/se05x_APDU_apis.h:385` mentions it only
as an auth requirement, never as a create target.

### Approach 2 — iterative delete under plain PlatformSCP03 channel auth

This is what `Se05x_API_DeleteAll_Iterative` does (see
`plug-and-trust/hostlib/hostLib/se05x/src/se05x_mw.c:22-78`). For each
object returned by `ReadIDList`, it calls `DeleteSecureObject` over the
current SCP03 channel. It works only for objects whose policy either
permits deletion under the default channel OR has no restrictive per-object
auth gate.

**It fails on every object that has `auth_obj_id = <UserID>` in its
TAG_POLICY** — SE050 enforces the policy regardless of channel, and
channel-level SCP03 auth does NOT implicitly satisfy a policy entry with
`auth_obj_id = 0x7FFF_0207` (that reserved ID is only used for
SetPlatformSCPRequest, not as a universal "admin" marker). After the
user PIN gets locked out, the UserID can no longer authenticate anyone,
so `delete_object_authed` can't run either. Every UserID-gated object
becomes unreachable.

## Historical v3 flash-PIN design (retired)

The following section preserves the original rationale for the two-entry
policy and crash-resumable wipe. Its TRNG-generated page-125 admin-PIN storage
is historical and must not be read as the current credential lifecycle; the
current axes and first-field candidate are summarized above and in the
production checklist.

Every gated user object carries a **two-entry TAG_POLICY**:

| Entry | `auth_obj_id`          | `ar_header`                          | Purpose                         |
|-------|------------------------|--------------------------------------|---------------------------------|
| 1     | UserID `0x7B06_0000`   | READ \| WRITE \| DELETE \| REQUIRE_SM| Normal operation (PIN-gated)    |
| 2     | ADMIN `0x7B06_00A0`    | DELETE \| REQUIRE_SM                 | PIN-lockout wipe                |

`ADMIN_WIPE_OBJ = 0x7B06_00A0` is a secondary UserID provisioned at
first boot with a 16-byte PIN generated via the STM32 TRNG and
persisted to secure flash page 125 (`0x0C0F_A000`):

```
// In secure/src/hw/flash.rs page 125 layout:
//   QW 0 (offset  0..15): admin PIN (16 bytes from rng::fill())
//   QW 1 (offset 16..31): wipe flag (byte 0: 0x00 armed / 0xFF blank)
```

The admin PIN never leaves the TrustZone secure world. On first boot
`Se050::provision()` checks `is_admin_pin_blank()`; if true, generates
a fresh PIN via `rng::fill()` and writes it to QW 0. On subsequent
boots it reads the existing PIN. The full page is erased as the final
step of any factory reset, so PIN + flag are atomically cleared together.

This approach is deliberately independent of the OPTIGA Platform Binding
Secret — an earlier iteration derived the admin PIN from the PBS, which
broke SE050-standalone builds (no PBS) and couldn't work for users who
have the SE050 shield without an OPTIGA chip attached. The current
design works for every combination (SE050 alone, dual-SE, future
variants) because the admin state lives on the STM32 side, where
secure flash is guaranteed to exist.

### Admin-wipe policy construction (apdu.rs)

```
TAG_POLICY value (18 bytes for 2-entry):
  [0x08] [auth1:4 BE] [ar1:4 BE]   ← entry 1
  [0x08] [auth2:4 BE] [ar2:4 BE]   ← entry 2
```

Entries are OR'd: if ANY entry's `auth_obj_id` is satisfied by the
current session AND that entry's `ar_header` permits the requested
operation, the operation succeeds. The admin entry has **only
ALLOW_DELETE + REQUIRE_SM** — never ALLOW_READ. That preserves the
hardware-enforced PIN gating on entropy: the admin credential can wipe
the chip but cannot exfiltrate the seed.

### Wipe flow

```
PIN attempt #10 fails
  ↓
SE050 hardware locks UserID (SW=0x6983 on next CreateSession)
  ↓
firmware: read admin_pin from flash page 125 QW 0
          arm wipe flag at page 125 QW 1 (1→0 bit-clear)
  ↓
SE050 admin session:
  CreateSession(ADMIN_WIPE_OBJ)
  VerifySessionUserID(admin_pin)
  DeleteSecureObject_authed(ENTROPY_OBJ)
  DeleteSecureObject_authed(VK_OBJ)
  DeleteSecureObject_authed(BOOTSTRAP_VK_OBJ)
  DeleteSecureObject_authed(USERID_OBJ)       ← user UserID — post-S-6
    shipping builds: FAILS 0x6986 BY DESIGN (the user/duress UserIDs
    carry no admin-delete entry; the wipe removes the data objects and
    the UserID stays locked). Bench images (#912) keep the admin-delete
    entry so this delete succeeds there.
  DeleteSecureObject_authed(ADMIN_WIPE_OBJ)   ← self-delete
  CloseSession
  ↓
best-effort unauthenticated sweep (iterative_delete_all) for legacy stragglers
  ↓
erase_admin_page()  ← clears the wipe marker / legacy admin area
(dual-SE orchestrator also wipes OPTIGA user objects; page 126 is untouched)
  ↓
zeroize all SRAM state
  ↓
return PinLocked → NS side reboots into first-boot wizard
```

### Crash safety

The wipe flag at `ADMIN_PAGE_ADDR + 16` is armed via a 1→0 bit-clear
(NOR flash allows this without pre-erase, so the admin PIN at QW 0 is
preserved and the wipe routine can still authenticate). If power is
cut mid-wipe, the flag remains set on reboot. The boot path in
`secure/src/main.rs` checks `is_wipe_armed()` before any unlock attempt
and calls `factory_reset_admin()` again (idempotent — duplicate deletes
are harmless, the SCP03 session is re-established from scratch). The
flag is only cleared by the final `erase_admin_page()` call, which runs
after SE050 wipe is verified clean.

### Round-trip self-test during first-boot

`policy_roundtrip_selftest` writes a canary UserID + gated data object
to `0x7B06_00B0/B1` with the same two-entry policy template, then
exercises the admin-delete path end-to-end. If the canary survives, the
TLV byte layout is broken (has happened before — see git history for
the garbled-policy orphans at `0x7B00_xxxx`). First-boot provisioning
aborts with a fatal panic rather than shipping a wallet that cannot
recover from PIN lockout.

This is the guardrail that prevents a future refactor from
re-introducing the unwipeable-orphan problem.

## Production checklist

### 1. PlatformSCP03 keys

Published NXP keys are historical bring-up credentials, not the candidate
factory handoff. The candidate factory transport keyset comes from the
factory-burned per-device OTP master through
`transport_se050_scp03_{enc,mac,dek}()`; those labels are disjoint from every
final credential label. The final `se050_scp03_{enc,mac,dek}_key()` helpers
derive on the BHK axis (DHUK fallback only in builds without `bhk`).

The journaled `rdp2-self-lock` candidate implements the transport-to-final
rotation, but does not approve it for production. The separate
`se050-rotate-scp03` halt path remains sacrificial validation evidence, not the
field protocol. Production remains blocked on authenticated per-unit handoff
and authenticate-before-rotate, durable old/new/KVN recovery and atomicity,
the exact OPTIGA E140 lifecycle-versus-final-rotation order, and silicon
receipts. This document does not authorize `PUT KEY` on a real unit.

### 2. Lifecycle of ADMIN_WIPE_OBJ PIN

The admin PIN is reproducibly derived by
`hw::secret_keys::se050_admin_pin()` on the BHK axis and has no flash
representation. Page 125 carries the non-secret wipe marker/legacy hygiene
area; `erase_admin_page()` clears that marker but does not rotate the derived
credential. Re-pairing requires the reviewed BHK/root lifecycle, not a flash
PIN rewrite.

The factory transport admin PIN is a distinct OTP-master-derived credential
from `transport_se050_admin_pin()`. The production contract requires the
transport state to authenticate before it can be replaced with the final
BHK-axis admin PIN; that authenticate-before-rotate evidence and the
old/new/KVN recovery contract remain production gates.

### 2a. Transport-to-final admin rotation — implemented candidate

The final admin credential uses the BHK/DHUK SAES KDF with domain tag
`"pqsigner/se050-admin-pin-v1"`; in the intended `bhk` build this is the BHK
axis. The final root never leaves silicon, and only the derived credential is
presented inside the secure channel. The factory transport credential instead
uses the per-device OTP master and the disjoint
`"pqsigner/transport/se050-admin-pin-v1"` label. The candidate code performs
that replacement, but production approval still depends on the handoff,
authenticate-before-rotate, durable recovery, ordering, and silicon gates
listed above.

### 3. Attestation-based device pairing (not yet implemented)

Today we trust any SE050 that presents a valid SCP03 handshake. A
production build should also verify the SE050 certificate chain against
a pinned NXP root CA + a pinned per-device UID, to defend against
chip-swap attacks. This is orthogonal to factory reset but sits in the
same boot-time init path — bundle them.

### 4. UI for lockout warnings

`secure/src/nsc/cmd_request_unlock.rs` now shows "LAST ATTEMPT — wallet
wipes on fail" on the 9th consecutive wrong PIN. For production, also
show an educational screen during the wipe itself ("Wiping — do not
power off") and a post-wipe screen telling the user their wallet can be
restored from the 24-word backup (wallet address, bootstrap pubkey hash,
and on-chain state are all unchanged after restore).

### 5. Dev chips vs production chips

Do NOT reuse dev chips across firmware generations without a fresh
provision. Our earlier dev chip accumulated 6 unwipeable orphans at
`0x7B00_xxxx` / `0x7B06_0000` because older firmware created objects
without the admin-delete policy entry. Those objects remain stuck
forever on that specific chip — only a fresh OM-SE050ARD-E (or a real
production part) is clean.

For ongoing dev work on such a polluted chip, migrate the production
OID range (`0x7B06_xxxx` → `0x7B08_xxxx` or similar) to avoid slot
collisions. This is a separate one-time change; the admin-wipe design
itself does not depend on the OID range.

## What NOT to do

- **Do NOT remove the admin-delete policy entry from the DATA objects.** The entropy/VK/bootstrap-VK blobs must keep two TAG_POLICY entries (user + admin); objects without entry 2 cannot be recovered from PIN lockout and are orphans-by-design. **UPDATE 2026-10-19 (S-6 exception):** the user and duress UserIDs are the deliberate exception — on shipping builds they carry NO admin-delete entry (admin delete fails `0x6986` by design; that *is* the S-6 fix). Bench images (#912) keep the two-entry UserID so `se050-factory-reset` can remove them.
- **Do NOT change the admin-PIN domain/root without a coordinated SE050
  reprovisioning ceremony.** Page 125 does not carry the PIN; erasing it only
  clears wipe/legacy state and cannot rotate the root-derived credential.
- **Do NOT skip the round-trip selftest.** It's the cheap insurance
  against re-introducing garbled-policy orphans on future builds.
- **Do NOT reuse the ADMIN_WIPE_OBJ PIN for user-facing operations.**
  The admin credential exists only to satisfy admin-delete policies;
  its ar_header grants only DELETE, never READ.
- **Do NOT try to provision `0x7FFF_0205` on dev chips.** Wastes time,
  always returns `SW=0x6985`. The FACTORY_RESET credential is
  NXP-controlled.
- **Do NOT run the wipe path without arming the flag first.** A power
  loss mid-wipe leaves the chip in a half-wiped state with no recovery
  signal. The flag is cheap and idempotent; always arm it first.
- **Do NOT bypass the admin-credential install during first-boot.**
  `Se050::provision()` runs `provision_admin` + `policy_roundtrip_selftest`
  automatically on any `stm32u585` target with SE050 — don't "optimise"
  it out. Skipping it ships a wallet that cannot recover from PIN lockout.

## File map

| Concern                       | File                                                       |
|-------------------------------|------------------------------------------------------------|
| TAG_POLICY byte layout        | `secure/src/se050/apdu.rs` (`build_policy`)                |
| UserID + data-obj creation    | `secure/src/se050/apdu.rs` (`write_userid`, `write_binary_gated`) |
| Admin credential provisioning | `secure/src/se050/mod.rs` (`provision_admin`, `store_objects`) — runs automatically inside `WalletStore::provision` on stm32u585 |
| Admin-delete wipe             | `secure/src/se050/mod.rs` (`admin_factory_reset`)          |
| Round-trip selftest           | `secure/src/se050/mod.rs` (`policy_roundtrip_selftest`)    |
| Admin credential + wipe flag  | `secure/src/hw/secret_keys.rs` (`se050_admin_pin`); page 125 retains only wipe-marker/legacy hygiene state (`erase_admin_page`, `arm_wipe_flag`, `is_wipe_armed`) |
| SE050 wipe entry point        | `secure/src/se050/mod.rs` `WalletStore::factory_reset_admin` |
| Dual-SE wipe orchestration    | `secure/src/dual_se.rs` `WalletStore::factory_reset_admin` (best-effort wipes OPTIGA + SE050; never erases page 126) |
| PIN-lockout trigger           | `secure/src/nsc/cmd_request_unlock.rs` (`trigger_lockout_wipe`) |
| Boot-time resume              | `secure/src/main.rs` (block after `load_pbs`)              |
| Flash layout (linker)         | `secure/memory-stm32u585.x` (`FLASH LENGTH = 1000K`, reserves pages 125-127) |

## References

- NXP UM11225 — SE050 User Manual (TAG_POLICY structure, ar_header bits)
- NXP `plug-and-trust/sss/ex/src/ex_sss_boot.c:94-114` — official factory reset is `DeleteAll_Iterative`, not bare `DeleteAll`
- NXP `plug-and-trust/hostlib/hostLib/se05x/src/se05x_mw.c:22-78` — iterative delete implementation, skips reserved ranges only
- NXP `plug-and-trust/hostlib/hostLib/inc/se05x_const.h:141-176` — `POLICY_OBJ_ALLOW_*` bit values
- PQSigner CLAUDE.md — invariants #1 (dual-chip split), #2 (hardware PIN gating), #3 (E2E encrypted tunnel), #4 (secrets in TrustZone only)
