# SE050 Factory Reset — Design and Production Checklist

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

## The design we shipped

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
  DeleteSecureObject_authed(USERID_OBJ)       ← user UserID
  DeleteSecureObject_authed(ADMIN_WIPE_OBJ)   ← self-delete
  CloseSession
  ↓
best-effort unauthenticated sweep (iterative_delete_all) for legacy stragglers
  ↓
erase_admin_page()  ← clears admin PIN + wipe flag atomically
(dual-SE only) erase_pbs_page()  ← orphans OPTIGA from STM32
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

Dev chips use NXP default SCP03 keys (`0x40 0x41 0x42 … 0x4F` — encoded
in our `se050/scp03.rs`). Production chips must have these rotated to
per-batch or per-device keys delivered by NXP's secure provisioning
service. The wipe path depends on SCP03 channel being establishable, so
the rotated keys must also be stored in TrustZone secure flash and
loaded before any SE050 operation.

**Action:** add a key-storage slot in secure flash (alongside PBS /
pairing key) and a boot-time load step before `scp03::establish()`.
Today the driver hard-codes the NXP defaults; that's fine for dev, not
for production.

### 2. Lifecycle of ADMIN_WIPE_OBJ PIN

Admin PIN is generated once at first-boot provisioning via STM32 TRNG
(`rng::fill()`) and persisted to secure flash page 125 QW 0. It is
read back from flash on every boot that needs it (factory reset, boot-time
wipe resume). Because it lives in TrustZone secure flash it is never
exposed to non-secure world, USB, or any external interface.

The PIN is erased atomically with the wipe flag when
`erase_admin_page()` runs at the end of a factory reset. After that
erase, any subsequent boot sees `is_admin_pin_blank() == true` and
treats the chip as unprovisioned (runs first-boot wizard, generates a
fresh admin PIN).

If you ever re-provision the firmware without wiping first (e.g. a
dev-mode reflash while keeping the existing SE050 contents), the
already-persisted admin PIN continues to work because it's read from
flash, not regenerated. Only `erase_admin_page()` rotates the PIN.

### 2a. Future optimisation — HUK-SAES derivation

Storing the admin PIN in flash is functional but dependent on flash
integrity. An attacker who can read page 125 off a powered-off chip
(invasive attack) learns the admin PIN and can wipe the device.
A stronger design derives the admin PIN at boot from the STM32U585
Hardware Unique Key via the SAES peripheral — the HUK never leaves the
silicon and is unique per chip. The admin PIN then has no on-flash
representation at all.

This is flagged as a future improvement because HUK-SAES wrapping is
not yet wired up for other secrets either (e.g. SCP03 platform keys —
see docs/work-todo.md item #7). When that infrastructure lands, fold
admin-PIN derivation into the same code path with domain tag
`"pqwallet-se050-admin-pin-huk-v1"` (new tag, not v1 — the v1 tag stays
frozen so already-provisioned flash-persisted devices keep working
during the migration).

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

- **Do NOT remove the admin-delete policy entry.** Every object the
  firmware creates on SE050 must have two TAG_POLICY entries. Objects
  without entry 2 cannot be recovered from PIN lockout and are
  orphans-by-design.
- **Do NOT regenerate the admin PIN without erasing page 125 first.**
  The PIN is TRNG-generated and persisted; overwriting only the PIN
  slot would leave the old wipe flag (if armed) in a stale state. Use
  `erase_admin_page()` to rotate.
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
| Admin PIN + wipe-flag storage | `secure/src/hw/flash.rs` page 125 (`read_admin_pin`, `write_admin_pin`, `erase_admin_page`, `arm_wipe_flag`, `is_wipe_armed`) |
| SE050 wipe entry point        | `secure/src/se050/mod.rs` `WalletStore::factory_reset_admin` |
| Dual-SE wipe orchestration    | `secure/src/dual_se.rs` `WalletStore::factory_reset_admin` (delegates to SE050, then erases PBS) |
| PIN-lockout trigger           | `secure/src/nsc/cmd_request_unlock.rs` (`trigger_lockout_wipe`) |
| Boot-time resume              | `secure/src/main.rs` (block after `load_pbs`)              |
| Flash layout (linker)         | `secure/memory-stm32u585.x` (`FLASH LENGTH = 1000K`, reserves pages 125-127) |

## References

- NXP UM11225 — SE050 User Manual (TAG_POLICY structure, ar_header bits)
- NXP `plug-and-trust/sss/ex/src/ex_sss_boot.c:94-114` — official factory reset is `DeleteAll_Iterative`, not bare `DeleteAll`
- NXP `plug-and-trust/hostlib/hostLib/se05x/src/se05x_mw.c:22-78` — iterative delete implementation, skips reserved ranges only
- NXP `plug-and-trust/hostlib/hostLib/inc/se05x_const.h:141-176` — `POLICY_OBJ_ALLOW_*` bit values
- PQSigner CLAUDE.md — invariants #1 (dual-chip split), #2 (hardware PIN gating), #3 (E2E encrypted tunnel), #4 (secrets in TrustZone only)
