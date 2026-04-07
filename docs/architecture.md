# SPHINCS+ Post-Quantum Hardware Wallet — TrustZone Architecture

## Overview

This project implements a post-quantum hardware wallet using **SLH-DSA (SPHINCS+)** signatures
with **ARM TrustZone** isolation on a Cortex-M33 microcontroller. Private key material never
leaves the secure world. The non-secure world (USB, display, buttons) can only request
signatures through a narrow gateway.

The firmware targets **STM32U585** (production) and runs on **QEMU mps2-an505** (development).
A desktop CLI (`sphincs-wallet`) demonstrates the full TROPIC01 flow over USB.

Two modes of operation:
- **`mock-se`** (default): Mock secure element in SRAM, no hardware needed
- **`tropic01-se`**: Real TROPIC01 chip connected via USB at `/dev/ttyACM0`, bridged to
  QEMU via semihosting file I/O. All chip communication is e2e encrypted (X25519 + AES-256-GCM).

```
┌─────────────────────────────────────────────────────────────┐
│                    QEMU mps2-an505                          │
│  ┌──────────────────────┐   ┌────────────────────────────┐  │
│  │   SECURE WORLD       │   │   NON-SECURE WORLD         │  │
│  │                      │   │                             │  │
│  │  SPHINCS+ keys       │   │  USB protocol handler      │  │
│  │  AES-GCM wrap/unwrap │   │  OLED display driver       │  │
│  │  PIN verification    │   │  Button input               │  │
│  │  TROPIC01 comms ─────│───│──── /dev/ttyACM0 ──► chip  │  │
│  │  (e2e encrypted SPI) │   │                             │  │
│  │                      │   │  Calls secure world ONLY   │  │
│  │  SysTick handler     │◄──│  through gateway            │  │
│  │  polls gateway       │──►│  Reads results              │  │
│  └──────────────────────┘   └────────────────────────────┘  │
│         0x10000000                  0x00200000               │
│       (secure flash)              (NS flash)                │
└─────────────────────────────────────────────────────────────┘
         │ (semihosting SYS_OPEN / SYS_READ / SYS_WRITE)
         ▼
   ┌─────────────┐      USB serial       ┌────────────────┐
   │ /dev/ttyACM0│◄─────────────────────►│ TROPIC01 chip  │
   │ (host)      │  115200 8N1 raw       │ (TS1302 devkit)│
   └─────────────┘                        └────────────────┘
```

## Workspace Structure

```
sphincs_rust/
├── Cargo.toml              # Workspace root
├── Makefile                # Build orchestration (secure → veneers → nonsecure → QEMU)
├── rust-toolchain.toml     # Nightly 2026-04-06, thumbv8m.main-none-eabi
│
├── desktop/                # Original USB CLI (std, runs on host)
│   ├── Cargo.toml          #   sphincs-wallet — talks to real TROPIC01 over USB
│   └── src/
│       ├── main.rs         #   enroll + sign commands
│       └── usb_dongle.rs   #   SPI-over-USB transport (embedded_hal::SpiDevice)
│
├── shared/                 # #![no_std] types shared between worlds
│   ├── Cargo.toml          #   zero dependencies
│   └── src/lib.rs          #   NscStatus, size constants, memory addresses
│
├── bip39/                  # #![no_std] BIP-39 24-word mnemonic crate
│   ├── Cargo.toml          #   sha2, hmac, zeroize
│   ├── src/lib.rs          #   Mnemonic, PBKDF2-HMAC-SHA512, prefix lookup
│   ├── src/wordlist.rs     #   Canonical 2048-word English wordlist
│   └── tests/vectors.rs    #   Trezor 24-word test vectors (host-tested)
│
├── secure/                 # TrustZone SECURE world firmware
│   ├── Cargo.toml          #   no_std crypto: slh-dsa, aes-gcm, sha2, hmac, bls12_381, bip39
│   ├── memory.x            #   FLASH 0x10000000 + NSC 0x103FF000 + RAM 0x38000000
│   ├── build.rs            #   Patches link.x to place .gnu.sgstubs in NSC region
│   └── src/
│       ├── main.rs         #   Boot: SAU → first-boot wizard → SysTick → boot NS
│       ├── sau.rs          #   SAU region config + MPC block config
│       ├── boot_ns.rs      #   VTOR_NS + MSP_NS + BXNS
│       ├── nsc.rs          #   Shared-memory gateway (5 commands)
│       ├── crypto.rs       #   KDF, AES-GCM, BIP-39→SLH-DSA seed derivation
│       ├── host_rng.rs     #   Host CSPRNG via semihosting /dev/urandom
│       ├── pin.rs          #   PIN verify via MAC-and-Destroy chain
│       ├── secure_element.rs  # trait SecureElement + MockSecureElement
│       ├── semihosting_spi.rs # SpiDevice impl via semihosting (tropic01-se)
│       ├── tropic01_se.rs     # Tropic01SecureElement with e2e encrypted sessions
│       ├── db_roots.rs        # Generated: ERC20_DB_ROOT + VK_DB_ROOT Merkle roots
│       ├── erc20/             # ERC20 dispatcher + bundle Merkle verifier
│       │   ├── mod.rs            # Public surface
│       │   ├── calldata.rs       # Strict ABI decoder (transfer/transferFrom/approve)
│       │   ├── dispatch.rs       # dispatch_tx() → TxKind trust level
│       │   ├── merkle.rs         # sha256 Merkle proof verifier (shared with VK DB)
│       │   └── bundle.rs         # NS → S metadata bundle parser + verifier
│       ├── zk/                # ZK clear-signing verifier (no_std, no alloc)
│       │   ├── mod.rs            # Module entry + size constants
│       │   ├── groth16.rs        # BLS12-381 Groth16 verifier (4 individual pairings)
│       │   ├── poseidon.rs       # Poseidon hash over BLS12-381 scalar field (alpha=5)
│       │   ├── poseidon_constants.rs  # Auto-generated round constants + MDS matrices
│       │   ├── vk_bundle.rs      # NS → S VK bundle parser + Merkle verifier
│       │   └── test_data/        # vk_bytes.bin, vk_hash.bin (Aave V3 reference VK)
│       └── ui/
│           ├── mod.rs         #   Display + Input + global singletons
│           ├── pin_entry.rs   #   2-button 8-digit PIN entry (+ confirm helper)
│           ├── confirm.rs     #   Multi-page tx confirmation navigator
│           └── seed_wizard.rs #   First-boot mnemonic display / verify / restore
│
├── secure/data/              # Curated source data for dbgen
│   ├── erc20.json            # (chain_id, address, name, symbol, decimals) rows
│   ├── vks.json              # Protocol VK manifest
│   ├── vks/*.vk.bin          # Per-protocol 960-byte Groth16 VKs
│   └── vks.review.txt        # Generated: release-review manifest (sha256 per VK)
│
├── dbgen/                    # Host-side DB + Merkle tree builder
│   ├── Cargo.toml
│   └── src/{main,erc20,vks,merkle}.rs
│
├── zk-test/                  # Host-side end-to-end test for the ZK verifier
│   ├── Cargo.toml            #   bls12_381 + sha2 (host std), no QEMU needed
│   └── src/main.rs           #   Mirrors the secure-world Poseidon + Groth16 path,
│                             #   exercises ZKlarity's proof_supply.json on the host
│
├── tools/
│   └── export_zk_constants.js # Exports Poseidon round constants from
│                              # poseidon-bls12381 (npm) into Rust source
│
└── nonsecure/                # TrustZone NON-SECURE world firmware
    ├── Cargo.toml            #   minimal: cortex-m-rt + semihosting
    ├── memory.x              #   FLASH 0x00200000 + RAM 0x28020000
    ├── build.rs              #   memory.x copy + magic-bytes validator for .bin blobs
    └── src/
        ├── main.rs           #   Interactive test harness
        ├── e2e_test.rs       #   Scripted runner for `make e2e` (feature-gated)
        ├── nsc_api.rs        #   Shared-memory gateway client
        ├── erc20_db.bin      #   Full ERC20 DB (generated by dbgen, include_bytes!d)
        ├── erc20_db.rs       #   NS-side lookup → metadata bundle builder
        ├── vk_db.bin         #   Full ZK VK DB (generated by dbgen)
        └── vk_db.rs          #   NS-side lookup → VK bundle builder
```

## Memory Map (QEMU mps2-an505)

The mps2-an505 has two SSRAM banks. The IDAU uses address bit 28 to distinguish
secure (0x1xxx/0x3xxx) and non-secure (0x0xxx/0x2xxx) aliases of the same physical memory.
The MPC (Memory Protection Controller) provides block-level S/NS attribution within each bank.

### SSRAM-0 (Code, 4 MB)

| Address Range       | Alias | MPC    | Usage                        |
|---------------------|-------|--------|------------------------------|
| `0x10000000-0x101FFFFF` | S     | Secure | Secure world code + rodata   |
| `0x103FF000-0x103FFFFF` | S     | NS     | NSC veneers (.gnu.sgstubs)   |
| `0x00200000-0x003FFFFF` | NS    | NS     | Non-secure world code        |

### SSRAM-1 (Data, 2 MB)

| Address Range       | Alias | MPC    | Usage                        |
|---------------------|-------|--------|------------------------------|
| `0x38000000-0x3801FFFF` | S     | Secure | Secure stack (128 KB)        |
| `0x28020000-0x2803FFFF` | NS    | NS     | Non-secure stack + BSS       |
| `0x2802FF00-0x2802FF14` | NS    | NS     | Shared memory gateway        |

### SAU Regions

| Region | Base         | Limit        | Type | Purpose              |
|--------|-------------|-------------|------|----------------------|
| 0      | `0x00200000` | `0x003FFFFF` | NS   | NS code flash        |
| 1      | veneer_base  | veneer_base+0xFF | NSC  | SG veneers (dynamic) |
| 2      | `0x28020000` | `0x29FFFFFF` | NS   | NS data SRAM         |
| 3      | `0x40000000` | `0x4FFFFFFF` | NS   | NS peripherals       |

Everything not covered by an SAU region defaults to Secure.

### MPC Configuration

| Controller | Register    | Blocks 0-63 | Blocks 64+ |
|-----------|-------------|-------------|------------|
| MPC0      | `0x58007000` | Secure      | NS         |
| MPC1      | `0x58008000` | Secure (0-3) | NS (4+)  |

## Secure Gateway

### Design

The gateway provides 5 operations across the TrustZone boundary:

| Command | ID | NS → S Args | S → NS Result |
|---------|-----|-------------|---------------|
| `GET_REMAINING` | 1 | — | Remaining PIN attempts (u32) |
| `REQUEST_UNLOCK` | 2 | — (PIN entered on trusted UI) | NscStatus |
| `GET_PUBKEY` | 3 | ptr to 32-byte output buf | NscStatus |
| `SIGN` | 4 | ptr to unsigned EIP-1559 tx, ptr to 17088-byte sig buf, tx_len | NscStatus |
| `CLEAR_SIGN` | 5 | ptr to ZK payload (VK ‖ proof ‖ calldata ‖ string ‖ vk_hash ‖ tx_len ‖ tx), ptr to sig buf, total_len | NscStatus |

### Implementation (QEMU workaround)

On QEMU mps2-an505, the ARM CMSE `SG` instruction veneers do not work due to a bug
where the SG instruction check reads through the MPC NS alias, failing for S-marked blocks
(see "QEMU Limitations" below). The workaround uses **shared memory + secure SysTick polling**:

```
         NON-SECURE                                SECURE
    ┌───────────────────┐                  ┌──────────────────────┐
    │                   │                  │                      │
    │ 1. Write CMD+args │──────────────►   │                      │
    │    to 0x2802FF00  │  shared memory   │                      │
    │                   │                  │ 2. SysTick fires     │
    │ 3. Spin on DONE   │                  │    poll_gateway()    │
    │    flag           │                  │    reads CMD          │
    │                   │                  │    dispatches         │
    │ 4. Read RESULT    │  ◄──────────────│    writes RESULT     │
    │    from 0x2802FF10│  shared memory   │    sets DONE=1       │
    │                   │                  │                      │
    └───────────────────┘                  └──────────────────────┘
```

Shared memory layout at `0x2802FF00`:

| Offset | Name   | Size | Direction | Description     |
|--------|--------|------|-----------|-----------------|
| +0x00  | CMD    | 4    | NS→S     | Command ID      |
| +0x04  | ARG0   | 4    | NS→S     | Pointer to input data |
| +0x08  | ARG1   | 4    | NS→S     | Pointer to output buffer |
| +0x0C  | ARG2   | 4    | NS→S     | Output buffer length |
| +0x10  | RESULT | 4    | S→NS     | Return value (NscStatus) |
| +0x14  | DONE   | 4    | S→NS     | 1 = result ready |

### On Real Hardware (STM32U585)

Replace the shared memory gateway with proper CMSE veneers:

```rust
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_request_unlock() -> u32;
pub extern "cmse-nonsecure-entry" fn nsc_sign(tx_ptr: u32, sig_ptr: u32, tx_len: u32) -> u32;
pub extern "cmse-nonsecure-entry" fn nsc_clear_sign(payload_ptr: u32, sig_ptr: u32, total_len: u32) -> u32;
pub extern "cmse-nonsecure-entry" fn nsc_get_pubkey(out_ptr: u32, out_len: u32) -> u32;
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32;
```

The `secure/src/nsc.rs` already exports `nsc_get_remaining_attempts` as a CMSE veneer.
The secure `build.rs` generates `veneers.o` via `--cmse-implib`, and the non-secure
build links against it. When the QEMU bug is not present (real hardware), these
veneers work directly.

## TROPIC01 Integration

### Semihosting SPI Bridge

The real TROPIC01 chip (TS1302 devkit) connects to the host laptop via USB serial
at `/dev/ttyACM0`. The firmware accesses it through QEMU's ARM semihosting:

1. **SYS_OPEN**: Opens `/dev/ttyACM0` on the host (the host must pre-configure with `stty`)
2. **SYS_WRITE**: Sends hex-encoded SPI commands (same protocol as `desktop/src/usb_dongle.rs`)
3. **SYS_READ**: Reads hex-encoded SPI responses byte-by-byte until `\n`
4. **SPI protocol**: `"A0B1C2x\n"` → chip processes → `"D3E4F5\r\n"`
5. **CS deassert**: `"CS=0\n"` → `"OK\r\n"`

The `SemihostingSpi` struct (`secure/src/semihosting_spi.rs`) implements
`embedded_hal::spi::SpiDevice`, so the `tropic01` crate works unmodified.

### E2E Encrypted Session

Every TROPIC01 operation establishes a fresh Noise_KK1 encrypted session:

```
Secure World                          TROPIC01 Chip
────────────                          ─────────────
1. startup_req(Reboot)          ───►  Chip resets
2. Generate ephemeral X25519          
   keypair (random from               
   host /dev/urandom)                  
3. session_start(                ───►  X25519 handshake
     shpub=SH0PUB_PROD0,              3x DH exchanges
     shpriv=SH0PRIV_PROD0,            AES-GCM auth verify
     ehpub, ehpriv, slot=0)    ◄───  Session keys derived
                                       (Noise_KK1 protocol)
                                       
   === All further commands encrypted with AES-256-GCM ===
   
4. mac_and_destroy(slot, data)   ─E2E─►  HMAC + destroy
5. r_mem_data_read(slot)         ─E2E─►  Read encrypted
6. r_mem_data_write(slot, data)  ─E2E─►  Write encrypted
7. session_abort()               ───►  Zeroize keys
```

The pre-shared pairing keys (`SH0PUB_PROD0`, `SH0PRIV_PROD0`) are compiled into
the secure world firmware. The ephemeral keys are fresh for each session, generated
from `/dev/urandom` via semihosting.

### Batch Operations

The `Tropic01SecureElement` provides batch methods that perform multiple operations
in a single e2e encrypted session, avoiding the overhead of re-establishing a session
for each individual command:

| Method | Operations per session |
|--------|----------------------|
| `batch_enroll()` | N x mac_and_destroy + 3 x r_mem_write |
| `batch_verify_pin()` | r_mem_read + mac_and_destroy + N x mac_and_destroy (re-init) + r_mem_write |
| `batch_read_key_material()` | 2 x r_mem_read |
| `batch_read_pin_state()` | r_mem_read |

### Running with Real TROPIC01

```bash
# 1. Connect TROPIC01 TS1302 devkit via USB
# 2. Configure serial port + build + run:
make run-tropic01

# Or manually:
stty -F /dev/ttyACM0 115200 raw -echo cs8 -cstopb -parenb
make FEATURES=tropic01-se all
make run
```

## Cryptographic Design

### Key Hierarchy

The root of trust is a **24-word BIP-39 mnemonic** chosen on first boot
(generated from the host CSPRNG / chip TRNG, or restored from a piece of
paper). The mnemonic is **never persisted on the device** — it lives only on
the user's paper backup.

The on-device secret blob is the **32-byte BIP-39 entropy** that the 24
words encode. The 48-byte SLH-DSA seed and the SigningKey itself are
**recomputed on every unlock** by re-running the full BIP-39 → SLH-DSA
chain. They never touch persistent storage.

Everything is deterministically derived from the entropy, so the same 24
words always produce the same SPHINCS+ keypair on any device running this
firmware.

```
                  ┌────────────────────────────┐
                  │   24-word BIP-39 mnemonic  │  256 bits of entropy
                  │   (paper backup, NOT on    │  + 8-bit checksum
                  │    device after first boot)│
                  └─────────────┬──────────────┘
                                │  Mnemonic::to_entropy()
                                ▼
            ┌──────────────────────────────────────┐
            │   BIP-39 entropy (32 B)              │
            │   STORED encrypted in r-mem slot 0   │
            │   under wrap_key derived from        │
            │   PIN-gated master_secret            │
            └────────────────┬─────────────────────┘
                             │  Mnemonic::from_entropy()
                             │  + PBKDF2-HMAC-SHA512 (2048 iters)
                             ▼  ───── runs on every unlock ─────
                  ┌────────────────────────────┐
                  │      bip39_seed (64 B)     │  ephemeral, stack-only
                  └─────────────┬──────────────┘
                                │  slhdsa_seed_from_bip39():
                                │  3 × SHA256("sphincs-slh-seed" || s || i)[..16]
                                ▼
                  ┌────────────────────────────┐
                  │ SLH-DSA seed (48 B)        │  ephemeral, stack-only
                  │ sk_seed ‖ sk_prf ‖ pk_seed │
                  └─────────────┬──────────────┘
                                │  slh_keygen_internal() (FIPS-205)
                                ▼
                  ┌────────────────────────────┐
                  │  SigningKey<Sha2_128f>     │  ephemeral, stack-only
                  │  (64 B + Merkle root)      │  zeroized after sign call
                  └────────────────────────────┘

  -- Independently --
  master_secret = SHA256("sphincs-master" || entropy || 0x00)   # at provision
                = decrypted from MACD chain via PIN              # at unlock
  wrap_key      = SHA256("sphincs-wrap-key" || master_secret || 0x00)
  → unwraps the 60-byte AES-GCM blob in r-mem slot 0 to recover entropy
```

**On-device storage** (`RMEM_*` slots in the secure element):

| Slot | Name                     | Contents                                  | Size |
|------|--------------------------|-------------------------------------------|------|
| 0    | `RMEM_ENCRYPTED_ENTROPY` | AES-GCM blob of the 32-byte BIP-39 entropy | 60 B |
| 1    | `RMEM_PIN_STATE`         | next-attempt counter + 9 × per-attempt encrypted master_secret blobs | 433 B |
| 2    | `RMEM_VERIFYING_KEY`     | 32-byte SLH-DSA public key (cached so the host can read it without unlocking) | 32 B |

The mnemonic is **not** in any slot. The 48-byte SLH-DSA seed is **not** in
any slot. Only the raw 32-byte BIP-39 entropy is persisted, which means the
on-device secret is bit-for-bit identical to what the user's paper backup
encodes. PBKDF2 + the slhdsa_seed_from_bip39 KDF run fresh on every
unlock — ~tens of milliseconds, dwarfed by SPHINCS+ signing's seconds.

### PIN Protection (MAC-and-Destroy)

Each PIN attempt consumes one MACD slot (9 slots = 9 attempts max). On correct PIN,
all slots are re-initialized. On 9 wrong PINs, the key is permanently erased ("bricked").

```
Enrollment (per slot j = 0..8):
  1. mac_and_destroy(j, init_input_j)     → initialize slot
  2. mac_and_destroy(j, pin_input_j)      → w_j (slot-specific wrap key)
  3. mac_and_destroy(j, init_input_j)     → re-initialize to known state
  4. encrypted_secrets[j] = AES-GCM(w_j, master_secret)

Verification (slot j = next_index):
  1. mac_and_destroy(j, pin_input_j)      → w_j'
  2. Try AES-GCM decrypt of encrypted_secrets[j] with w_j'
  3. If decrypt succeeds → correct PIN, recover master_secret
  4. If decrypt fails → wrong PIN, increment next_index
```

### Recovery from Seed Phrase

If the device is lost, bricked (9 wrong PINs erase all MACD slots), or
otherwise unusable, the user can restore the wallet on any replacement unit
running the same firmware. The procedure:

1. Power on a fresh / wiped device. The first-boot wizard runs.
2. Choose **"Restore"** instead of **"New Wallet"**.
3. Choose a new PIN (the PIN is local to each device — it gates only the
   on-device encrypted state, not the mnemonic itself, so a recovered device
   uses whatever new PIN the user picks).
4. Type the 24 words from the paper backup using the trusted UI's letter-
   scroll widget. The first 4 letters of every BIP-39 English word are
   unique, so each word usually only needs 3 keystrokes before auto-completing.
   Short words (`act`, `add`, `art`, …) drop into a candidate-pick list when
   the prefix matches multiple longer words.
5. The wizard verifies the BIP-39 checksum and rejects bad phrases.
6. The same `slhdsa_seed_from_bip39` KDF runs and reconstructs an identical
   48-byte SLH-DSA seed. The MACD chain is re-initialized, the encrypted seed
   blob is rewritten, and the verifying key matches the original byte-for-byte.

The recovery contract is the stability of two functions:

```rust
Mnemonic::to_seed("")                       // PBKDF2-HMAC-SHA512, 2048 iters
crypto::slhdsa_seed_from_bip39(&bip39_seed) // domain-separated SHA-256 KDF
```

These are tested by host-side unit tests (`cargo test -p sphincs-tz-bip39`)
against the canonical Trezor test vectors and by an end-to-end QEMU test
that runs the Restore flow twice and confirms the verifying keys match
byte-for-byte.

### Backup Verification

After displaying the 24 words on first boot, the wizard prompts for a
spot-check of **3 randomly-selected words** (e.g. "Enter word 7", "Enter
word 14", "Enter word 21") via the same word-entry widget used for
recovery. The device only finalises provisioning if all three match. This
catches transcription errors before they become permanent — same flow as
Ledger / Trezor. The selected indices come from the host CSPRNG so the
prompts differ between runs.

### SLH-DSA Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | SLH-DSA-SHA2-128f (FIPS 205) |
| Security level | 128-bit (NIST Level 1) |
| Signing key | 64 bytes |
| Verifying key | 32 bytes |
| Signature | 17,088 bytes |
| Stack during signing | ~20-34 KB |

## Secure Element Abstraction

The `SecureElement` trait abstracts the TROPIC01 API subset used by the wallet:

```rust
pub trait SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError>;
    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError>;
    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError>;
    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError>;
}
```

| Implementation | Feature | Backend |
|---------------|---------|---------|
| `MockSecureElement` | `mock-se` (default) | In-memory arrays, HMAC-SHA256 for MACD |
| `Tropic01SecureElement` | `tropic01-se` | Real TROPIC01 chip via semihosting SPI, e2e encrypted |

The mock stores up to 8 r-mem slots (512 bytes each) and 16 MACD slots (32 bytes each).
The real implementation establishes a fresh Noise_KK1 encrypted session per operation batch.

## Build System

### Prerequisites

```bash
rustup toolchain install nightly-2026-04-06
rustup target add thumbv8m.main-none-eabi --toolchain nightly
sudo apt install gcc-arm-none-eabi qemu-system-arm
```

### Build Commands

```bash
# Mock secure element (no hardware needed)
make all                          # Build both worlds with mock SE
make run                          # Build + run in QEMU

# Real TROPIC01 chip (TS1302 devkit at /dev/ttyACM0)
make run-tropic01                 # Configure serial + build + run
make FEATURES=tropic01-se all     # Build only (manual serial setup)
make setup-serial                 # Configure /dev/ttyACM0 only

# Other
make secure                       # Build only secure world
make nonsecure                    # Build only non-secure world
make clean                        # Remove build artifacts
```

### Build Pipeline

```
secure/           arm-none-eabi-ld         nonsecure/
  *.rs  ──────►  --cmse-implib  ──────►    *.rs
  memory.x        --out-implib=             memory.x
                   veneers.o                 +veneers.o
                        │                       │
                        ▼                       ▼
              sphincs-tz-secure.elf    sphincs-tz-nonsecure.elf
                        │                       │
                        └───────────┬───────────┘
                                    ▼
                          qemu-system-arm
                          -M mps2-an505
                          -kernel secure.elf
                          -device loader,file=nonsecure.elf
```

The secure world must build first because the non-secure world links against `veneers.o`
(the CMSE import library containing SG stub addresses). The Makefile uses separate
`--target-dir` for each crate to avoid linker flag conflicts.

### Linker Flags

| Crate | Linker Flags |
|-------|-------------|
| secure | `-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=veneers.o` |
| nonsecure | `-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=veneers.o` |

`arm-none-eabi-ld` is required because Rust's default linker (LLD) does not support CMSE.

## Boot Sequence

```
 1. QEMU starts in secure mode
 2. CPU fetches SP from 0x10000000, reset vector from 0x10000004
 3. cortex-m-rt Reset handler: zero BSS, copy .data
 4. main():
    a. Configure MPC0 (SSRAM-0: blocks 0-63 S, 64+ NS)
    b. Configure MPC1 (SSRAM-1: blocks 0-3 S, 4+ NS)
    c. Configure SAU (4 regions: NS code, NSC veneers, NS data, NS periph)
    d. DSB + ISB barriers
    e. Initialize trusted UI (display + buttons)
    f. is_provisioned()? → if no, run first-boot wizard:
       - User picks (and confirms) a PIN via the trusted UI
       - User chooses "New Wallet" or "Restore"
       - New: 32 B host_rng entropy → BIP-39 24-word mnemonic → display
              paginated → spot-check 3 random words against re-entry
       - Restore: word-by-word entry with 4-letter prefix narrowing
       - master_secret = KDF("sphincs-master", entropy, 0)
       - One-shot full chain (PBKDF2 + slhdsa_seed_from_bip39 + KeyGen)
         to compute the verifying key for caching in slot 2
       - MACD chain initialized, encrypted ENTROPY (not seed) and
         verifying key written to r-mem (mock or TROPIC01 e2e session)
    g. Initialize shared memory gateway (clear command buffer)
    h. Enable secure SysTick (1000-cycle interval)
    i. Set VTOR_NS = 0x00200000
    j. Set MSP_NS from NS vector table[0]
    k. BXNS to NS reset handler
 5. Non-secure world boots via cortex-m-rt
 6. NS main() exercises gateway commands
 7. debug::exit(EXIT_SUCCESS) terminates QEMU
```

## Sign Transaction Flow (End-to-End)

```
NS World                          Secure World                        TROPIC01 Chip
────────                          ────────────                        ─────────────
1. Write PIN to NS SRAM
2. CMD=ENTER_PIN, ARG0=&pin  ──►  SysTick fires
                                  Read PIN from NS memory
                                  [tropic01-se: open e2e session] ──► X25519 handshake
                                  mac_and_destroy(slot, pin_in) ─E2E─► HMAC + destroy
                                  AES-GCM decrypt master_secret
                                  Re-init all MACD slots ────────E2E─► Restore slots
                                  [tropic01-se: close session] ──────► Zeroize keys
                                  RESULT=Ok, DONE=1
3. Read RESULT=Ok            ◄──

4. Write tx_hash to NS SRAM
5. CMD=SIGN, ARG0=&hash,     ──►  SysTick fires
   ARG1=&sig_buf, ARG2=17088     Read tx_hash from NS memory
                                  [tropic01-se: open e2e session] ──► X25519 handshake
                                  Read encrypted ENTROPY (60 B) ─E2E─► r_mem_data_read slot 0
                                  [tropic01-se: close session] ──────► Zeroize keys
                                  Derive wrap_key from master_secret
                                  AES-GCM decrypt → 32 B BIP-39 entropy
                                  Mnemonic::from_entropy(entropy)
                                  PBKDF2-HMAC-SHA512(2048) → 64 B bip39_seed
                                  slhdsa_seed_from_bip39 → 48 B SLH-DSA seed
                                  slh_keygen_internal → SigningKey
                                  slh_dsa::SigningKey::try_sign(tx_hash)
                                  Write 17,088-byte signature to NS sig_buf
                                  Wipe entropy + bip39_seed + slh_seed
                                  + signing key from RAM
                                  RESULT=Ok, DONE=1
6. Read RESULT=Ok            ◄──
   Read 17,088-byte signature
   from sig_buf
```

## ZK Clear Signing

For supported DeFi protocols (Aave V3 today), the secure world refuses to
display a "human-readable" action string on the trusted UI unless a
**Groth16 zero-knowledge proof** cryptographically certifies that the
string is a faithful ABI interpretation of the raw calldata being signed.
This closes a long-standing trust hole in hardware wallets: today, the
companion app on the host is free to render `swap 1 ETH for 3000 USDC`
while the chip is asked to sign a calldata blob that actually drains the
caller's balance to an attacker.

The architecture follows the [ZKNOX clear-signing
proposal](https://zknox.org) and reuses the [ZKlarity Circom
circuit](https://github.com/zklarity/zklarity-circuits): the proving side
runs off-device, on either a watchtower service or the user's companion;
the wallet only ever runs the **verifier**, which is small enough
(`#![no_std]`, no `alloc`) to fit inside the secure world.

### Verification chain

The full VK pool lives in **non-secure firmware rodata**
(`nonsecure/src/vk_db.bin`, `include_bytes!`d into the NS image).
The secure world only embeds a single 32-byte Merkle root in
`secure/src/db_roots.rs::VK_DB_ROOT`. At sign time the non-secure
world walks its local index by `(chain_id, contract)`, reads the
matching 960-byte VK + the pre-computed Merkle proof for its leaf
position, and forwards the bundle to the secure world.

```
NS World                                Secure World
────────                                ────────────
1. Local lookup on (chain_id, tx.to)    VK_DB_ROOT [u8; 32]
   in `nonsecure/src/vk_db.rs` →        embedded in secure image
   leaf_index, vk_bytes (960 B),
   merkle_proof[depth × 32 B]

2. Build clear-sign payload:
     [  0..384)   Groth16 proof (π.A ‖ π.B ‖ π.C)
     [384..548)   Aave V3 calldata (164 B, right-zero-padded)
     [548..612)   readable string (64 B, null-padded)
     [612..616)   tx_len (u32 LE)
     [616..)      EIP-1559 tx envelope
     then:
     [bundle_len u32 LE]
     [vk_bundle:
        chain_id (8 B) ‖ contract (20 B) ‖ vk_bytes (960 B)
        ‖ leaf_index (4 B) ‖ proof_depth (4 B)
        ‖ merkle_proof (depth × 32 B)
     ]

3. CMD=CLEAR_SIGN, ARG0=&payload  ──►  SysTick fires
   ARG1=&sig_buf, ARG2=total_len
                                       a. Validate payload pointer + length,
                                          reject overlap with shared mailbox
                                       b. Copy entire payload into a secure-stack
                                          buffer (TOCTOU defense)
                                       c. Parse the EIP-1559 envelope FIRST,
                                          extract chain_id, to, value, data
                                       d. Cross-check:
                                            tx.to.is_some()
                                            tx.value.is_zero()
                                            payload.calldata[..tx.data.len()]
                                               == tx.data
                                            payload.calldata[tx.data.len()..]
                                               == [0; ...] (padding)
                                          FAIL any → CryptoError
                                       e. Re-derive canonical leaf bytes from
                                          the bundle: (chain_id ‖ contract
                                          ‖ vk_bytes)
                                       f. leaf_hash = sha256(0x00 ‖ canonical)
                                          walk the Merkle proof, hashing
                                          pairwise with 0x01 || left || right,
                                          using bit i of leaf_index to pick
                                          left/right at each level
                                          final hash != VK_DB_ROOT → reject
                                          also cross-check bundle.chain_id +
                                          bundle.contract match parsed tx
                                       g. Deserialize the VK (now trusted) and
                                          the proof from the payload
                                       h. H_tx  = Poseidon(calldata, 164)
                                          H_str = Poseidon(readable, 64)
                                          (Poseidon over the BLS12-381 scalar
                                          field, alpha=5, Hades — matches
                                          ZKlarity's poseidon-bls12381 npm
                                          package bit-for-bit)
                                       i. vk_x = IC[0] + H_tx·IC[1] + H_str·IC[2]
                                       j. Verify Groth16 equation:
                                            e(π.A, π.B) · e(-α, β)
                                          · e(-vk_x, γ) · e(-π.C, δ) == 1 ∈ GT
                                          (4 individual pairings — no
                                          multi_miller_loop, so no alloc)
                                          FAIL → CryptoError, "ZK INVALID"
                                          OK   → continue
                                       k. Render `readable` on the trusted UI
                                          (3 pages: header, action string,
                                          confirm prompt). User long-presses
                                          R to confirm or L to cancel
                                       l. Parse + sign the EIP-1559 envelope
                                          (same flow as CMD_SIGN steps 5–10)
                                       m. RESULT=Ok, DONE=1
4. Read RESULT=Ok                ◄──
   Read 17 088-byte signature
   from sig_buf
```

### What this gives you

- **The display is cryptographically bound to the calldata.** The
  Poseidon hashes over the calldata and the readable string are the
  Groth16 public inputs. A proof exists *only* if a circuit-defined
  ABI-interpretation function maps that exact calldata to that exact
  string. Substituting either side invalidates the pairing equation.
- **The VK is authenticated against a secure-flash Merkle root.** The
  full VK pool ships in non-secure rodata, but the secure world only
  trusts a VK after re-deriving the leaf hash from the supplied bytes
  and walking the Merkle proof up to `VK_DB_ROOT`. The trust anchor
  is the firmware-signing key itself — the release reviewer compares
  `secure/data/vks.review.txt` (a build-artifact manifest of
  `(chain_id, contract, sha256(vk))` triples) against on-chain
  governance values before signing the release. Adding a new protocol
  requires a firmware update that bumps the root.
- **The NS side cannot forge a VK substitution.** If a hostile
  non-secure world sends a different VK for a pinned contract, the
  Merkle proof over the substituted bytes won't match the embedded
  root and the request is rejected before Groth16 ever runs.
- **The bundle cannot be replayed for the wrong transaction.** The
  bundle's `(chain_id, contract)` fields are cross-checked against the
  parsed envelope's `tx.chain_id` and `tx.to` after Merkle verification,
  so a valid VK for Aave V3 on Mainnet cannot be attached to a tx
  targeting a different chain or a different contract.
- **The signing key never depends on the proof's correctness.** A
  failing proof returns `CryptoError` *before* the entropy is even read
  from the secure element. The seed and SLH-DSA path are unchanged.

### Why classical, when everything else is post-quantum?

Groth16 and Poseidon over BLS12-381 are **classical** — a CRQC that
breaks the discrete log over BLS12-381's pairing-friendly curves could
forge a Groth16 proof for an arbitrary `(calldata, readable)` pair.

We accept this for now because:

1. **The ZK layer cannot leak the seed.** It only gates *what gets
   displayed before signing*. The classical assumptions are the same as
   they would be without the proof — the user is back to "trust the
   companion's display string".
2. **No PQ ZK proof system fits today.** Hash-based STARKs (Plonky3,
   Risc0) produce proofs that are O(100 KB) and verifiers that need
   alloc; lattice-based SNARKs are not yet practical for circuits the
   size of Aave V3 calldata parsing. The migration target is an
   STARK-based verifier once the proof + verifier sizes fit in the
   firmware budget.
3. **The display string is short-lived.** Even a successful forgery is
   only useful in the few seconds between the user reading the OLED and
   pressing confirm. There is no harvest-now-decrypt-later attack on a
   ZK display proof.

### Sizes (today, Aave V3 supply circuit)

| Field | Size | Notes |
|---|---|---|
| Verification key | 960 B | α(96) + β(192) + γ(192) + δ(192) + IC[0..2](288) — ships in NS rodata |
| Groth16 proof | 384 B | π.A(96) ‖ π.B(192) ‖ π.C(96), uncompressed |
| Calldata window | 164 B | matches ZKlarity circuit `MAX_CALLDATA` |
| Readable string | 64 B | matches ZKlarity circuit `STRING_LEN` |
| VK DB Merkle root | 32 B | embedded in secure flash via `db_roots::VK_DB_ROOT` |
| VK Merkle proof | depth × 32 B | ≤ 32 levels; 5 pinned Aave V3 deployments today → proof_depth ≤ 3 |
| Verify time (host) | ~3.3 ms | measured via `cargo run -p zk-test`; the `bls12_381` crate's pairing in pure Rust |
| Verify time (QEMU) | seconds | dominated by software BLS12-381 pairing on Cortex-M33 |

### Host-side parity test (`zk-test` crate)

`zk-test` is a host-only crate (`std`, real `bls12_381` from crates.io)
that imports the **same** `poseidon_constants.rs` and `test_vectors.rs`
files as the secure world, plus its own private copy of the reference
Aave V3 VK (independent of the firmware DB so it's stable across
Merkle-root changes). It runs the entire verifier chain on
`proof_supply.json` (a real Aave V3 supply proof generated by
ZKlarity's prover) and asserts:

1. Our Poseidon output for a known input matches `poseidon-bls12381`'s
   output bit-for-bit.
2. Groth16 verification of `proof_supply.json` returns true.

This catches divergence between the secure world's Poseidon
implementation and the reference circuit *without* the multi-minute
QEMU emulation cost of running BLS12-381 pairings on a soft-Cortex-M33.

```bash
cargo run -p zk-test --release
# → Poseidon: ok (matches poseidon-bls12381 reference)
# → Groth16 : ok in 3.3ms
```

### Automated end-to-end test (`make e2e`)

`make e2e` is a non-interactive test suite that builds both worlds
with a special `e2e-test` cargo feature and runs the full gateway
flow in QEMU with stdin closed. The feature:

- Replaces the first-boot wizard with deterministic provisioning from
  a fixed test mnemonic (`abandon`×23 + `art`) and PIN `00000000`
- Sets `PIN_VERIFIED` + `MASTER_SECRET` directly so the gateway is
  callable on boot
- Short-circuits every `confirm()` dialog to auto-return `Confirmed`
- Logs the chosen `TxKind` variant for every `cmd_sign` / `cmd_clear_sign`
  so the host harness can assert routing

It walks four scenarios back-to-back and greps the QEMU stdout for
both `[S][e2e] dispatch = <variant>` and `[E2E] <name> = PASS` lines
for every one:

| Scenario | Gateway | Expected TxKind |
|---|---|---|
| value_transfer | `CMD_SIGN` | `ValueTransfer` |
| erc20_known (USDC mainnet, bundle attached) | `CMD_SIGN` | `Erc20Known` |
| blind_sign (Uniswap router selector only) | `CMD_SIGN` | `ContractCall` |
| zk_clear_sign (Aave V3 supply, VK bundle attached) | `CMD_CLEAR_SIGN` | `ZkClearSign` |

The runner exits 0 only if every assertion holds. Total runtime
~20 seconds including QEMU's software BLS12-381 pairing.

The `e2e-test` feature is **never** enabled in production builds;
`secure/Cargo.toml` documents it as "NEVER ship in production: it
disables every meaningful trust gate."

### Tool: `tools/export_zk_constants.js`

Generates `secure/src/zk/poseidon_constants.rs` from the
`poseidon-bls12381` npm package's round constants and MDS matrices.
Run only when bumping the upstream package — the generated file is
checked in so the secure-world build does not require Node.js.

## Building the ERC20 + VK databases

The two on-device databases (ERC20 metadata, ZK clear-signing VKs)
are built by the `dbgen` workspace crate from JSON source files
checked into `secure/data/`. This section documents the source
schema, the tooling, the generated artifacts, the trust-anchor
workflow, and the sanity guards. For a quick-start "how do I add a
token" guide see the corresponding section in the top-level README.

### Source-data layout

```
secure/data/
├── erc20.json              # curated ERC20 metadata — sorted by (chain_id, address)
├── vks.json                # VK manifest (one block per protocol + its deployments)
├── vks/                    # raw 960-byte Groth16 verification keys
│   └── aave_v3_supply.vk.bin
└── vks.review.txt          # GENERATED — release-review manifest (checked in)
```

#### `secure/data/erc20.json`

A JSON array of records, one per `(chain_id, contract)` the wallet
should recognise. All fields are required except `flags`.

```json
[
  { "chain_id": 1, "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "name": "USD Coin", "symbol": "USDC", "decimals": 6 },
  { "chain_id": 8453, "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "name": "USD Coin", "symbol": "USDC", "decimals": 6 }
]
```

| Field | Type | Constraint |
|---|---|---|
| `chain_id` | u64 | EIP-155 chain id, matches what the EIP-1559 envelope encodes |
| `address` | hex string | 20 bytes, with or without `0x` prefix; case insensitive |
| `name` | UTF-8 string | 1–255 bytes. `dbgen` hard-errors if longer |
| `symbol` | UTF-8 string | 1–255 bytes |
| `decimals` | u8 | Token decimals used by `U256::format_decimal_fixed` |
| `flags` | u8 (optional, default 0) | Reserved per-entry flags |

#### `secure/data/vks.json`

A JSON array where each element describes one protocol (i.e. one
circuit + VK) plus every chain/contract deployment that shares that
VK. Dedup happens at the protocol level: the Aave V3 supply VK is
identical across Mainnet/Base/Arbitrum/Optimism/Polygon, so all five
deployments ride on a single 960-byte entry in the VK pool.

```json
[
  {
    "protocol": "aave-v3-supply-v1",
    "vk_file": "aave_v3_supply.vk.bin",
    "deployments": [
      { "chain_id": 1,     "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        "label": "Aave V3 Pool, Mainnet" },
      { "chain_id": 8453,  "address": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
        "label": "Aave V3 Pool, Base" }
    ]
  }
]
```

`vk_file` is a path relative to `secure/data/vks/` pointing at a raw
960-byte Groth16 VK blob. `dbgen` rejects any file that's not exactly
`VK_BLOB_LEN` bytes (960). The `label` is purely cosmetic and only
appears in the release-review manifest.

### Canonical leaf encoding

The Merkle leaf hash for each entry is `sha256(0x00 || canonical)`,
where `canonical` is the exact byte sequence reconstructed at both
ends of the wire. The dbgen writer emits these bytes into the tree;
the secure-world verifier re-emits the same bytes from the bundle
received via the gateway before hashing. Both implementations share
the layout via `sphincs_tz_shared::db_format` constants.

**ERC20 canonical leaf:**

```
chain_id      u64 LE            (8 B)
contract      [u8; 20]          (20 B)
decimals      u8                (1 B)
name_len      u8                (1 B)
name          [u8; name_len]
symbol_len    u8                (1 B)
symbol        [u8; symbol_len]
```

**VK canonical leaf:**

```
chain_id      u64 LE            (8 B)
contract      [u8; 20]          (20 B)
vk_bytes      [u8; 960]         (960 B)
```

Internal Merkle nodes use `sha256(0x01 || left || right)`. The
`0x00`/`0x01` domain separation prefix stops an attacker who controls
the entry encoding from crafting bytes that look like an
internal-node concatenation, which would otherwise break
second-preimage resistance for the tree.

### dbgen pipeline

`cargo run -p dbgen` (a new workspace member) runs a single
host-side pipeline that produces all four generated outputs:

```
secure/data/erc20.json                     ─┐
                                            ├─► erc20::build_db()
                                            │    ├─ parse + validate rows
                                            │    ├─ sort by (chain_id, contract)
                                            │    ├─ intern name + symbol into pool
                                            │    ├─ compute leaf hashes from canonical encoding
                                            │    ├─ build Merkle tree (pad to pow-2 by dup)
                                            │    └─ emit blob + per-entry proofs
                                            ▼
                                  nonsecure/src/erc20_db.bin   (include_bytes! in NS)
                                  ERC20_DB_ROOT: [u8; 32]      (→ secure/src/db_roots.rs)

secure/data/vks.json                       ─┐
secure/data/vks/*.vk.bin                    ├─► vks::build_db()
                                            │    ├─ load each VK, validate 960 B
                                            │    ├─ dedup VKs by sha256(vk_bytes)
                                            │    ├─ flatten (chain_id, contract) → vk_id
                                            │    ├─ same canonical leaf + Merkle build
                                            │    └─ emit blob + per-entry proofs + review text
                                            ▼
                                  nonsecure/src/vk_db.bin      (include_bytes! in NS)
                                  VK_DB_ROOT: [u8; 32]         (→ secure/src/db_roots.rs)
                                  secure/data/vks.review.txt   (human-reviewable manifest)
```

All four outputs are **checked into the repo** so downstream builds
need only `cargo` (no Node.js, no network access). Rerun `dbgen`
whenever the JSON source changes, and commit the regenerated
outputs alongside the source diff.

### Blob format (generated on-disk layout)

Both blobs share a 32-byte header, a sorted entry array, a
secondary pool (strings for ERC20, VK bytes for VK), and a
per-entry proofs section. Constants live in
`shared/src/db_format.rs`.

**`erc20_db.bin` (`b"ERC2"`):**

```
Header (32 B):
  magic        [u8; 4] = b"ERC2"
  version      u32 LE  = 1
  flags        u32 LE
  entry_cnt    u32 LE
  pool_off     u32 LE    // byte offset of string pool from blob start
  pool_size    u32 LE
  proof_depth  u32 LE    // sibling hashes per proof (= log2(padded n))
  proofs_off   u32 LE    // byte offset of per-entry proofs array

Entries (entry_cnt × 40 B, sorted by (chain_id, contract)):
  chain_id     u64 LE
  contract     [u8; 20]
  name_off     u32 LE     // offset into string pool
  symbol_off   u32 LE
  decimals     u8
  flags        u8
  _pad         [u8; 2]

String pool:
  Length-prefixed: [u8 len][bytes]. Strings are interned at build
  time so "USD Coin" appears once even if 10 chains have a USDC.

Proofs:
  entry_cnt × (proof_depth × 32 B). Proof[i] is the list of sibling
  hashes from leaf i up to the root, ordered leaf-up. The direction
  at each level is implicit from the bits of i.
```

**`vk_db.bin` (`b"VKDB"`):**

Same header shape with `VK_BLOB_LEN = 960`. Entries are 32 B each
(`chain_id`, `contract`, `vk_id: u8`, `vk_sha_pfx: [u8; 3]` — a
defense-in-depth SHA-256 prefix the verifier cross-checks against
the pool entry it indexes). The secondary pool holds `vk_count ×
960` bytes of unique VKs. The `vk_sha_pfx` catches any drift
between the entry's `vk_id` and the pool contents that survived
dbgen's internal checks.

### Round-trip self-test

After writing a blob, `dbgen` immediately opens it through its
host-side mirror of the runtime parser, re-derives the canonical
leaf bytes for every source row, walks the appended Merkle proof up
to the just-computed root, and asserts match. Any drift between the
writer and the reader — which would silently break the secure-world
verifier — fails `dbgen` loudly with a precise error pointing at the
specific row.

The parser mirror lives in `dbgen/src/{erc20.rs,vks.rs}` as
`HostErc20Db` and `HostVkDb`. It deliberately mimics the structure
the **non-secure-side** parser (`nonsecure/src/erc20_db.rs`,
`nonsecure/src/vk_db.rs`) uses so the two can't drift.

### Secure-side Merkle verifier

`secure/src/erc20/merkle.rs` exposes one function, shared by both
DBs:

```rust
pub fn verify_proof(
    canonical: &[u8],
    leaf_index: usize,
    proof_bytes: &[u8],
    proof_depth: usize,
    expected_root: &[u8; 32],
) -> bool;
```

It walks the supplied sibling hashes from `sha256(0x00 || canonical)`
to the root, picking left/right at each level by bit `i` of
`leaf_index`. No heap, no allocation, no panics on bad input — a
bad bundle just returns `false` and the gateway surfaces
`CryptoError` to NS.

### Stale-blob protection

`nonsecure/build.rs` panics at compile time if either of its
`include_bytes!`'d blobs doesn't start with the expected magic. The
common failure mode — "edited `erc20.json`, forgot to run `dbgen`"
— fails the build with a clear "run `cargo run -p dbgen`" message
instead of silently shipping stale data.

```rust
// nonsecure/build.rs
check_db_magic("src/erc20_db.bin", b"ERC2");
check_db_magic("src/vk_db.bin", b"VKDB");
```

The secure-side counterpart is implicit: `secure/src/db_roots.rs`
is generated by `dbgen` as regular Rust source, so any format
mismatch would be caught by the compiler rather than by magic-byte
sniffing.

### Release-review workflow (VK DB only)

`dbgen` also writes `secure/data/vks.review.txt`, a
human-readable manifest that lists the VK DB Merkle root plus every
`(protocol, chain_id, contract, sha256(vk))` triple in the DB:

```
=== ZK Clear-Signing VK Manifest (firmware build artifact) ===
...
Merkle root (VK_DB_ROOT) = db0bddf81091a9fee79a028e3e5a258204d73eda1109e3d97a123cf420661471

aave-v3-supply-v1
  sha256(vk) = f36a73b5bb084a9800ceff63e33e061d182af2b09f6bcef20d441c68fd80292e
  chain      1, contract 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 (Aave V3 Pool, Mainnet)
  chain   8453, contract 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5 (Aave V3 Pool, Base)
  ...
```

**This file is the trust anchor for the whole local-VK lookup
story.** Before signing a firmware release, a human reviewer MUST
compare every `(chain_id, contract, sha256(vk))` row against the
on-chain `clearSigningVKHash` (or equivalent governance source) for
that protocol on that chain. The wallet trusts the firmware-signing
key to attest that this comparison was done — without this
artifact, "local VK lookup" is just "trust the repo maintainer," not
"trust the protocol's on-chain governance."

Concretely, the release-signing checklist adds one step:

```
[ ] git diff secure/data/vks.review.txt
    for every added or modified row:
      [ ] Fetch clearSigningVKHash from the protocol's governance
          contract on the listed chain
      [ ] Confirm it matches sha256(vk) in the manifest
      [ ] Record the verification in the release notes
```

### Putting it all together

```bash
# 1. Edit source data
$EDITOR secure/data/erc20.json
# or drop a new VK and update secure/data/vks.json
cp new_protocol.vk.bin secure/data/vks/
$EDITOR secure/data/vks.json

# 2. Regenerate all four outputs
cargo run -p dbgen

# 3. Review the diff (critical for VK changes)
git diff secure/data/vks.review.txt
# [release reviewer compares new rows against on-chain values]

# 4. Sanity-build both worlds (magic-bytes validator runs here)
make all

# 5. Run the scripted e2e suite
make e2e

# 6. Commit source + all regenerated outputs atomically
git add secure/data/ nonsecure/src/{erc20,vk}_db.bin secure/src/db_roots.rs
git commit -m "..."
```

## QEMU Limitations

### MPC S-Alias Bug (QEMU 8.2.2)

**Symptom:** `SFSR.INVEP` (Invalid Entry Point) SecureFault when NS code branches to
an SG veneer, even though SAU correctly marks the region as NSC and the SG instruction
bytes are verified present.

**Root cause:** QEMU's mps2-an505 model does not allow S-alias reads
(`0x1xxx_xxxx`) of SSRAM blocks marked as NS by the MPC. The SG instruction verification
path reads through this broken path, so it cannot read the SG opcode and reports INVEP.
On real hardware, secure code can access both S and NS memory regardless of MPC settings.

**Workaround:** Shared memory gateway with secure SysTick polling (see "Secure Gateway"
section above). The CMSE veneers are still generated and linked — they will work on
real STM32U585 hardware.

**Note:** Secure code CAN read/write NS memory through the NS alias
(`0x0xxx_xxxx` / `0x2xxx_xxxx`). Only the S-alias of NS-MPC blocks is broken.

## Porting to STM32U585

When the STM32U585 board arrives:

1. **Memory map:** Update `memory.x` files with STM32U585 flash/SRAM addresses.
   The SAU programming model is identical (standard ARMv8-M). The MPC is replaced
   by STM32's GTZC (Global TrustZone Security Controller).

2. **Gateway:** Replace the shared memory gateway with proper CMSE veneers
   (`extern "cmse-nonsecure-entry"`). The veneer generation already works; only the
   NS-side call mechanism changes from shared memory to direct function calls through
   `veneers.o` symbols. The QEMU MPC/SG bug does not affect real hardware.

3. **SPI transport:** Replace `SemihostingSpi` with a real `embedded_hal::spi::SpiDevice`
   implementation using Embassy's SPI driver. The `Tropic01SecureElement` and its
   `with_session!` macro work unchanged — only the SpiDevice impl swaps out.

4. **RNG:** Replace semihosting `/dev/urandom` reads in `secure/src/host_rng.rs`
   with the STM32U585's hardware RNG (`embassy_stm32::rng`) or the TROPIC01's
   TRNG (`session.get_random_value(32)`). The `host_rng::fill` and
   `host_rng::byte` API can stay the same — only the implementation changes.
   This RNG feeds:
   * BIP-39 mnemonic generation in the first-boot wizard (32 bytes of entropy)
   * Word indices for the 3-word backup spot check
   * Ephemeral X25519 keypairs for each TROPIC01 e2e session

5. **Key generation:** Already mnemonic-driven. The first-boot wizard
   (`secure/src/main.rs::run_first_boot_wizard`) prompts the user for a PIN
   and a 24-word BIP-39 mnemonic (generated fresh or restored from paper).
   The 48-byte SLH-DSA seed is then derived deterministically via
   `crypto::slhdsa_seed_from_bip39`. Nothing else needs to change for
   STM32U585 — the mnemonic flow runs identically on the real hardware,
   only the RNG backend differs.

6. **Embassy:** Add `embassy-stm32` for async HAL (USB, SPI, GPIO, RNG). Embassy supports
   STM32U585 via feature flag `stm32u585zi`.

## no_std Dependencies

All cryptographic crates run without heap allocation:

| Crate | Version | no_std | Notes |
|-------|---------|--------|-------|
| `slh-dsa` | 0.2.0-rc.4 | `default-features = false` | 17 KB signatures on stack |
| `aes-gcm` | 0.10 | `default-features = false, features = ["aes"]` | In-place encrypt/decrypt |
| `sha2` | 0.10 | `default-features = false` | Used for KDF + PBKDF2-HMAC-SHA512 + ZK VK hash |
| `hmac` | 0.12 | `default-features = false` | Used for mock MACD + PBKDF2 |
| `signature` | 3.0.0-rc.10 | `default-features = false` | Signer/Verifier traits |
| `bls12_381` | 0.8 | `default-features = false, features = ["groups", "pairings"]` | Groth16 ZK clear-sign verifier; 4 individual pairings, no `multi_miller_loop` so no alloc |
| `sphincs-tz-bip39` | local crate | `#![no_std]` | 24-word BIP-39 mnemonic + PBKDF2-HMAC-SHA512, host-tested against canonical Trezor vectors |
| `tropic01` | git (libtropic-rs) | `#![no_std]` | TROPIC01 driver (optional, `tropic01-se` feature) |
| `x25519-dalek` | 2.0.1 | `default-features = false` | X25519 for e2e session (optional) |

## Security Considerations

- **Key isolation:** SPHINCS+ signing key exists in secure SRAM only during the signing
  operation. It is wiped (zeroed + compiler fence) immediately after use.

- **E2E encrypted transport:** All communication between TrustZone secure world and the
  TROPIC01 chip is encrypted with AES-256-GCM over a Noise_KK1 session (X25519 key
  exchange with pre-shared pairing keys). The private key is encrypted at rest
  (AES-GCM wrap in r-mem), encrypted in transit (session encryption), and only
  plaintext in secure SRAM during signing.

- **PIN bricking:** After `MAX_ATTEMPTS` (9) wrong PINs, the encrypted signing key and
  all MACD state are erased from the secure element. Recovery is impossible by design.

- **Pointer validation:** In the gateway, NS pointers should be validated against
  `NS_SRAM_BASE..NS_SRAM_END` before dereferencing. On real hardware, use the TT
  (Test Target) instruction for proper CMSE address validation.

- **Stack budget:** SPHINCS+ signing requires ~20-34 KB of stack (17 KB for the
  `Signature` struct + working memory). The secure world linker script allocates
  128 KB of SRAM with stack growing from the top.

- **Shared memory:** The gateway command buffer is in NS SRAM and is thus writable
  by the non-secure world at any time. The secure handler treats all data read from
  shared memory as untrusted input.

- **Session freshness:** Each TROPIC01 operation batch generates a fresh ephemeral
  X25519 keypair (from `/dev/urandom` on QEMU, hardware RNG on STM32U585), preventing
  session replay attacks.
