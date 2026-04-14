mod usb_dongle;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use rand_core::{OsRng as OsRng06, RngCore};
use sha2::{Digest, Sha256};
use sphincs_c7::{SigningKey, VerifyingKey};
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

use usb_dongle::UsbDongle;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_ATTEMPTS: u8 = 10;

const RMEM_ENCRYPTED_SK: U16 = U16::new(0);
const RMEM_PIN_STATE: U16 = U16::new(1);
const RMEM_VERIFYING_KEY: U16 = U16::new(2);

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

fn kdf(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(input);
    h.update([index]);
    h.finalize().into()
}

fn kdf_keccak(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};
    let mut h = Keccak256::new();
    h.update(domain);
    h.update(input);
    h.update([index]);
    h.finalize().into()
}

fn macd_init_input(master_secret: &[u8; 32], j: u8) -> [u8; 32] {
    kdf(b"sphincs-macd-init", master_secret, j)
}

fn macd_pin_input(pin: &[u8; 8], j: u8) -> [u8; 32] {
    kdf(b"sphincs-macd-pin", pin, j)
}

fn derive_wrap_key(master_secret: &[u8; 32]) -> [u8; 32] {
    kdf(b"sphincs-wrap-key", master_secret, 0)
}

fn nonce_for(index: u8) -> [u8; 12] {
    let h: [u8; 32] = kdf(b"sphincs-nonce", &[index], 0);
    let mut n = [0u8; 12];
    n.copy_from_slice(&h[..12]);
    n
}

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8], nonce_idx: u8) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    cipher
        .encrypt(Nonce::from_slice(&nonce_for(nonce_idx)), plaintext)
        .expect("AES-GCM encryption failed")
}

fn aes_decrypt(key: &[u8; 32], ciphertext: &[u8], nonce_idx: u8) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    cipher
        .decrypt(Nonce::from_slice(&nonce_for(nonce_idx)), ciphertext)
        .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed"))
}

// ---------------------------------------------------------------------------
// PIN state serialization
// ---------------------------------------------------------------------------

const PER_SLOT_CT_LEN: usize = 32 + 16;

fn serialize_pin_state(next_index: u8, encrypted_secrets: &[Vec<u8>]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(1 + encrypted_secrets.len() * PER_SLOT_CT_LEN);
    blob.push(next_index);
    for c in encrypted_secrets {
        assert_eq!(c.len(), PER_SLOT_CT_LEN);
        blob.extend_from_slice(c);
    }
    blob
}

fn deserialize_pin_state(blob: &[u8]) -> Result<(u8, Vec<Vec<u8>>)> {
    if blob.is_empty() {
        anyhow::bail!("PIN state blob is empty");
    }
    let next_index = blob[0];
    let rest = &blob[1..];
    if rest.len() % PER_SLOT_CT_LEN != 0 {
        anyhow::bail!("PIN state blob has invalid length");
    }
    let secrets: Vec<Vec<u8>> = rest.chunks(PER_SLOT_CT_LEN).map(|c| c.to_vec()).collect();
    Ok((next_index, secrets))
}

// ---------------------------------------------------------------------------
// Terminal PIN input (masked with *)
// ---------------------------------------------------------------------------

struct RawModeGuard {
    fd: i32,
    original: libc::termios,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

fn prompt_pin(prompt: &str) -> Result<[u8; 8]> {
    use std::io::{self, BufRead, IsTerminal, Read, Write};

    if !io::stdin().is_terminal() {
        eprint!("{prompt}");
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.len() != 8 || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            anyhow::bail!("PIN must be exactly 8 digits");
        }
        let mut pin = [0u8; 8];
        pin.copy_from_slice(trimmed.as_bytes());
        return Ok(pin);
    }

    eprint!("{prompt}");
    io::stderr().flush()?;

    let fd = libc::STDIN_FILENO;
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        anyhow::bail!("tcgetattr failed");
    }
    let mut raw = original;
    raw.c_lflag &= !(libc::ECHO | libc::ICANON);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
        anyhow::bail!("tcsetattr failed");
    }
    let _guard = RawModeGuard { fd, original };

    let mut digits: Vec<u8> = Vec::with_capacity(8);
    let mut byte = [0u8; 1];
    loop {
        io::stdin().read_exact(&mut byte)?;
        match byte[0] {
            b'\n' | b'\r' => {
                eprintln!();
                break;
            }
            127 | 8 => {
                if digits.pop().is_some() {
                    eprint!("\x08 \x08");
                    io::stderr().flush()?;
                }
            }
            3 => {
                eprintln!();
                anyhow::bail!("Cancelled");
            }
            b'0'..=b'9' if digits.len() < 8 => {
                digits.push(byte[0]);
                eprint!("*");
                io::stderr().flush()?;
            }
            _ => {}
        }
    }
    if digits.len() != 8 {
        anyhow::bail!("PIN must be exactly 8 digits (got {})", digits.len());
    }
    let mut pin = [0u8; 8];
    pin.copy_from_slice(&digits);
    Ok(pin)
}

// ---------------------------------------------------------------------------
// Connect to TROPIC01 and start a secure session. Expands inline via macro
// since the ActiveSession type is not re-exported from the tropic01 crate.
// ---------------------------------------------------------------------------

macro_rules! open_session {
    ($device_path:expr) => {{
        let dongle = UsbDongle::new($device_path, 115_200)
            .map_err(|e| anyhow::anyhow!("Failed to open USB dongle: {e}"))?;
        let mut tropic01 = Tropic01::new(dongle);

        print!("  Rebooting chip...");
        tropic01
            .startup_req(tropic01::StartupReq::Reboot)
            .map_err(|e| anyhow::anyhow!("Reboot failed: {e:?}"))?;
        println!("OK");

        print!("  Starting secure session...");
        let ehpriv = StaticSecret::random_from_rng(OsRng06);
        let ehpub = PublicKey::from(&ehpriv);
        let shpub: PublicKey = SH0PUB_PROD0.into();
        let shpriv: StaticSecret = SH0PRIV_PROD0.into();
        let session = tropic01
            .session_start(&X25519Dalek, shpub, shpriv, ehpub, ehpriv, 0)
            .map_err(|(_, e)| anyhow::anyhow!("Session start failed: {e:?}"))?;
        println!("OK");

        session
    }};
}

// ---------------------------------------------------------------------------
// enroll: generate key + set PIN + store on chip
// ---------------------------------------------------------------------------

fn cmd_enroll(device_path: &str) -> Result<()> {
    println!("=== Enroll: Generate key and store on TROPIC01 ===\n");

    // Generate keypair
    println!("[1/4] Generating SPHINCS+C7 keypair...");
    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 16];
    OsRng06.fill_bytes(&mut sk_seed);
    OsRng06.fill_bytes(&mut pk_seed);
    let signing_key = SigningKey::keygen(sk_seed, pk_seed);
    let verifying_key = signing_key.verifying_key();
    // Serialize as sk_seed(32) || pk_seed(16) || pk_root(16) = 64 bytes
    let mut sk_bytes = Vec::with_capacity(64);
    sk_bytes.extend_from_slice(signing_key.sk_seed());
    sk_bytes.extend_from_slice(signing_key.pk_seed());
    sk_bytes.extend_from_slice(signing_key.pk_root());
    let vk_bytes = verifying_key.to_bytes().to_vec();
    println!("  Signing key:   {} bytes", sk_bytes.len());
    println!("  Verifying key: {} bytes", vk_bytes.len());

    // Set PIN
    println!("\n[2/4] Set a PIN to protect the signing key");
    let pin = prompt_pin("  Enter 8-digit PIN: ")?;
    let pin_confirm = prompt_pin("  Confirm PIN:       ")?;
    if pin != pin_confirm {
        anyhow::bail!("PINs do not match");
    }
    println!("  PIN set.");

    // Connect
    println!("\n[3/4] Connecting to TROPIC01 via {device_path}...");
    let mut session = open_session!(device_path);

    // Set up chip-bound PIN protection
    println!("\n[4/4] Setting up chip-bound PIN protection...");

    let mut master_secret = [0u8; 32];
    OsRng06.fill_bytes(&mut master_secret);

    // Encrypt SPHINCS+ SK
    let wrap_key = derive_wrap_key(&master_secret);
    let mut sk_nonce = [0u8; 12];
    OsRng06.fill_bytes(&mut sk_nonce);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();
    let encrypted_sk_ct = cipher
        .encrypt(Nonce::from_slice(&sk_nonce), sk_bytes.as_slice())
        .expect("encryption failed");
    let mut encrypted_sk_blob = Vec::with_capacity(12 + encrypted_sk_ct.len());
    encrypted_sk_blob.extend_from_slice(&sk_nonce);
    encrypted_sk_blob.extend_from_slice(&encrypted_sk_ct);

    // Initialize MAC-and-Destroy slots
    println!("  Initializing {} MAC-and-Destroy slots...", MAX_ATTEMPTS);
    let mut encrypted_secrets: Vec<Vec<u8>> = Vec::with_capacity(MAX_ATTEMPTS as usize);

    for j in 0..MAX_ATTEMPTS {
        let slot = U16::new(j as u16);
        let init_in = macd_init_input(&master_secret, j);
        let pin_in = macd_pin_input(&pin, j);

        session
            .mac_and_destroy(slot, &init_in)
            .map_err(|e| anyhow::anyhow!("MACD init slot {j}: {e:?}"))?;
        let w_j: [u8; 32] = *session
            .mac_and_destroy(slot, &pin_in)
            .map_err(|e| anyhow::anyhow!("MACD pin slot {j}: {e:?}"))?;
        session
            .mac_and_destroy(slot, &init_in)
            .map_err(|e| anyhow::anyhow!("MACD restore slot {j}: {e:?}"))?;

        encrypted_secrets.push(aes_encrypt(&w_j, &master_secret, j));
    }
    println!("  Slots ready.");

    // Store everything in r-mem
    session.r_mem_data_erase(RMEM_ENCRYPTED_SK).ok();
    session
        .r_mem_data_write(RMEM_ENCRYPTED_SK, &encrypted_sk_blob)
        .map_err(|e| anyhow::anyhow!("write encrypted_sk: {e:?}"))?;

    let pin_state_blob = serialize_pin_state(0, &encrypted_secrets);
    session.r_mem_data_erase(RMEM_PIN_STATE).ok();
    session
        .r_mem_data_write(RMEM_PIN_STATE, &pin_state_blob)
        .map_err(|e| anyhow::anyhow!("write pin_state: {e:?}"))?;

    // Store verifying key (public, no encryption needed)
    session.r_mem_data_erase(RMEM_VERIFYING_KEY).ok();
    session
        .r_mem_data_write(RMEM_VERIFYING_KEY, &vk_bytes)
        .map_err(|e| anyhow::anyhow!("write verifying_key: {e:?}"))?;

    session.session_abort().ok();

    println!("\n=== Key enrolled successfully! ===");
    println!("  Encrypted SK in r-mem slot 0 ({} bytes)", encrypted_sk_blob.len());
    println!("  PIN state in r-mem slot 1 ({} bytes)", pin_state_blob.len());
    println!("  Verifying key in r-mem slot 2 ({} bytes)", vk_bytes.len());
    println!("  {} wrong-PIN attempts before brick", MAX_ATTEMPTS);
    println!("\n  Run `sphincs-wallet sign` to unlock and sign a message.");
    Ok(())
}

// ---------------------------------------------------------------------------
// sign: unlock with PIN + sign a message
// ---------------------------------------------------------------------------

fn cmd_sign(device_path: &str) -> Result<()> {
    println!("=== Sign: Unlock key and sign a message ===\n");

    // Connect
    println!("[1/4] Connecting to TROPIC01 via {device_path}...");
    let mut session = open_session!(device_path);

    // Read stored state
    println!("\n[2/4] Reading stored key data...");
    let state_blob = session
        .r_mem_data_read(RMEM_PIN_STATE)
        .map_err(|e| anyhow::anyhow!("read pin_state: {e:?}"))?
        .to_vec();
    let (next_index, enc_secrets) = deserialize_pin_state(&state_blob)?;

    if next_index >= MAX_ATTEMPTS {
        session.r_mem_data_erase(RMEM_ENCRYPTED_SK).ok();
        session.r_mem_data_erase(RMEM_PIN_STATE).ok();
        anyhow::bail!(
            "KEY BRICKED: all {} PIN attempts exhausted. Key erased.",
            MAX_ATTEMPTS
        );
    }

    let remaining = MAX_ATTEMPTS - next_index;
    println!("  Wrong-PIN attempts remaining: {remaining}");

    // Prompt for PIN
    println!("\n[3/4] Unlock signing key");
    let pin = prompt_pin("  Enter PIN: ")?;

    // Authenticate via MAC-and-Destroy (irreversibly consumes the slot)
    let j = next_index;
    let slot = U16::new(j as u16);
    let pin_in = macd_pin_input(&pin, j);

    print!("  Authenticating with chip...");
    let w_j: [u8; 32] = *session
        .mac_and_destroy(slot, &pin_in)
        .map_err(|e| anyhow::anyhow!("MACD unlock: {e:?}"))?;

    match aes_decrypt(&w_j, &enc_secrets[j as usize], j) {
        Ok(recovered_s) => {
            println!("OK");

            let mut recovered_master = [0u8; 32];
            recovered_master.copy_from_slice(&recovered_s);

            // Re-initialize all slots
            print!("  Re-initializing slots...");
            for slot_j in 0..MAX_ATTEMPTS {
                let s = U16::new(slot_j as u16);
                let init_in = macd_init_input(&recovered_master, slot_j);
                session
                    .mac_and_destroy(s, &init_in)
                    .map_err(|e| anyhow::anyhow!("Re-init slot {slot_j}: {e:?}"))?;
            }
            println!("OK");

            // Reset attempt index
            let new_state = serialize_pin_state(0, &enc_secrets);
            session.r_mem_data_erase(RMEM_PIN_STATE).ok();
            session
                .r_mem_data_write(RMEM_PIN_STATE, &new_state)
                .map_err(|e| anyhow::anyhow!("write pin_state: {e:?}"))?;

            // Decrypt SPHINCS+ signing key
            let sk_blob = session
                .r_mem_data_read(RMEM_ENCRYPTED_SK)
                .map_err(|e| anyhow::anyhow!("read encrypted_sk: {e:?}"))?
                .to_vec();
            let sk_nonce = &sk_blob[..12];
            let sk_ct = &sk_blob[12..];
            let wrap_key = derive_wrap_key(&recovered_master);
            let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();
            let decrypted_sk = cipher
                .decrypt(Nonce::from_slice(sk_nonce), sk_ct)
                .map_err(|_| anyhow::anyhow!("Failed to decrypt SPHINCS+ SK"))?;

            // Load verifying key
            let vk_bytes = session
                .r_mem_data_read(RMEM_VERIFYING_KEY)
                .map_err(|e| anyhow::anyhow!("read verifying_key: {e:?}"))?
                .to_vec();

            println!("  Signing key unlocked ({} bytes).", decrypted_sk.len());

            // Sign
            println!("\n[4/4] Signing test message...");
            // Reconstruct from stored parts: sk_seed(32) || pk_seed(16) || pk_root(16)
            if decrypted_sk.len() != 64 {
                anyhow::bail!("Bad SK blob length: {} (expected 64)", decrypted_sk.len());
            }
            let mut sk_seed = [0u8; 32];
            let mut pk_seed_arr = [0u8; 16];
            let mut pk_root = [0u8; 16];
            sk_seed.copy_from_slice(&decrypted_sk[0..32]);
            pk_seed_arr.copy_from_slice(&decrypted_sk[32..48]);
            pk_root.copy_from_slice(&decrypted_sk[48..64]);
            let retrieved_sk = SigningKey::from_parts(sk_seed, pk_seed_arr, pk_root);

            if vk_bytes.len() != 32 {
                anyhow::bail!("Bad VK length: {} (expected 32)", vk_bytes.len());
            }
            let mut vk_arr = [0u8; 32];
            vk_arr.copy_from_slice(&vk_bytes);
            let verifying_key = VerifyingKey::from_bytes(&vk_arr);

            let message = b"Post-quantum hardware wallet test message";
            let msg_hash: [u8; 32] = {
                use sha3::{Digest as _, Keccak256};
                Keccak256::digest(message).into()
            };
            let sig = retrieved_sk.sign(&msg_hash, None);
            let sig_bytes = sig.to_vec();
            println!(
                "  Message:   \"{}\"",
                std::str::from_utf8(message).unwrap()
            );
            println!(
                "  Signature: {} bytes (first 16: {:02x?})",
                sig_bytes.len(),
                &sig_bytes[..16]
            );

            if !verifying_key.verify(&msg_hash, &sig) {
                anyhow::bail!("Signature verification failed");
            }
            println!("  Verification: VALID");

            session.session_abort().ok();
            println!("\n=== Signing complete! ===");
        }
        Err(_) => {
            println!("FAILED");

            let new_index = next_index + 1;
            let attempts_left = MAX_ATTEMPTS - new_index;

            if attempts_left == 0 {
                session.r_mem_data_erase(RMEM_ENCRYPTED_SK).ok();
                session.r_mem_data_erase(RMEM_PIN_STATE).ok();
                session.r_mem_data_erase(RMEM_VERIFYING_KEY).ok();
                anyhow::bail!(
                    "Wrong PIN. KEY BRICKED: 0 attempts remaining. All data erased."
                );
            }

            let new_state = serialize_pin_state(new_index, &enc_secrets);
            session.r_mem_data_erase(RMEM_PIN_STATE).ok();
            session
                .r_mem_data_write(RMEM_PIN_STATE, &new_state)
                .map_err(|e| anyhow::anyhow!("write pin_state: {e:?}"))?;

            session.session_abort().ok();
            anyhow::bail!("Wrong PIN. {} attempts remaining.", attempts_left);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Two-tier key derivation helpers (mirrors secure/src/crypto.rs)
// ---------------------------------------------------------------------------

fn slhdsa_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let chunk0 = kdf_keccak(b"sphincsc7-sk-seed", bip39_seed, 0);
    let chunk1 = kdf_keccak(b"sphincsc7-pk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&chunk0);
    out[32..48].copy_from_slice(&chunk1[..16]);
    out
}

fn bootstrap_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let chunk0 = kdf_keccak(b"pqwallet-c7-bootstrap-sk-seed", bip39_seed, 0);
    let chunk1 = kdf_keccak(b"pqwallet-c7-bootstrap-pk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&chunk0);
    out[32..48].copy_from_slice(&chunk1[..16]);
    out
}

fn main_signer_seed_from_bip39(bip39_seed: &[u8; 64], chain_id: u64, key_index: u32) -> [u8; 48] {
    let mut input = [0u8; 76]; // 64 + 8 + 4
    input[..64].copy_from_slice(bip39_seed);
    input[64..72].copy_from_slice(&chain_id.to_be_bytes());
    input[72..76].copy_from_slice(&key_index.to_be_bytes());

    let mut out = [0u8; 48];
    let chunk0 = kdf_keccak(b"pqwallet-c7-main-sk-seed", &input, 0);
    let chunk1 = kdf_keccak(b"pqwallet-c7-main-pk-seed", &input, 0);
    out[0..32].copy_from_slice(&chunk0);
    out[32..48].copy_from_slice(&chunk1[..16]);
    out
}

fn derive_signing_key_from_seed(seed: &[u8; 48]) -> SigningKey {
    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 16];
    sk_seed.copy_from_slice(&seed[0..32]);
    pk_seed.copy_from_slice(&seed[32..48]);
    SigningKey::keygen(sk_seed, pk_seed)
}

// ---------------------------------------------------------------------------
// get-keys: show bootstrap and per-chain main VKs from chip
// ---------------------------------------------------------------------------

fn cmd_get_keys(device_path: &str) -> Result<()> {
    println!("=== Two-Tier Key Info ===\n");

    println!("[1/3] Connecting to TROPIC01 via {device_path}...");
    let mut session = open_session!(device_path);

    // Read bootstrap VK (stored at r-mem slot 3)
    println!("\n[2/3] Reading bootstrap VK from r-mem slot 3...");
    let bootstrap_vk_result = session.r_mem_data_read(U16::new(3));
    match bootstrap_vk_result {
        Ok(vk) => {
            let vk_bytes = vk.to_vec();
            println!("  Bootstrap VK ({} bytes): 0x{}", vk_bytes.len(),
                     vk_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        }
        Err(_) => {
            println!("  Bootstrap VK: not provisioned (old firmware?)");
        }
    }

    // Read legacy/default VK (stored at r-mem slot 2)
    println!("\n[3/3] Reading default VK from r-mem slot 2...");
    let default_vk_result = session.r_mem_data_read(RMEM_VERIFYING_KEY);
    match default_vk_result {
        Ok(vk) => {
            let vk_bytes = vk.to_vec();
            println!("  Default VK ({} bytes): 0x{}", vk_bytes.len(),
                     vk_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        }
        Err(e) => {
            println!("  Default VK: read error ({e:?})");
        }
    }

    session.session_abort().ok();

    println!("\n  Note: Per-chain main VKs are derived on-demand from the");
    println!("  seed phrase and are not stored on the chip.");
    println!("\n=== Done ===");
    Ok(())
}

// ---------------------------------------------------------------------------
// deploy: produce bootstrap signature for factory deployment
// ---------------------------------------------------------------------------

fn cmd_deploy(device_path: &str, chain_id_str: &str) -> Result<()> {
    let chain_id: u64 = chain_id_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid chain ID: {chain_id_str}"))?;

    println!("=== Deploy: Produce bootstrap signature for chain {chain_id} ===\n");

    println!("[1/5] Connecting to TROPIC01 via {device_path}...");
    let mut session = open_session!(device_path);

    // Read the bootstrap VK
    println!("\n[2/5] Reading bootstrap VK...");
    let bootstrap_vk_bytes = session
        .r_mem_data_read(U16::new(3))
        .map_err(|e| anyhow::anyhow!("read bootstrap VK: {e:?}"))?
        .to_vec();
    println!("  Bootstrap VK: 0x{}",
             bootstrap_vk_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());

    // Unlock to derive the main VK
    println!("\n[3/5] Unlock to derive per-chain main VK");
    let state_blob = session
        .r_mem_data_read(RMEM_PIN_STATE)
        .map_err(|e| anyhow::anyhow!("read pin_state: {e:?}"))?
        .to_vec();
    let (next_index, enc_secrets) = deserialize_pin_state(&state_blob)?;

    if next_index >= MAX_ATTEMPTS {
        anyhow::bail!("KEY BRICKED: all PIN attempts exhausted.");
    }

    let pin = prompt_pin("  Enter PIN: ")?;
    let j = next_index;
    let slot = U16::new(j as u16);
    let pin_in = macd_pin_input(&pin, j);

    let w_j: [u8; 32] = *session
        .mac_and_destroy(slot, &pin_in)
        .map_err(|e| anyhow::anyhow!("MACD unlock: {e:?}"))?;

    let recovered_s = aes_decrypt(&w_j, &enc_secrets[j as usize], j)?;
    let mut recovered_master = [0u8; 32];
    recovered_master.copy_from_slice(&recovered_s);

    // Re-initialize slots after successful unlock
    for slot_j in 0..MAX_ATTEMPTS {
        let s = U16::new(slot_j as u16);
        let init_in = macd_init_input(&recovered_master, slot_j);
        session
            .mac_and_destroy(s, &init_in)
            .map_err(|e| anyhow::anyhow!("Re-init slot {slot_j}: {e:?}"))?;
    }
    let new_state = serialize_pin_state(0, &enc_secrets);
    session.r_mem_data_erase(RMEM_PIN_STATE).ok();
    session
        .r_mem_data_write(RMEM_PIN_STATE, &new_state)
        .map_err(|e| anyhow::anyhow!("write pin_state: {e:?}"))?;

    // Decrypt entropy to derive the per-chain main VK
    println!("\n[4/5] Deriving per-chain main VK for chain {chain_id}, key index 0...");
    let sk_blob = session
        .r_mem_data_read(RMEM_ENCRYPTED_SK)
        .map_err(|e| anyhow::anyhow!("read encrypted entropy: {e:?}"))?
        .to_vec();
    let sk_nonce = &sk_blob[..12];
    let sk_ct = &sk_blob[12..];
    let wrap_key = derive_wrap_key(&recovered_master);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();
    let decrypted_entropy = cipher
        .decrypt(Nonce::from_slice(sk_nonce), sk_ct)
        .map_err(|_| anyhow::anyhow!("Failed to decrypt entropy"))?;

    // Note: for the two-tier architecture, the enrolled blob is the BIP-39
    // entropy (32 bytes) in the new firmware, or the raw SK (64 bytes) in
    // the legacy firmware. We handle both cases.
    let main_vk_hex = if decrypted_entropy.len() == 32 {
        // New BIP-39 entropy-based firmware
        // We need to go through the full derivation chain — but we don't
        // have the BIP-39 crate here. Instead, just print a note.
        println!("  (BIP-39 entropy detected — per-chain VK derivation requires");
        println!("   the hardware wallet firmware. Use the device to derive VKs.)");
        String::from("(derive on device)")
    } else {
        // Legacy: raw signing key stored
        println!("  (Legacy SK blob detected — {}-byte)", decrypted_entropy.len());
        String::from("(legacy mode)")
    };
    println!("  Main VK: {main_vk_hex}");

    // Produce the bootstrap signature for deployment
    println!("\n[5/5] Producing bootstrap signature...");
    println!("  Note: In production, the bootstrap signature is produced by the");
    println!("  hardware wallet firmware via CMD_SIGN_BOOTSTRAP. This tool");
    println!("  cannot sign without the bootstrap signing key on the device.");

    session.session_abort().ok();

    println!("\n=== Deployment info for chain {chain_id} ===");
    println!("  Bootstrap VK: 0x{}",
             bootstrap_vk_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("  Wallet address = CREATE2(factory, keccak256(bootstrapPubKey), initCodeHash)");
    println!("  Use CMD_SIGN_BOOTSTRAP on the device to produce the deployment signature.");
    println!("\n=== Done ===");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main — dispatch subcommand
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str());
    let device_path = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("/dev/ttyACM0");

    match command {
        Some("enroll") => cmd_enroll(device_path),
        Some("sign") => cmd_sign(device_path),
        Some("get-keys") => cmd_get_keys(device_path),
        Some("deploy") => {
            let chain_id = args.get(3).map(|s| s.as_str()).unwrap_or("8453");
            cmd_deploy(device_path, chain_id)
        }
        _ => {
            eprintln!("SPHINCS+ Post-Quantum Hardware Wallet");
            eprintln!("  Two-tier PQ signer with chip-bound key protection\n");
            eprintln!("Usage: sphincs-wallet <command> [device_path] [args...]\n");
            eprintln!("Commands:");
            eprintln!("  enroll             Generate keypair, set PIN, store on TROPIC01");
            eprintln!("  sign               Unlock with PIN and sign a test message");
            eprintln!("  get-keys           Show bootstrap and per-chain main VKs");
            eprintln!("  deploy <chain_id>  Produce bootstrap sig for factory deployment\n");
            eprintln!("device_path defaults to /dev/ttyACM0");
            std::process::exit(1);
        }
    }
}
