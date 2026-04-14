# Side-channel attacks on SLH-DSA for PQSigner OS: a comprehensive threat assessment

**PQSigner OS faces a critical and immediate side-channel vulnerability: the SLH-DSA PRF function processes the master secret SK.seed over 8,000 times per signature, creating a textbook DPA target that requires as few as 1–10 observed signatures to exploit on an unprotected Cortex-M33.** No full key-recovery has been published against SPHINCS+/SLH-DSA specifically, but Saarinen's TVLA assessment at CRYPTO 2024 showed catastrophic leakage (t-statistic of **24.5 at just 1,000 traces**, where the concern threshold is 4.5) from CPU-based SLH-DSA implementations. The current software SHA-256 implementation via the Rust `sha2` crate, running unmasked on STM32U585, represents the worst-case configuration. Neither the HASH hardware peripheral nor the planned 128f→192f migration addresses this. The primary mitigation path is either adopting Fluhrer's PRF-tree architecture (1.7× overhead, SHAKE only) or implementing masked SHA-256 for PRF calls (3–5× overhead, likely impractical in pure software at 160 MHz).

---

## Q1: No full key-recovery exists, but the attack surface is proven

The published literature contains **no practical, end-to-end SCA key-recovery attack against SPHINCS+ or SLH-DSA**. However, three papers collectively demonstrate that such an attack is straightforward to mount against unprotected implementations:

**Kannwischer, Genêt, Butin, Krämer, and Buchmann (COSADE 2018)** performed DPA on SPHINCS-256's BLAKE-256 PRF and **recovered a 32-bit chunk of the secret key** using approximately 10,000 power traces with a Hamming-weight correlation model. The attack targeted the PRF's repeated consumption of the same secret key material across signatures — structurally identical to SLH-DSA's PRF(SK.seed, ADRS) construction.

**Saarinen (CRYPTO 2024, "SLotH")** conducted the first quantitative side-channel sensitivity assessment of SLH-DSA across all 12 NIST parameter sets. Using a **100,000-trace TVLA (Test Vector Leakage Assessment)**, he demonstrated that CPU-based implementations show immediate, catastrophic leakage of SK.seed. The protected SLotH hardware unit — which keeps SK.seed inside a dedicated hash accelerator and never exposes it to the CPU — passed the same TVLA at 100K traces. This experimentally confirms that the leak surface is the CPU processing of SK.seed, not the algorithm itself.

**Fluhrer (ePrint 2024/500, NIST 5th PQC Conference 2024)** proposed a DPA-resistant SLH-DSA architecture using PRF trees that limit secret reuse to ≤5 contexts per intermediate value. He explicitly states that standard SPHINCS+ is **immune to timing and cache-based side-channel attacks** (no secret-dependent branches or memory accesses in a constant-time implementation) but highly vulnerable to power/EM DPA due to repeated PRF calls with the same SK.seed.

The closest published analogues for trace-count estimation come from HMAC-SHA-256 DPA literature. Belenky et al. (TCHES 2023) achieved **100% key-derivative recovery on unprotected hardware SHA-256 using 275,000 traces** with their novel CDPA technique, and earlier (COSADE 2021) achieved **full recovery with a template attack using ~30,000 traces and equipment costing under $3,000**. Belaïd et al. (2013) demonstrated ~2,600 traces per 8-bit sub-key in simulation. These numbers apply to hardware implementations; **software SHA-256 on Cortex-M typically leaks more** due to sequential word-level processing that creates stronger Hamming-weight/distance signatures.

The fault-attack literature is more mature: Genêt (TCHES 2023) showed that a single random bit flip anywhere in SPHINCS+ signing drops security guarantees with high probability, and Genêt, Kannwischer et al. (Kangacrypt 2018) demonstrated practical voltage-glitch forgery on Arduino Due (Cortex-M3) in seconds. The SLasH-DSA paper (2025) achieved software-only universal forgery via Rowhammer against OpenSSL's SLH-DSA.

---

## Q2: PRF(SK.seed) dominates the leak surface by orders of magnitude

A detailed analysis of SLH-DSA-SHA2-128f signing reveals **105,196 total hash operations per signature**, of which **8,272 are PRF calls that directly consume SK.seed**. These PRF calls constitute the overwhelmingly dominant threat surface.

### Hash operation breakdown per SLH-DSA-SHA2-128f signature

| Operation | Count | Secret input | Severity |
|-----------|-------|-------------|----------|
| **PRF(SK.seed, ADRS)** — FORS leaf secrets | **2,112** | SK.seed (master secret) | **Critical** |
| **PRF(SK.seed, ADRS)** — WOTS+ secret keys | **6,160** | SK.seed (master secret) | **Critical** |
| F (WOTS+ chain hashes) | 92,400 | Derived chain values | High |
| F (FORS leaf public values) | 2,112 | Derived FORS secrets | Medium-High |
| H (Merkle tree internal nodes) | 2,233 | Public values only | None |
| T (root compressions) | 177 | Public values only | None |
| PRFmsg(SK.prf, OptRand, M) | 1 | SK.prf | Medium |
| Hmsg (message digest) | 1 | Public values only | None |

**PRF(SK.seed) is a textbook DPA target** because it processes the same 16-byte secret with different, known, public ADRS values across 8,272 invocations per signature. The ADRS structure is fully deterministic and derivable by an attacker from the public signature. This means each signature provides the attacker with **8,272 correlated sub-traces** — enabling horizontal DPA within a single signing operation. For comparison, the COSADE 2018 attack on SPHINCS-256 needed ~10,000 traces total across ~2,000 signatures with 5–7 PRF calls each. PQSigner OS provides more traces in a single signature than that attack used in total.

**WOTS+ chain F calls** (92,400 per signature) process derived secret values, not SK.seed directly. Each intermediate chain value is used exactly once, making classical DPA harder, but Hamming-weight leakage from the F function still reveals partial information about derived secrets. Fluhrer notes that even single-use values leak "some information (such as the Hamming weights of some sequences of bits of a secret value)."

**FORS leaf generation** (2,112 PRF + 2,112 F calls) feeds into the PRF threat: the PRF calls generating FORS secrets are included in the 8,272 critical PRF invocations above. The F calls processing FORS secrets are single-use but could leak partial information enabling reduced-complexity forgery.

**SK.prf via PRFmsg** is invoked only once per signature but is vulnerable across many signatures. If the attacker collects HMAC-SHA-256 traces across ~500–10,000 signing operations, SK.prf recovery is feasible. Combined with deterministic signing (OptRand = 0), SK.prf recovery enables the attacker to predict FORS instance selection for any message.

**HT layer transitions** leak no secret information — the traversal path is public and derivable from the signature.

---

## Q3: The STM32U585 HASH peripheral is not SCA-hardened

**ST Microelectronics makes no DPA/SPA resistance claims for the HASH peripheral**, in sharp contrast to the SAES and PKA peripherals which explicitly advertise DPA resistance in the datasheet (DS13086), reference manual (RM0456), and training materials. The distinction is unambiguous: the datasheet describes "a secure AES coprocessor **with DPA resistance**" and "a PKA **with DPA resistance**" but lists the "HASH hardware accelerator" with no security qualifier.

ST's own SESIP guidance document (UM3370 for STM32MP25xx) contains the statement: **"Cryptographic hash operations, available in the HASH peripheral, must not be used to manipulate sensitive [data]."** This is an explicit admission that the HASH peripheral lacks the internal countermeasures (masking, shuffling, dummy rounds, random seed injection) that SAES and PKA employ. The HASH peripheral is **not connected to the RNG's private bus** that feeds random seeds to SAES and PKA for their DPA countermeasures.

### Routing SHA-256 through HASH: relocates the leak, does not eliminate it

Using the HASH peripheral for SLH-DSA's SHA-256 operations provides two genuine benefits: **constant-time execution** (eliminating software timing side-channels) and **significant performance improvement** (~66 cycles per 512-bit block vs. hundreds in software). However, three leak surfaces remain:

- **AHB bus transfers to HASH_DIN**: Writing SK.seed bytes to the peripheral's input register creates bus transitions proportional to the Hamming weight/distance of the data
- **Internal computation**: The HASH engine performs SHA-256 compression with fixed, deterministic power patterns — no random masking or shuffling occurs, producing more predictable and concentrated power signatures than spread-out software instructions
- **AHB bus transfers from HASH_HR[0..7]**: Reading digest registers leaks output values

Academic literature confirms that unprotected hardware SHA-256 is DPA-vulnerable. Belenky et al. (COSADE 2021) achieved full key-derivative disclosure on an FPGA hardware SHA-256 with ~30K traces and a $3K setup. The HASH peripheral's concentrated, predictable power profile may actually produce **cleaner** DPA signals than software implementations.

### Recommended HASH peripheral configuration

Despite lacking SCA hardening, the HASH peripheral should still be used for performance and timing-channel elimination. Configure it as follows:

```c
// 1. Enable clocks
__HAL_RCC_HASH_CLK_ENABLE();
__HAL_RCC_GTZC1_CLK_ENABLE();

// 2. Lock HASH to secure world via GTZC
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_HASH,
    GTZC_TZSC_PERIPH_SEC | GTZC_TZSC_PERIPH_PRIV);

// 3. Configure HASH_CR for SHA-256
// HASH_CR: ALGO[1]=1, ALGO[0]=0 → SHA-256
// DATATYPE=0b10 (byte swap), DMAE=1 if using DMA
HASH->CR = HASH_CR_ALGO_1 | HASH_CR_DATATYPE_1 | HASH_CR_INIT;

// 4. DMA channel: secure source + secure destination
DMA_NodeConfTypeDef nodeConfig;
nodeConfig.SrcSecure  = DMA_CHANNEL_SRC_SEC;
nodeConfig.DestSecure = DMA_CHANNEL_DEST_SEC;

// 5. Enable illegal-access detection via TZIC
HAL_GTZC_TZIC_EnableIT(GTZC_PERIPH_HASH);
```

**Verdict: Use HASH for performance and timing safety, but treat it as providing zero DPA protection.** All software-level SCA countermeasures (masking, shuffling, PRF-tree) remain necessary.

---

## Q4: 2^20 rotation is insufficient without countermeasures, generous with them

The rotation cadence question cannot be answered independently of the countermeasure posture. The critical insight is that **a single SLH-DSA-SHA2-128f signature provides 8,272 PRF sub-traces** with the same SK.seed, enabling horizontal DPA within one signing operation.

### Trace-count thresholds from the literature

| Attack type | Target | Traces needed | Source |
|-------------|--------|--------------|--------|
| Horizontal DPA (unprotected CPU) | SLH-DSA PRF(SK.seed) | **1–10 signatures** (~8K–83K sub-traces) | Extrapolated from Saarinen TVLA (t=24.5 at 1K traces) |
| CDPA (non-profiled) | HMAC-SHA-256 on HW | 30K–275K traces | Belenky et al. (TCHES 2023) |
| Template attack (profiled) | HMAC-SHA-256 on HW | ~30K traces (profiling + attack) | Belenky et al. (COSADE 2021) |
| Classical DPA | HMAC-SHA-256 (simulated) | ~2,600 per 8-bit chunk | Belaïd et al. (2013) |
| CPA on Cortex-M23 (TrustZone bypassed) | AES in secure world | 1,000–5,000 | O'Flynn (TCHES 2019) |

### Rotation sufficiency analysis

| Countermeasure level | Signatures to break | 2^20 budget | Verdict |
|---------------------|--------------------|-----------|---------| 
| Unprotected software SHA-256 | **1–10** | 1,048,576 | **Catastrophically insufficient** |
| Constant-time, no masking | **10–100** | 1,048,576 | **Completely insufficient** |
| 1st-order masked PRF | 1,000–10,000 | 1,048,576 | Marginal (100× margin at best) |
| 2nd-order masking | 100,000–1,000,000 | 1,048,576 | Borderline sufficient |
| PRF-tree + shuffling + masking | >1,000,000 | 1,048,576 | Sufficient |

**Recommended rotation cadences:**

- **With current implementation (unmasked `sha2` crate)**: Rotation is irrelevant — implement countermeasures first. Even rotating every signature would not help because one signature suffices for attack.
- **With 1st-order masked PRF**: Rotate every **2^14 (16,384)** signatures for a ≥10× safety margin.
- **With 2nd-order masking or PRF-tree**: **2^20 is adequate**. Could safely extend to 2^24.
- **Conservative universal recommendation**: **2^16 (65,536) signatures** provides a comfortable margin against profiled deep-learning attacks across all reasonable countermeasure levels.

An additional architectural defense: **implement a signing rate limiter**. For a hardware wallet signing ERC-4337 UserOperations, legitimate usage is unlikely to exceed 100 signatures per day. Rate-limiting to 1 signature per second with a daily cap of 1,000 extends the time an attacker needs to collect traces from minutes to months, providing meaningful practical security even if the cryptographic countermeasures are imperfect.

---

## Q5: The 128f→192f migration is orthogonal to side-channel resistance

**Migrating from SHA2-128f to SHA2-192f provides no meaningful SCA improvement.** Both parameter sets use SHA-256 as the core hash primitive. The DPA attack targets the SHA-256 compression function processing SK.seed — the same function, the same intermediate values, the same leakage model. The only differences:

- **More PRF calls**: 192f requires **17,424 PRF(SK.seed) calls per signature** vs. 8,272 for 128f (due to deeper FORS trees: t=256 vs. t=64). This actually **doubles the attack surface**.
- **Wider secret**: SK.seed is 24 bytes vs. 16 bytes, forcing the attacker to recover 50% more bytes — but DPA recovers keys byte-by-byte, so effort scales linearly (1.5×), not exponentially.
- **More WOTS+ chains**: 51 vs. 35 chains per instance, creating more intermediate secret values and more F-function leak points.
- **Doubled signature size**: 35,664 bytes vs. 17,088 bytes, with 32% longer signing time.

The well-established principle in implementation security is that side-channel attacks are implementation attacks, not parameter attacks. Increasing the security parameter defends against mathematical cryptanalysis (quantum search, collision finding), not against DPA, which exploits physical leakage from the computation itself. Fluhrer's residual-leakage probabilities for his protected PRF-tree design show 2^{-223} for 128-bit on 32-bit processors vs. 2^{-332} for 192-bit — both astronomically small and neither being the practical limiting factor.

**The choice that actually matters for SCA is hash family, not security level.** SHA-256 mixes Boolean operations (XOR, AND, NOT) with arithmetic operations (modular addition) every round, requiring expensive Boolean-to-arithmetic and arithmetic-to-Boolean (A2B/B2A) conversions for masking — estimated 3–5× overhead per hash call in software. Keccak/SHAKE uses **purely Boolean operations** with a 1,600-bit internal state, enabling efficient threshold implementations where only the first and last 2 rounds need protection (middle 20 rounds operate on effectively random state). Saarinen explicitly notes that SHA-2 is "very poorly suited" for masking. **If SCA is the primary concern, migrating to SLH-DSA-SHAKE-128f is dramatically more effective than migrating to SHA2-192f.**

---

## Catalogued threat list with severity ratings and mitigations

| # | Threat | Severity | Mechanism | Traces to exploit | Mitigation | Mitigation cost |
|---|--------|----------|-----------|-------------------|------------|----------------|
| T1 | **DPA on PRF(SK.seed)** | **Critical** | 8,272 PRF calls/sig with same secret, varying known ADRS | 1–10 sigs (unprotected) | PRF-tree architecture (SHAKE) or masked SHA-256 for PRF calls | 1.7× (PRF-tree) or 3–5× (masking) |
| T2 | **Hamming-weight leak from WOTS+ F chains** | **High** | 92,400 F calls processing derived secrets; partial HW leak per call | ~100 sigs (profiled template) | 3-share threshold F (SHAKE) or masked F (SHA-256); shuffled chain order | 1.5× (threshold) |
| T3 | **FORS leaf secret leakage via F** | **Medium-High** | 2,112 F calls on FORS secrets; combined with T1 enables FORS forgery | Via T1 primarily | Full treehash (no optimization); randomized tree order; F masking | Negligible (full treehash) |
| T4 | **DPA on SK.prf via PRFmsg** | **Medium** | 1 HMAC-SHA-256/sig across many sigs; SK.prf recovery enables chosen-msg | 500–10,000 sigs | Mandatory random OptRand via TRNG; masked HMAC inner block | ~0% (OptRand) |
| T5 | **Bus timing side-channel (BUSted!)** | **Medium** | Microarchitectural bus arbitration leaks secure-world data to NS code | Software-only, ~6 bits/measurement | Disable NS DMA during signing; avoid concurrent NS/S bus contention | Minor firmware change |
| T6 | **Fault injection (voltage glitch)** | **Medium** | Single bit flip during signing enables universal forgery (Genêt TCHES 2023) | 1 faulted signature | Redundant computation + comparison; note: sign-then-verify is NOT effective | 2× signing time |
| T7 | **EM probe on HASH peripheral** | **Medium** | Concentrated power profile from unmasked HW SHA-256 | ~30K sub-traces (per Belenky) | Board-level EM shielding; decoupling caps; noise injection via TRNG-driven dummy ops | Hardware cost |
| T8 | **HT layer traversal pattern** | **Low** | Layer transitions reveal tree index — but this is public information | N/A | None needed | N/A |

---

## Concrete implementation recommendations

### Architecture-level decisions (must resolve before shipping)

**1. Strongly consider migrating from SHA-2 to SHAKE parameter sets.** This is the single highest-impact decision for SCA resistance. SHAKE enables efficient threshold implementations, the Fluhrer PRF-tree architecture (reference implementation at `github.com/sphincs/sidechannel-resistent`), and has a 1,600-bit internal state where middle rounds are effectively random. If ERC-4337 contract verification requires SHA-2 (e.g., for on-chain verification gas costs), maintain SHA-2 for the on-chain verifier but consider whether the signer can use SHAKE internally. Note that Fluhrer's PRF-tree signatures are **compatible with standard SLH-DSA verification** — only the private key format differs.

**2. Implement mandatory non-deterministic signing.** This is the cheapest, highest-value countermeasure. The STM32U585 has a hardware TRNG (RNG peripheral). Generate 16 bytes of fresh randomness for OptRand on every signature:

```rust
// In slh_sign():
let mut opt_rand = [0u8; N]; // N=16 for 128f, N=24 for 192f
// Read from STM32U585 RNG peripheral (address 0x420C0800 in secure world)
unsafe {
    let rng = &*(0x520C_0800 as *const RngRegisters); // Secure alias
    while rng.sr.read() & RNG_SR_DRDY == 0 {} // Wait for data ready
    for chunk in opt_rand.chunks_exact_mut(4) {
        while rng.sr.read() & RNG_SR_DRDY == 0 {}
        chunk.copy_from_slice(&rng.dr.read().to_le_bytes());
    }
}
// Pass opt_rand to PRFmsg computation — NEVER use zeros
```

**3. Implement a signing rate limiter.** For an ERC-4337 smart wallet, legitimate signing frequency is low. Enforce:

```rust
const MAX_SIGS_PER_SECOND: u32 = 1;
const MAX_SIGS_PER_DAY: u32 = 500;
const MAX_SIGS_PER_KEY: u32 = 65_536; // 2^16 rotation threshold

// In secure-world signing handler:
if daily_counter >= MAX_SIGS_PER_DAY { return Err(RateLimited); }
if key_counter >= MAX_SIGS_PER_KEY { return Err(RotationRequired); }
if ticks_since_last_sig < SYSTICK_HZ { return Err(TooFast); }
```

**4. Implement WOTS+ chain and FORS tree shuffling.** Negligible cost, provides trace desynchronization:

```rust
fn fisher_yates_shuffle(perm: &mut [u8], rng: &mut HwRng) {
    for i in (1..perm.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        perm.swap(i, j);
    }
}

// Before WOTS+ chain computation:
let mut chain_order: Vec<u8> = (0..WOTS_LEN as u8).collect();
fisher_yates_shuffle(&mut chain_order, &mut rng);
for &idx in &chain_order {
    compute_wots_chain(idx as usize, ...);
}

// Before FORS tree computation:
let mut tree_order: Vec<u8> = (0..FORS_K as u8).collect();
fisher_yates_shuffle(&mut tree_order, &mut rng);
```

**5. Always compute full FORS trees.** Do not optimize treehash to skip leaf computations. The standard reference implementation already computes all t leaves per tree — verify that the Rust implementation does the same. Any "optimization" that skips leaves creates data-dependent memory access patterns.

**6. Zeroize all intermediate secrets immediately after use:**

```rust
use zeroize::Zeroize; // Use the zeroize crate with Rust

// After signing completes:
sk_seed_buffer.zeroize();
wots_secret_keys.zeroize();
fors_secret_values.zeroize();
// Compiler barrier to prevent reordering
core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
// Data synchronization barrier for Cortex-M33
unsafe { core::arch::arm::__dsb(0xF); }
```

**7. Configure GTZC to isolate all crypto peripherals and key SRAM:**

```c
// Lock HASH, RNG, and SAES to secure privileged world
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_HASH,
    GTZC_TZSC_PERIPH_SEC | GTZC_TZSC_PERIPH_PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_RNG,
    GTZC_TZSC_PERIPH_SEC | GTZC_TZSC_PERIPH_PRIV);

// Lock SRAM2 (used for key material) as secure via MPCBB
// GTZC1_MPCBB2_SECCFGR0: set all bits to 1 (all 256-byte blocks secure)
GTZC_MPCBB2->SECCFGR[0] = 0xFFFFFFFF;
// Enable SRAM2 secure watermark in FLASH_SECWM (prevents readback)
```

### Board-level countermeasures for the B-U585I-IOT02A

The Discovery board is a development platform, not a production form factor. For production hardware:

- Add **ferrite beads** on USB-C VBUS to attenuate power-line leakage
- Place **100nF + 10nF decoupling capacitors** as close as possible to VDD/VDDA pins
- Consider a **metal shield can** over the STM32U585 to attenuate EM emanation
- Use the STM32U585's internal voltage regulator (SMPS mode) rather than external LDO — switching regulators add noise that degrades attacker SNR
- Route high-speed TRNG output to an unused GPIO toggling during signing to inject power noise

---

## Conclusion: what changes and what to do next

Three findings fundamentally reshape PQSigner OS's security posture. First, the **PRF(SK.seed) vulnerability is not theoretical** — Saarinen's TVLA measurements prove that unprotected CPU-based SLH-DSA implementations leak the master secret rapidly, and the 8,272 PRF calls per signature provide an attacker with more than enough statistical material from a single signing operation. Second, **neither the HASH peripheral nor TrustZone provides side-channel protection** — ST explicitly excludes the HASH peripheral from its DPA-resistant components, and published attacks (O'Flynn 2019, BUSted! 2024) have bypassed TrustZone-M isolation via physical and microarchitectural side-channels on closely related Cortex-M chips. Third, **the SHA-2 vs. SHAKE choice dominates the SCA engineering calculus** — SHA-256's mixed Boolean-arithmetic structure makes masking 3–5× more expensive than Keccak's pure-Boolean design, meaning that SLH-DSA-SHAKE-128f with Fluhrer's PRF-tree architecture (1.7× overhead) provides dramatically better SCA protection than any practical SHA-256 masking scheme on Cortex-M33.

The recommended priority order: (1) mandatory random OptRand via hardware TRNG (zero cost, immediate), (2) signing rate limiter and 2^16 key rotation (low cost, immediate), (3) WOTS+/FORS shuffling (negligible cost, immediate), (4) evaluate SHAKE migration feasibility against on-chain verification constraints (architectural decision), (5) if staying on SHA-2, route hashing through HASH peripheral for performance and implement the best feasible software masking of PRF calls, (6) redundant signature computation for fault protection, (7) board-level EM countermeasures for production hardware.