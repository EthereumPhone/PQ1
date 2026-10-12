No battery-free consumer wallet ships active tamper sensing, and I found no published method for an MCU to detect a tap on its own display bus. The realistic gains on a new board are keeping the seed off the display and button lines, burying those nets under potting, and (as a research bet) a fingerprinted mesh read at boot.

Evidence grades: **T** = teardown, audit or source code I read; **V** = vendor page I read, no independent confirmation; **U** = UNCONFIRMED (search excerpt or press only). Bracketed numbers refer to the source list at the end. No repository file was modified.

## 1. Shipped wallets

| Device | Enclosure | Active sensing | Battery | Response | Display / input path | Vendor tells user | Grade |
|---|---|---|---|---|---|---|---|
| Ledger Nano X | Opened and re-closed around an implant [1] | None | Yes | None | SE drives OLED over SPI; implant read it there and sent seed words over LTE [1] | Buy direct; compare internals to reference photos; "looking into further hardening for future products" (Ledger, quoted in [1]) | T [1][2] |
| Ledger Stax / Flex | Not stated | None claimed | Yes | None | "Driven directly by the Secure Element" [3] | Genuine check | V; no teardown found |
| Trezor Safe 3 / 5 | "Tamper evident casing" [4] | None | No | None | No claim | "Do not attempt to force open" [4] | V; Donjon showed some Safe 3 supply-chain checks bypassable (reported 2024-11-12) [5] |
| Trezor Safe 7 | Aluminium unibody, glass [4] | None claimed | Yes (LiFePO4) [4] | None | No claim | Same | V |
| Coldcard Mk4 / Q | Clear case; epoxy "no longer needed" for Mk4 [6] | None | Mk4 no; Q optional 3xAAA [6] | None | SE-controlled genuine LED; no display claim | Check bag number in three places, VOID seal, look through case [6] | V |
| BitBox02 / Nova | Case glued to PCB with epoxy [7] | None | No | None | None | "Check it for signs of tampering" before each use; targeted tampering out of scope [7] | V |
| Keystone 3 Pro | Not stated | Tamper GPIO plus MCU sensor block [8] | Yes; erase runs from a "button cell" [8] | Erases SE pages and latches a tamper mark in the ATECC608B [8] | Not covered in code read | — | T (firmware master, read 2026-10-12) [8]; sensor geometry unverified |
| NGRAVE ZERO | Not stated | "Detect any intrusions" [9], mechanism undisclosed | Yes (U) | "Wipe itself entirely" [9] | Unknown | Attestation at power-on | V; no teardown found |
| Passport Prime | Openable; "not tamper-proof after disassembly" | Two normally-open tamper switches [10] | Yes (Li-ion) | Hardware clears SECURAM on tamper or power loss [10] | Debug and SE test pads sit under the display; removing the display trips tamper [10] | Do not open | T (Keylabs audit, 2025) [10] |
| GridPlus Lattice1 | 3D laser-structured mesh [11] | Continuous waveform on mesh | Yes; "around 5 years when unplugged" [11] | Erase and permanent brick | Screen drawn by secure MCU; whether panel and flex are inside the mesh is not stated [11] | — | V |
| Cypherock X1 | Ultrasonic weld (U) | None | No (U) | None | OLED and joystick on STM32L4 [14] | — | V/U |
| Jade / Jade Plus | Plus has a metal body [13] | None | Plus yes | None | No SE; "virtual secure element" [13] | Genuine check | V |
| OneKey Pro | Aluminium, glass | None physical; "auto-wipe" example is firmware modification [12] | Yes | Wipe | No claim | Check box seal | V; OneKey Mini MCU-to-SE bus was interposed with an FPGA in 2023 (U) [12] |
| Tangem | Laminated card (U) | None | No | None | No display or buttons | — | U |

- Every shipped wallet with an active tamper response carries a battery (Keystone, Passport Prime, Lattice1). Battery-free devices use only passive measures: epoxy, clear case, welded shell.
- "The secure chip drives the screen" protects against a compromised MCU, not a tap. The Nano X implant is the counter-example [1].
- A wipe before a seed exists achieves nothing unless the event is latched and shown. Keystone is the one confirmed latch; its UI tasks reference the flag (grep hits only, UI code not read).
- User guidance is visual inspection plus a genuine check. A passive tap changes nothing that check measures; in 2020 it did not flag a reflashed MCU [2].

## 2. Detection with no power present

| Approach | Measured | Front end and MCU pins | Stability | Attack results | Shipped |
|---|---|---|---|---|---|
| Coating PUF (Tuyls, CHES 2006) | Capacitance of a doped die coating | On-die sensors, custom silicon | Not re-read (PDF 403) | Not re-read | Not for boards (U) |
| B-TREPID / TCHES 2019 cover [15] | 16x16 Tx/Rx electrodes, 128 differential nodes, about 50 pF mutual, +/-132 fF variation | STM32F303 behind analog muxes: few MCU pins (mux selects, excitation, one ADC), but a discrete chain of differential amp, JFET transimpedance amp and filters; noise 1.7 fF. Later custom 350 nm sensor IC, 460 aF (U) | -20 to +60 C after compensation, 3 to 5 erratic nodes; foils aged at 90 C / 85 % RH shifted little, measurement circuit not aged | 115 covers; 300 um drill detected; drill plus repair still moved 8 to 18 nodes, limits acknowledged | No: "prototypes" (2018) [16]; "technology demonstrators" and IP offered [17] |
| Theory follow-ups | — | — | — | At least 459 cells at 3 bits for 128-bit security [18]; 100-bit from 306-bit entropy (U) [19] | — |
| TDR mesh fingerprint (TCHES 2026) [21] | Reflection profile of a PCB meander | STM32G474 high-resolution timer, HDMI redriver, Schottky sampling gates; under 10 EUR; better than 200 ps | "Reasonably robust" (author blog); paper not read | Scope probe and micro-soldering detected, no false negatives; tells identical PCBs apart | No |
| NTAG 213 TT loop [20] | One wire, open or closed | None (NFC-powered) | — | Checked only at start-up, then latched permanently | Yes (labels) |
| Conductive-ink seals, resistor networks in potting | Loop resistance | One ADC pin | — | — | Patent only; none found shipped (U) |
| Anti-Tamper Radio [26] | RF response inside a metal case | Radios and antennas | — | 0.1 mm needle detected | No; needs continuous monitoring |

- "Works unpowered" means the state is held in the physical structure and read at next boot. A binary loop can be bridged before cutting or repaired before the next power-up; only analog fingerprints (capacitance, reflection profile) resist that.
- In transit there is no seed to destroy, so an enclosure PUF acts as a detector only. Its enrolled baseline must sit in a secure element or OTP, since flash is rewritable at RDP-0 (my inference from your shipping model).
- The capacitive cover costs few MCU pins; its real cost is the analog chain and a flex cover bonded round the board. The 2025 analysis asks for at least 459 cells, against 128 differential nodes in 2019 (my comparison).
- The TDR mesh is the only scheme I found built from stock parts, but it relies on a high-resolution timer that the STM32U585 datasheet does not list [29].

## 3. Sensing a tap from the MCU

| Work | Senses | Hardware | Resolution | MCU-only? |
|---|---|---|---|---|
| PDNPulse (TIFS 2023) [22] | Power-network impedance | Keysight E5063A VNA plus custom probe | 1.8 fF is a simulated limit, not a measurement | No |
| ImpedanceVerif (TCHES 2023) [23] | Power-network impedance | On-FPGA network analyzer | Not stated | No (FPGA) |
| Xu et al. (FCCM 2021) [24]; DIVOT iTDR by the same group (U) | Phase shift or reflection at bus transmitter | Xilinx ZCU104, DDR4 at 2400 MT/s | Not stated | No (FPGA) |
| Goette and Scheuermann [21] | Dedicated mesh trace | STM32G474 | Better than 200 ps | Yes, on a mesh, not a live bus |
| Petersen thesis (2018) [25] | PCB pad capacitance | LC capacitance-to-digital converter IC | Not in abstract | No (extra IC) |
| "PACTOR" | — | — | — | Not found under that name |

- I found no published result where a general-purpose MCU detects a passive tap on its own SPI or GPIO lines using timers, ADC or comparators.
- The STM32U585 has a charge-transfer touch controller (up to 22 channels, fewer on small packages) [29]. Using it on display lines is unpublished. Constraints from the alternate-function table: the pin must carry both SPI and a touch channel and be time-multiplexed; one pin per touch group goes to a sampling capacitor; PA5/PA7 carry no touch channel; PB13 (SPI2 clock) and PB5 (SPI1 data out) do, but no single SPI instance has both lines on touch pins.
- A soldered wire plus an input pin adds picofarads, but so do flex and panel tolerances and temperature, and a buffered tap adds far less. Fine probes add over 20 fF [15].
- Battery-free specific (my inference from [1] and [22]): the Nano X implant sat beside a host battery that had been shrunk and whose gauge was bypassed; PDNPulse argues a self-powered implant needs a cell usually over 6 mm across. Without a host battery, a radio implant must draw from VBUS while plugged in or carry a visible cell.

## 4. Package-level tap resistance

| Evidence | What it shows |
|---|---|
| Grand 2026 [1] | Slide labels place the tap at the OLED SPI interface on the board's back side, not at a chip package |
| Kraken 2020 [2] | Programming pins reachable; "a spring-loaded pogo-pin interface could be used" |
| Keylabs 2025 [10] | Test pads under the display were rated low impact only because tamper switches cover them |
| Immler 2019 [15] | Names inner-layer routing, BGA-only parts and buried vias as best practice, without a cost figure |
| Skorobogatov 2016 [28] | NAND desoldered to reach its bus with cheap parts |
| Dolos 2021 (U) | TPM bus sniffed by clipping onto another chip on the same SPI bus |
| Harrison et al., USENIX Security 2025 [27] | Over fifty board attacks reviewed; most are prevented by architecture, not by electrical detection |
| ST datasheet [29] | Tamper pins / active tampers: 48-pin 3 / 2; WLCSP90 8 / 7; UFBGA132 and UFBGA169 8 / 7 |

- I found no source that quantifies the tap-cost gain of BGA over QFN. The published position is qualitative.
- BGA with via-in-pad and inner routing removes solderable copper at the MCU only. The net still surfaces at the display connector, the flex, the buttons and any test pad, so those ends need covering.
- What a larger package reliably buys is pins: eight tamper pins instead of three, so buttons no longer share them.
- I found no published implant that tapped under a BGA on a consumer wallet; attackers used easier points.

## 5. Supercapacitor-powered active mesh

| Item | Figure |
|---|---|
| STM32U585 VBAT current at 3.0 V, 25 C [29] | 0.16 uA (RTC off); 0.62 uA (RTC, LSE bypass); 1.3 to 1.8 uA typical at 85 C; VBAT range 1.65 to 3.6 V |
| Tamper pins in VBAT mode [29] | All eight available; ST names "an external battery or an external supercapacitor" as the VBAT source, with no hold time |
| Coin supercap leakage at 5.5 V rated, after 72 h [30] | 0.1 F: 3 uA; 1 F: 8 uA; storage limit +50 C |
| Hold time, 1 F from 3.3 V to 1.65 V | 1.65 C / 8.6 uA is about 2.2 days (pessimistic, rated-voltage leakage); about 12 days if leakage were 1 uA |
| Hold time, 0.1 F | About 13 hours |
| Shipped wallets | Lattice1 battery "around 5 years" [11]; Keystone button cell [8]; Passport Li-ion [10] |
| PCI PTS A1 [31] | Tamper must cause "automatic and immediate erasure" |
| Payment industry letter, 2024-04-12 [32] | Tamper circuitry "is maintained by ensuring continuous power supply" |

- Leakage, not MCU current, sets the hold time: days, against weeks or months in transit and storage. A 5.5 V part also needs clamping to VBAT's 3.6 V limit.
- I found no shipped design or application note for a supercapacitor-only active mesh, and no hold-time figure for the DS3645 (full datasheet under NDA) or MAX32520 (U).
- The payment model stores keys in battery-backed RAM and erases on tamper. With no battery there is nothing powered to erase, and a discharged capacitor is indistinguishable from an attack unless that state bricks the unit, which is what Lattice1 does when its battery runs out [11].

## 6. Display-path protection

| Product or source | Mechanism | Stops a passive tap? |
|---|---|---|
| Ledger [3][1] | SE drives display | No, demonstrated |
| Passport Prime [10] | Display covers the pads; removing it trips tamper | Not shown for a tap on the flex with the display in place |
| Lattice1 [11] | Secure MCU inside mesh draws screen | Unknown for the flex |
| PCI PTS v6.1 [31] | A8 protects prompt integrity; B3 forbids displaying PIN digits | Display secrecy is not a payment requirement |
| Precursor [33] | User-inspectable board, optional epoxy | By eye only; "tamper resistance is a largely unsolved problem" |
| Encrypted link or secure controller for small SPI panels | — | None found |

- No shipped small-panel scheme makes a tapped bus unreadable. The working answers are physical enclosure of the whole path, or not showing the secret.
- Payment terminals never display the secret, so their rules give no template for showing a seed.
- Tangem (U) and BitBox02 (microSD, U) avoid displaying the seed in normal setup, which removes the target the Nano X implant read.

## (a) Ranked options

| # | Option | Detects or prevents | Defeated by | Unpowered? | Cost class | Competitor |
|---|---|---|---|---|---|---|
| 1 | Seed backup and restore that never cross the display or button lines (SE-encrypted card or microSD) | Removes the seed from the tap | Tap on the new path if unencrypted; PIN and addresses still exposed; changes the recovery experience | Yes | BOM part plus firmware | Tangem, BitBox02 (U) |
| 2 | Pot MCU, SEs, display connector, flex tail and button nets in opaque epoxy | Makes soldering a tap destructive | Patient milling; tap at the panel glass | Yes | Process | BitBox02 [7] |
| 3 | Inner-layer routing, via-in-pad, no test pads outside the potted area, BGA or WLCSP MCU (also frees eight tamper pins for a powered mesh) | Removes easy solder points | Tap at connector or flex; mesh is blind while unpowered | Yes (routing); no (mesh) | Layout, BOM part | Passport Prime (pads under display) [10] |
| 4 | Clear enclosure plus published reference photos | Lets the user see an implant or its battery | Users who do not look; implant under parts | Yes | Mechanical tooling | Coldcard [6] |
| 5 | VBUS current-sense resistor read by the ADC, compared with a per-state profile enrolled in an SE | A VBUS-powered implant | Implant with its own cell, tap upstream of the shunt, or draw below noise | No, but neither can that implant run | BOM part; unproven | None found |
| 6 | Welded shell with several conductive loops of trimmed resistance across the seam, values enrolled in an SE, read at boot | Opening the shell | Measure, bridge, then cut | Yes | Layout plus mechanical | None found battery-free |
| 7 | TDR-fingerprinted mesh over the display and button region, baseline in SE | Probing and soldering on the mesh | Unknown; one paper; needs a second MCU or timer part | Yes | Research project, about 10 EUR BOM | None |
| 8 | Capacitive enclosure PUF cover | Drilling of 300 um and cover removal | Drill plus repair partly succeeded [15] | Yes | Research project | None |

Not re-read and not relied on: wallet.fail (35C3), Donjon's own posts, Tuyls 2006. The Safe 3 attack method is press-reported only.

## (b) Re-verify yourself

1. The implant read the SE-to-OLED SPI bus and used an LTE module and eSIM, with a smaller battery fitted to make room: https://grandideastudio.com/media/ledger_hardware_implant_slides.pdf. The slides do not state the exact solder points, the implant's power source or genuine-check behaviour.
2. STM32U585 tamper-pin counts per package (Table 2; I inferred the column order) and VBAT current (Table 72): https://www.st.com/resource/en/datasheet/stm32u585ai.pdf. I read the local copy at /home/nicola/Downloads/stm32u585ai.pdf, DS13086 Rev 10.
3. Enclosure-PUF figures, especially the drill-and-repair result: https://tches.iacr.org/index.php/TCHES/article/view/7334.
4. The TDR mesh paper: I read only the abstract, artifact readme and author blog, not the temperature or attack sections: https://eprint.iacr.org/2025/1962.
5. Battery dependence of shipped tamper responses: https://github.com/KeystoneHQ/keystone3-firmware/blob/master/src/hardware_interface/anti_tamper.c, https://foundation.xyz/security/passport-prime-keylabs-audit-2025.pdf, https://docs.gridplus.io/lattice1/security-features.

## Sources

[1] Grand, slides rev. 2026-05-29: grandideastudio.com/media/ledger_hardware_implant_slides.pdf
[2] Kraken Security Labs, 2020-07-08: blog.kraken.com/post/5590/kraken-security-labs-supply-chain-attacks-against-ledger-nano-x/
[3] Ledger Academy, 2024-09-13: ledger.com/academy/topics/ledgersolutions/the-secure-touchscreen-secure-screens-for-ledgers-next-generation-devices
[4] Trezor, accessed 2026-10-12: trezor.io/learn/security-privacy/how-trezor-keeps-you-safe/trezor-hardware-built-in-security
[5] Trezor: trezor.io/vulnerability/donjon-s-trezor-safe-3-evaluation
[6] Coinkite, updated 2026-10-01: coldcard.com/docs/physical-notes/ and coldcard.com/docs/coldcard-q/
[7] BitBox threat model (read through a reader proxy; direct fetch 403): bitbox.swiss/bitbox02/threat-model/
[8] Keystone firmware: github.com/KeystoneHQ/keystone3-firmware (src/hardware_interface/anti_tamper.c, src/driver/drv_tamper.c)
[9] NGRAVE support (reader proxy): support.ngrave.io/hc/en-us/articles/4409561457041
[10] Keylabs audit and Foundation response (2025-10-03): foundation.xyz/security/passport-prime-keylabs-audit-2025.pdf, foundation.xyz/security/passport-prime-audit-response-2025.pdf
[11] GridPlus, accessed 2026-10-12: docs.gridplus.io/lattice1/security-features
[12] OneKey: onekey.so/products/onekey-pro-hardware-wallet/; Unciphered 2023-02: unciphered.com/security-firm-unciphered-hacked-into-popular-hardware-wallet-onekey/
[13] Blockstream: blockstream.com/jade/
[14] Cypherock: docs.cypherock.com/design-decisions/cypherock-x1-hardware-architecture
[15] Immler et al., TCHES 2019(1): tches.iacr.org/index.php/TCHES/article/view/7334
[16] IEEE Spectrum, 2018-05-03: spectrum.ieee.org/the-unhackable-envelope
[17] Fraunhofer EMFT: emft.fraunhofer.de/en/research-development/flexible-systems/tamper-protection.html
[18] Maringer and Hiller, TCHES 2025(2): tches.iacr.org/index.php/TCHES/article/view/12059
[19] Garb et al., TCHES 2022(3): tches.iacr.org/index.php/TCHES/article/view/9698
[20] NXP NT2H1311TT datasheet, 2017: nxp.com/docs/en/data-sheet/NT2H1311TT.pdf
[21] Goette and Scheuermann, TCHES 2026(1): eprint.iacr.org/2025/1962; artifacts.iacr.org/tches/2026/a6; jaseg.de/blog/paper-sampling-mesh-monitor/
[22] Zhu et al.: arxiv.org/abs/2204.02482
[23] Mosavirik et al.: tches.iacr.org/index.php/TCHES/article/view/9954
[24] Xu et al.: digitalcommons.uri.edu/ele_facpubs/1212/
[25] Petersen: digitalrepository.unm.edu/ece_etds/418
[26] Staat et al., 2021-12: arxiv.org/abs/2112.09014
[27] Harrison et al., 2024-10: arxiv.org/abs/2410.09993
[28] Skorobogatov, 2016-09: arxiv.org/abs/1609.04327
[29] ST DS13086 Rev 10, 2024-07
[30] Abracon ADCH-S05R5S, Rev B 2025-11-18: abracon.com/datasheets/ADCH-S05R5S.pdf
[31] PCI PTS POI v6.1, 2022-03: listings.pcisecuritystandards.org/documents/PCI_PTS_POI_SRs_v6-1_Final.pdf
[32] Payment trade bodies' letter: e-ma.org/wp-content/uploads/2024/12/Joint-industry-letter-on-EU-Battery-Regulation-2024-04-12.pdf
[33] bunnie, 2020-11-23: bunniestudios.com/blog/?p=5979

A copy of this report and the extracted source texts are in the session scratchpad: /tmp/claude-1000/-home-nicola-repos-PQSigner-OS/7844318a-f4f1-49a2-b794-31ae48f548cc/scratchpad/draft_report.txt (that directory is temporary).