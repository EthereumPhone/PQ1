//! Every data object the OPTIGA Trust M V3 SRM documents (v3.70, Tables
//! 46–48: `docs/SLS32AIA010MKUSON10XTMA2/OPTIGA_Trust_M_Solution_Reference_Manual.md`
//! lines ~5010-5250), tagged with how the probe may print its DATA part.
//!
//! The class decides logging only, never whether a request is sent:
//! - `Public`: chip identity, lifecycle, counters, certificates. Hex is logged.
//! - `Secret`: anything that may hold key material or wallet shares. Only the
//!   length and an 8-byte SHA-256 fingerprint ever leave the device.
//! - `Key` / `Session`: the SRM forbids GetDataObject on their data part
//!   "even if the metadata states the access rights differently". The probe
//!   sends one 1-byte read to check that, and fingerprints anything returned.
//! - `MetaOnly`: reading the data would disturb the probe itself (F1C2 is the
//!   last-error code the probe relies on), so only its metadata is read.

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Public,
    Secret,
    Key,
    Session,
    MetaOnly,
}

#[derive(Clone, Copy)]
pub(crate) struct Obj {
    pub oid: u16,
    pub class: Class,
    pub name: &'static str,
}

const fn o(oid: u16, class: Class, name: &'static str) -> Obj {
    Obj { oid, class, name }
}

use Class::{Key, MetaOnly, Public, Secret, Session};

pub(crate) const INVENTORY: &[Obj] = &[
    // Global data structures (Table 46).
    o(0xE0C0, Public, "LcsG"),
    o(0xE0C1, Public, "SecurityStatusG"),
    o(0xE0C2, Public, "CoprocessorUID"),
    o(0xE0C3, Public, "SleepModeActivationDelay"),
    o(0xE0C4, Public, "CurrentLimitation"),
    o(0xE0C5, Public, "SecurityEventCounter"),
    o(0xE0C6, Public, "MaxComBufferSize"),
    o(0xE0C9, Public, "SecurityMonitorConfig"),
    o(0xE0E0, Public, "DeviceCert1"),
    o(0xE0E1, Public, "Cert2"),
    o(0xE0E2, Public, "Cert3"),
    o(0xE0E3, Public, "Cert4"),
    o(0xE0E8, Public, "TrustAnchor1"),
    o(0xE0E9, Public, "TrustAnchor2"),
    o(0xE0EF, Public, "ProtectedUpdateTrustAnchor"),
    o(0xE120, Public, "MonotonicCounter1"),
    o(0xE121, Public, "MonotonicCounter2"),
    o(0xE122, Public, "MonotonicCounter3"),
    o(0xE123, Public, "MonotonicCounter4"),
    o(0xE140, Secret, "PlatformBindingSecret"),
    // Key objects (Table 47).
    o(0xE0F0, Key, "DeviceEccKey1"),
    o(0xE0F1, Key, "EccKey2"),
    o(0xE0F2, Key, "EccKey3"),
    o(0xE0F3, Key, "EccKey4"),
    o(0xE0FC, Key, "RsaKey1"),
    o(0xE0FD, Key, "RsaKey2"),
    o(0xE100, Session, "SessionContext1"),
    o(0xE101, Session, "SessionContext2"),
    o(0xE102, Session, "SessionContext3"),
    o(0xE103, Session, "SessionContext4"),
    o(0xE200, Key, "DeviceSymmetricKey1"),
    // Application data structures (Table 48).
    o(0xF1C0, Public, "LcsA"),
    o(0xF1C1, Public, "SecurityStatusA"),
    o(0xF1C2, MetaOnly, "LastErrorCode"),
    o(0xF1D0, Secret, "Arb3_D0_AuthRef"),
    o(0xF1D1, Secret, "Arb3_D1_EntropyHalfO"),
    o(0xF1D2, Secret, "Arb3_D2_MasterSecret"),
    o(0xF1D3, Secret, "Arb3_D3_VK"),
    o(0xF1D4, Secret, "Arb3_D4_BootstrapVK"),
    o(0xF1D5, Secret, "Arb3_D5"),
    o(0xF1D6, Secret, "Arb3_D6"),
    o(0xF1D7, Secret, "Arb3_D7"),
    o(0xF1D8, Secret, "Arb3_D8_DuressAuthRef"),
    o(0xF1D9, Secret, "Arb3_D9"),
    o(0xF1DA, Secret, "Arb3_DA"),
    o(0xF1DB, Secret, "Arb3_DB"),
    o(0xF1E0, Secret, "Arb2_E0"),
    o(0xF1E1, Public, "Arb2_E1_ProvisionSentinel"),
];

/// Number of inventory entries; sizes the R3/R9 snapshot arrays.
pub(crate) const N: usize = INVENTORY.len();

pub(crate) fn contains(oid: u16) -> bool {
    INVENTORY.iter().any(|e| e.oid == oid)
}
