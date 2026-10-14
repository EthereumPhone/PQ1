"""Expected OPTIGA metadata: the seed of the golden manifest.

Two references per object:
  * FACTORY: Infineon's shipped metadata (factory_metadata.json, extracted
    from Infineon's trust_m3_json.txt dump of a standard V3).
  * FIRMWARE: the security tags this repo's firmware writes, transcribed from
    the `build_metadata_*` builders in secure/src/optiga/apdu.rs. Only the tags
    the firmware writes are listed (the chip adds LcsO/size tags itself).

Comparison is tag-wise over the security tags (LcsO, Change, Read, Execute,
MetadataUpdate, DataType, ResetType, Algorithm, KeyUsage); sizes and version
are ignored. An object matching neither reference is reported as UNKNOWN.

When the code changes a builder, change it here too. The unit tests pin a few
of these against the builder bytes quoted in the docs.
"""

from __future__ import annotations

import json
from pathlib import Path

FACTORY_JSON = Path(__file__).resolve().with_name("factory_metadata.json")

# Hex of each tag's VALUE (no tag/length bytes).
_PROTECTED_PRE116 = {0xD0: "23f1d0fe20e140", 0xD1: "23f1d0", 0xD3: "ff"}
_PROTECTED_POST116 = {0xD0: "23f1d0fe20e140", 0xD1: "23f1d0fd20e140", 0xD3: "ff"}
_DURESS_PRE116 = {0xD0: "23f1d8fe20e140", 0xD1: "23f1d8", 0xD3: "ff"}
_DURESS_POST116 = {0xD0: "23f1d8fe20e140", 0xD1: "23f1d8fd20e140", 0xD3: "ff"}

FIRMWARE_PROFILES: dict[int, dict[str, dict[int, str]]] = {
    0xE140: {
        "pbs (pair_for_first_boot)": {0xD0: "e1fc07fe20e140", 0xD1: "e1fc07", 0xD3: "00", 0xE8: "22"},
    },
    0xF1D0: {
        "authref dev (no hw counter)": {0xD0: "00", 0xD1: "ff", 0xD3: "00", 0xE8: "31"},
        "authref hw-counter, Change=ALW": {0xD0: "00", 0xD1: "ff", 0xD3: "40e120", 0xE8: "31"},
        "authref hw-counter, Change=Auto(F1D0) [S-1 candidate]": {
            0xD0: "23f1d0",
            0xD1: "ff",
            0xD3: "40e120",
            0xE8: "31",
        },
    },
    0xE120: {
        "pin counter (hw-counter)": {0xD0: "23f1d0", 0xD1: "00", 0xD3: "00"},
    },
    0xE121: {
        "duress counter": {0xD0: "23f1d8", 0xD1: "00", 0xD3: "00"},
    },
    0xF1D8: {
        "duress authref (LUC E121)": {0xD0: "00", 0xD1: "ff", 0xD3: "40e121", 0xE8: "31"},
    },
    0xF1E1: {
        "provisioning sentinel (counter)": {0xD0: "20e140", 0xD1: "00", 0xD3: "ff"},
        "relaxed (wipe in progress)": {0xD0: "00", 0xD1: "00", 0xD3: "ff"},
    },
    0xE0E8: {"TA junk (fenced S-2 candidate)": {0xD0: "ff", 0xD1: "ff", 0xD3: "ff"}},
    0xE0E9: {"TA junk (fenced S-2 candidate)": {0xD0: "ff", 0xD1: "ff", 0xD3: "ff"}},
    0xE0EF: {"TA junk (fenced S-2 candidate)": {0xD0: "ff", 0xD1: "ff", 0xD3: "ff"}},
}
for _oid in (0xF1D1, 0xF1D2, 0xF1D3, 0xF1D4):
    FIRMWARE_PROFILES[_oid] = {
        "secret, pre-#116 weak Read=Auto(F1D0)": dict(_PROTECTED_PRE116),
        "secret, post-#116 Read=Auto(F1D0)&&Conf(E140)": dict(_PROTECTED_POST116),
        "relaxed (wipe in progress)": {0xD0: "00", 0xD1: "00", 0xD3: "ff"},
    }
for _oid in (0xF1D6, 0xF1D9, 0xF1DA, 0xF1DB):
    FIRMWARE_PROFILES[_oid] = {
        "duress secret, pre-#116": dict(_DURESS_PRE116),
        "duress secret, post-#116": dict(_DURESS_POST116),
    }

# Objects that hold wallet secrets or gate them. Used to rank findings.
WALLET_OIDS = {
    0xE140: "PBS (shielded-connection root)",
    0xF1D0: "PIN AuthRef",
    0xF1D1: "entropy half_O",
    0xF1D2: "master secret",
    0xF1D3: "VK",
    0xF1D4: "bootstrap VK",
    0xE120: "PIN attempt counter (LUC)",
    0xF1E1: "provisioning sentinel",
    0xF1D8: "duress AuthRef",
    0xF1D9: "duress half_O",
    0xF1DA: "duress master secret",
    0xF1DB: "duress VK",
    0xF1D6: "duress bootstrap VK",
}
# The objects whose READ protection #116 is about.
SECRET_READ_OIDS = (0xF1D1, 0xF1D2, 0xF1D3, 0xF1D4, 0xF1D6, 0xF1D9, 0xF1DA, 0xF1DB)

TRUST_ANCHOR_POOL = (0xE0E8, 0xE0E9, 0xE0EF)
CERT_OIDS = (0xE0E0, 0xE0E1, 0xE0E2, 0xE0E3)

# First 8 bytes of known PBS values, as `load_pbs` logs them at boot.
KNOWN_PBS_PREFIXES = {
    "8ca52e4bc284d822": "dev-testkey (otp-hardcoded-master-key)",
    "0c7d81b2d807a5ea": "bench board #1 DHUK root",
}


def load_factory() -> dict[int, str]:
    data = json.loads(FACTORY_JSON.read_text())
    return {int(k, 16): v for k, v in data["metadata"].items()}
