#!/usr/bin/env python3
"""Fail on drift in the manually reviewed EasyCrypt/Rust correspondence.

Hashes pin the inputs to that review; they do not establish refinement. Model
proofs and the real-helper host test supply separate, explicitly scoped evidence.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.joinpath('../../../../..').resolve()
PORT = 'contracts/verification/easycrypt/c10-port/'
SOURCES = (
    'sphincs-c10/src/wots.rs', 'sphincs-c10/src/hash.rs', 'sphincs-c10/src/lib.rs',
    'sphincs-c10/src/fors.rs', 'sphincs-c10/src/address.rs', 'sphincs-c10/src/params.rs',
    'sphincs-c10/tests/easycrypt_transcript.rs',
    PORT + 'tools/check_source_binding.py',
    'contracts/verification/scripts/run_easycrypt_split.py',
    PORT + 'base-c10-split/WOTS_TW_ES.ec',
    PORT + 'base-c10-split/RadixEncoding.ec',
    *(PORT + 'cdrafts-split/' + f + '.ec' for f in (
        'C10Counter', 'C10Bytes', 'C10BoundedGrind', 'C10DeployedInstance', 'WOTS_C_Real',
        'C10Encoding', 'C10DigitUniform', 'C10BoundedSigning', 'BoundedIID', 'C10BoundedIID',
        'C10BoundedGame', 'C10BoundedReduction', 'C10BoundedMA',
        'C10BoundedHypertree', 'C10BoundedLeaf',
        'FORS_C10', 'C10HypertreeCoverage', 'SharedROBounded', 'C10Randomizer',
        'C10HashDomains', 'C10SharedSearch', 'C10SearchBounds', 'C10HypertreeCharged',
        'XmssmtCC_All', 'C10WOTSCorrect', 'C10HypertreeCorrect', 'C10CubeCorrect',
        'C10CubeConstruction', 'C10ReductionChoose', 'C10ReductionForge',
        'C10AcceptedReduction', 'C10HypertreeAccepted', 'C10StatefulSearch',
        'C10RawOracle', 'C10RawGrind', 'FORSC10Digest')),
)


def check(root=ROOT):
    manifest = json.loads((root / PORT / 'cert-source-binding.json').read_text())
    if manifest.get('schema') != 1 or set(manifest['sources']) != set(SOURCES):
        raise ValueError('unexpected source-binding schema or source set')
    for name in SOURCES:
        got = hashlib.sha256((root / name).read_bytes()).hexdigest()
        if got != manifest['sources'][name]:
            raise ValueError(f'source binding changed: {name}')
    print(f'OK EasyCrypt manual source binding: {len(SOURCES)} inputs (not extraction)')


if __name__ == '__main__':
    try:
        check()
    except (OSError, ValueError, KeyError) as error:
        sys.exit(f'FAIL: {error}')
