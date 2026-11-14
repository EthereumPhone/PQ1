"""Small shared checks for the source-bound output-serialization profile."""
import hashlib
import gzip
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = ('positive', 'little-endian', 'omitted-word', 'unreachable')
INPUT_CONTRACT_SHA256 = '9d918089ccf64480ee210eea7e0d55eaf07dcfa4055ce930385baf0a8084e0ae'
EVIDENCE_INDEX_SHA256 = 'dcdf039372ef67712b54bb75eeeeac17fbb25211696cfe0c6d0ff7dfbcf18dd7'


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique_object)


def input_contract(profile=HERE):
    path = profile / 'frozen/input-contract.json'
    require(sha(path) == INPUT_CONTRACT_SHA256, 'input contract changed')
    contract = read_json(path)
    require(contract['format'] == 1 and set(contract['case_source_sha256']) == set(CASES),
            'input contract schema/cases differ')
    for field, name in [('harness_sha256', 'harness.rs.in'),
                        ('manifest_sha256', 'Cargo.toml'), ('lock_sha256', 'Cargo.lock')]:
        require(sha(profile / 'frozen/inputs' / name) == contract[field], 'input template changed: ' + name)
    for entry in contract['dependency_archives'].values():
        require(sha(profile / entry['path']) == entry['sha256'], 'dependency archive changed')
    patch = contract['generic_array_patch']
    require(sha(profile / patch['path']) == patch['sha256'], 'dependency correction changed')
    return contract


class Evidence:
    """Read authenticated raw bytes; an edited receipt cannot repin itself."""

    def __init__(self, profile=HERE):
        self.profile = profile
        path = profile / 'frozen/evidence-index.json'
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == EVIDENCE_INDEX_SHA256, 'evidence index changed')
        self.index = json.loads(raw, object_pairs_hook=unique_object)
        self.cache = {}

    def raw(self, original):
        original = str(original)
        require(original in self.index, 'unarchived evidence: ' + original)
        if original not in self.cache:
            entry = self.index[original]
            packed = (self.profile / entry['artifact']).read_bytes()
            require(hashlib.sha256(packed).hexdigest() == entry['archive_sha256'], 'evidence archive changed')
            raw = gzip.decompress(packed)
            require(len(raw) == entry['raw_bytes'] and hashlib.sha256(raw).hexdigest() == entry['raw_sha256'],
                    'raw evidence changed')
            self.cache[original] = raw
        return self.cache[original]

    def json(self, original):
        return json.loads(self.raw(original), object_pairs_hook=unique_object)

    def authenticate_all(self):
        for original in self.index:
            self.raw(original)
        return len(self.index)
