"""Fail-closed guard for one frozen experimental SHA extraction.

This is an exact-snapshot profile, not a generic Iterator/Zip model. The
structural census binds every mapped function reference, Zip type use and
IterMut dictionary use in transparent bodies. The final whole-input digest
also binds Charon's deduplicated type IDs, foreign signatures and declarations.
No production compiler invocation is authorized by this research guard alone.
"""
from pathlib import Path
import hashlib
import json
import sys

EXPECTED_LLBC_SHA256 = '7c3947d1498ceb668e535e448878ed7930708163f373baf63f9990aff25c2601'
MAX_INPUT_BYTES = 8 * 1024 * 1024
MANIFEST_SHA256 = '1affc223ff0bce55b6dcae8d13b61856cd57a10c409f549d3cbf3f5b514fc344'

class ProfileRejected(ValueError):
    pass

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProfileRejected('duplicate JSON key: ' + key)
        result[key] = value
    return result

def load_strict(data):
    if len(data) > MAX_INPUT_BYTES:
        raise ProfileRejected('input size exceeds profile bound')
    return json.loads(data, object_pairs_hook=unique_object)

def walk(value, path):
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, path + '/' + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk(item, path + '/' + str(index))

def census(document):
    tr = document['translated']
    names = tr['item_names']
    if len({canonical(x['key']) for x in names}) != len(names):
        raise ProfileRejected('duplicate declaration name identity')
    bindings = []
    selected = {'type_decls': {7, 8, 9}, 'fun_decls': {24, 26}, 'trait_impls': {9}}
    for section, ids in selected.items():
        rows = [x for x in tr[section] if x is not None]
        if len({x['def_id'] for x in rows}) != len(rows):
            raise ProfileRejected('duplicate declaration ID in ' + section)
        for ident in sorted(ids):
            row = next((x for x in rows if x['def_id'] == ident), None)
            if row is None:
                raise ProfileRejected('missing mapped declaration')
            bindings.append({'section': section, 'id': ident,
                             'declaration_sha256': sha(canonical(row))})
    sites = []
    transparent = []
    for declaration in tr['fun_decls']:
        if declaration is None or not isinstance(declaration['body'], dict):
            continue
        ident = declaration['def_id']
        transparent.append(ident)
        for path, node in walk(declaration['body'], 'function/' + str(ident)):
            if not isinstance(node, dict):
                continue
            kind = None
            if set(node) == {'Fun'} and node['Fun'] in (24, 26):
                kind = 'mapped_function_reference'
            elif 'Adt' in node and isinstance(node['Adt'], dict) and node['Adt'].get('id') == 7:
                kind = 'mapped_zip_type'
            elif 'TraitImpl' in node and isinstance(node['TraitImpl'], dict) and node['TraitImpl'].get('id') == 9:
                kind = 'mapped_mutable_iterator_dictionary'
            elif 'Regular' in node and isinstance(node['Regular'], dict) and node['Regular'].get('kind') in ({'Fun': 24}, {'Fun': 26}):
                kind = 'mapped_call_instantiation'
            if kind:
                sites.append({'kind': kind, 'path': path, 'node_sha256': sha(canonical(node))})
    return {'bindings': bindings, 'transparent_functions': transparent, 'sites': sorted(sites, key=lambda x: (x['path'], x['kind']))}

def check(data, manifest_data):
    # The expected census is immutable configuration, never learned from the
    # candidate, and never accepted as a caller-selected replacement.
    if sha(manifest_data) != MANIFEST_SHA256:
        raise ProfileRejected('profile manifest identity changed')
    expected = load_strict(manifest_data)
    document = load_strict(data)
    if set(document) != {'charon_version', 'translated', 'has_errors'}:
        raise ProfileRejected('unsupported root schema')
    if document['has_errors'] is not False or document['charon_version'] != '0.1.299':
        raise ProfileRejected('wrong Charon schema or extraction errors')
    actual = census(document)
    if actual != expected['census']:
        raise ProfileRejected('mapped declarations or structural use census changed')
    # Charon serializes types with shared IDs. This digest binds the complete
    # graph, including definitions outside the mapped call nodes. No ID-only
    # acceptance, partial traversal, or generic type-resolution claim is made.
    if sha(data) != EXPECTED_LLBC_SHA256:
        raise ProfileRejected('complete LLBC identity changed')
    return {'accepted': True, 'profile': expected['profile'],
            'llbc_sha256': sha(data), 'mapped_sites': len(actual['sites']),
            'transparent_functions': len(actual['transparent_functions'])}

def main():
    if len(sys.argv) != 2:
        raise ProfileRejected('usage: profile_guard.py INPUT.llbc')
    with Path(sys.argv[1]).open('rb') as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    with Path(__file__).with_name('profile-manifest.json').open('rb') as stream:
        manifest = stream.read(MAX_INPUT_BYTES + 1)
    print(json.dumps(check(data, manifest)))

if __name__ == '__main__':
    try:
        main()
    except (ProfileRejected, KeyError, TypeError, StopIteration, json.JSONDecodeError, RecursionError, OSError) as error:
        print(json.dumps({'accepted': False, 'reason': str(error)}), file=sys.stderr)
        sys.exit(1)
