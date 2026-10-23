"""Typed tree-construction changes consumed by the unchanged actual-caller proofs."""
import re
from c10_representation import source

MODULES = ('C10FunctionalBuildValue', 'C10FunctionalBuildStack',
           'C10FunctionalBuildBackend', 'C10FunctionalBuildOutside',
           'C10FunctionalBuildCost', 'C10FunctionalForsBuild', 'C10FunctionalMerkleBuild',
           'C10FunctionalBuildHistory', 'C10FunctionalForsBuildHistory',
           'C10FunctionalMerkleBuildHistory', 'C10FunctionalBuildContracts')
OPERATORS = ('tree_level_value', 'tree_nodes_value', 'tree_root_value', 'tree_auth_values',
             'fors_tree_leaves', 'fors_root_value', 'fors_auth_values', 'fors_sign_values',
             'merkle_tree_leaves', 'merkle_root_value', 'merkle_auth_values', 'merkle_build_value')

# name, operator, Lean before/after, EasyCrypt before/after, first Lean/EC consumer.
BUILD_CHANGES = [
    ('left-child', 'tree_level_value', 'nodes (2 * i)', 'nodes (2 * i + 1)',
     'nodes (2 * i)', 'nodes (2 * i + 1)', 'level_get', 'functional_level_nth'),
    ('right-child', 'tree_level_value', 'nodes ((2 * i) + 1)', 'nodes (2 * i)',
     'nodes ((2 * i) + 1)', 'nodes (2 * i)', 'level_get', 'functional_level_nth'),
    ('node-height', 'tree_level_value', '(Int.ofNat height)', '(Int.ofNat (height+1))',
     '0 (height) (i)', '0 (height+1) (i)', 'level_get', 'functional_level_nth'),
    ('node-index', 'tree_level_value', '(Int.ofNat i)', '(Int.ofNat (i+1))',
     '0 (height) (i)', '0 (height) (i+1)', 'level_get', 'functional_level_nth'),
    ('round-order', 'tree_nodes_value', 'List.reverse', 'id', 'rev ', 'idfun ',
     'nodes_succ', 'functional_build_fold'),
    ('root-rounds', 'tree_root_value', 'total_height total_height values', 'total_height (total_height-1) values',
     'total_height total_height values', 'total_height (total_height-1) values',
     'root_value', 'functional_root_value'),
    ('auth-parity', 'tree_auth_values', '% 2) = 0', '% 3) = 0', '%% 2) = 0', '%% 3) = 0',
     'auth_get', 'functional_auth_nth'),
    ('auth-default', 'tree_auth_values', 'List.replicate 16 0', 'List.replicate 16 1',
     'nth (nseq 16 0)', 'nth (nseq 16 1)', 'auth_get', 'functional_auth_nth'),
    ('fors-leaf-index', 'fors_tree_leaves', 'seed ht tree (Int.ofNat i)', 'seed ht tree (Int.ofNat (i+1))',
     'seed ht tree (i)', 'seed ht tree (i+1)', 'fors_node_value', 'functional_fors_build_leaf'),
    ('fors-root-kind', 'fors_root_value', 'seed 0 ht 3 tree', 'seed 0 ht 2 tree',
     'seed 0 ht 3 tree', 'seed 0 ht 2 tree', 'extracted_fors_root_value', 'functional_fors_forest_root'),
    ('fors-auth-keypair', 'fors_auth_values', 'seed 0 ht 3 tree', 'seed 0 ht 3 0',
     'seed 0 ht 3 tree', 'seed 0 ht 3 0', 'fors_path_value', 'functional_fors_catalog_path'),
    ('fors-sign-secret', 'fors_sign_values', 'fors_secret_value hash_fn secret ht tree leaf)', 'fors_secret_value hash_fn secret ht tree (leaf+1))',
     'fors_secret_value hash_fn secret ht tree leaf)', 'fors_secret_value hash_fn secret ht tree (leaf+1))',
     'extracted_fors_sign_valid_values', 'fixed_fors_raw_sign'),
    ('merkle-leaf-index', 'merkle_tree_leaves', 'tree (Int.ofNat i)', 'tree (Int.ofNat (i+1))',
     'tree (i)', 'tree (i+1)', 'merkle_node_value', 'functional_merkle_leaf_build'),
    ('merkle-root-kind', 'merkle_root_value', 'tree 2 0 9', 'tree 3 0 9',
     'tree 2 0 9', 'tree 3 0 9', 'extracted_merkle_root_value', 'functional_merkle_forest_root'),
    ('merkle-auth-keypair', 'merkle_auth_values', 'tree 2 0 9', 'tree 2 1 9',
     'tree 2 0 9', 'tree 2 1 9', 'merkle_path_value', 'functional_merkle_catalog_path'),
    ('merkle-build-target', 'merkle_build_value', 'tree index0)', 'tree (index0+1))',
     'tree index0)', 'tree (index0+1))',
     'extracted_merkle_build_valid_value', 'fixed_functional_merkle_build'),
]


def functional_definitions(lean):
    text = source(lean)
    prefix = 'def ' if lean else 'op '
    result = []
    for name in OPERATORS:
        match = re.search(r'(?ms)^' + prefix + name + r'\b.*?(?=\n\n|\Z)', text)
        if not match:
            raise ValueError('functional construction operator missing: ' + name)
        result.append(match.group())
    return '\n\n'.join(result) + '\n'


def native_fixture(port, definitions):
    imports, bodies = [], []
    for name in MODULES:
        text = (port / 'cdrafts-split' / (name + '.ec')).read_text()
        def collect(match):
            for theory in match.group(1).split():
                if theory not in MODULES and theory not in imports:
                    imports.append(theory)
            return ''
        bodies.append(re.sub(r'(?m)^require import ([^.]+)\.', collect, text))
    return 'require import ' + ' '.join(imports) + '.\n\n' + definitions + '\n' + '\n'.join(bodies)


# Calibrated against ordinary proof diagnostics, never resource failures.
BUILD_REASONS = {row[0]: '[by]: cannot close goals' for row in BUILD_CHANGES}
BUILD_REASONS['round-order'] = 'nothing to rewrite'
for _name in ('fors-root-kind', 'fors-auth-keypair', 'merkle-root-kind', 'merkle-auth-keypair'):
    BUILD_REASONS[_name] = 'the given proof-term proves:'
for _name in ('fors-sign-secret', 'merkle-build-target'):
    BUILD_REASONS[_name] = 'cannot prove goal (strict)'


def functional_build_outputs(port):
    from c10_representation_controls import changed
    from c10_functional_build_fixtures import native_source
    original = functional_definitions(False)
    benign = changed(original, 'tree_nodes_value', '(i + 1)', '(i + (2-1))', False)
    result = {port / 'scratch/c10_build_value_positive.ec': native_fixture(port, original),
              port / 'scratch/c10_build_value_preserving.ec': native_fixture(port, benign),
              port / 'scratch/c10_build_value_fixtures.ec': native_source()}
    for name, operator, _, _, before, after, _, _ in BUILD_CHANGES:
        altered = changed(original, operator, before, after, False)
        stem = 'c10_build_value_' + name.replace('-', '_')
        result[port / 'scratch' / (stem + '_typed.ec')] = 'require import AllCore List IntDiv C10Representation.\n' + altered
        result[port / 'scratch' / (stem + '_reject.ec')] = native_fixture(port, altered)
    return {path: text.rstrip() + '\n' for path, text in result.items()}


def functional_build_rows():
    rows = ['scratch/c10_build_value_positive.ec\tMUST-PASS\t-',
            'scratch/c10_build_value_preserving.ec\tMUST-PASS\t-',
            'scratch/c10_build_value_fixtures.ec\tMUST-PASS\t-']
    for name, *_ in BUILD_CHANGES:
        stem = 'scratch/c10_build_value_' + name.replace('-', '_')
        rows += [stem + '_typed.ec\tMUST-PASS\t-',
                 stem + '_reject.ec\tMUST-FAIL\t' + BUILD_REASONS[name]]
    return rows
