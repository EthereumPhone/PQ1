"""Typed functional tree mutations consumed by the unchanged endpoint proofs.

A definition must typecheck before its first intended proof consumer rejects it.
Rejection is proof sensitivity, not a theorem negating the changed definition.
"""
import re
from c10_representation import source

MODULES = ('C10FunctionalTreeValue', 'C10FunctionalMerkle', 'C10FunctionalForsRecovery')
OPERATORS = ('fors_secret_value', 'fors_leaf_value', 'tree_pair_value',
             'tree_path_step', 'tree_path_value', 'fors_recover_value', 'merkle_recover_value')

# name, operator, Lean before/after, EasyCrypt before/after, first Lean/EC consumer.
TREE_CHANGES = [('secret-index', 'fors_secret_value', 'ht tree leaf)', 'ht tree (leaf+1))', 'ht tree leaf)',
  'ht tree (leaf+1))', 'fors_secret_pure_value', 'functional_fors_private'),
 ('leaf-kind', 'fors_leaf_value', '0 ht 3 tree', '0 ht 2 tree', '0 ht 3 tree', '0 ht 2 tree',
  'fors_leaf_pure_value', 'functional_fors_leaf'),
 ('pair-order', 'tree_pair_value', '(pad_node left) (pad_node right)', '(pad_node right) (pad_node left)',
  '(pad_node left) (pad_node right)', '(pad_node right) (pad_node left)', 'pair_pure_value',
  'functional_tree_step'),
 ('parent', 'tree_path_step', '/ 2))', '/ 4))', '%/ 2))', '%/ 4))', 'path_step_value',
  'functional_tree_step'),
 ('height', 'tree_path_step', 'height + 1', 'height + 2', 'height + 1', 'height + 2', 'path_step_value',
  'functional_tree_step'),
 ('parity', 'tree_path_step', '% 2) = 0 then current', '% 3) = 0 then current', '%% 2) = 0 then current',
  '%% 3) = 0 then current', 'path_step_value', 'functional_tree_step'),
 ('sibling', 'tree_path_step', 'else (List.getD auth height', 'else (List.getD auth (height+1)',
  'else (nth (nseq 16 0) auth height', 'else (nth (nseq 16 0) auth (height+1)', 'path_step_value',
  'functional_tree_step'),
 ('path-order', 'tree_path_value', 'List.reverse', 'id', 'rev ', 'idfun ', 'path_succ',
  'functional_path_fold'),
 ('fors-kind', 'fors_recover_value', 'seed 0 ht 3 tree', 'seed 0 ht 2 tree', 'seed 0 ht 3 tree',
  'seed 0 ht 2 tree', 'extracted_fors_recover_value', 'functional_fors_recovery_value'),
 ('fors-keypair', 'fors_recover_value', 'seed 0 ht 3 tree', 'seed 0 ht 3 0', 'seed 0 ht 3 tree',
  'seed 0 ht 3 0', 'extracted_fors_recover_value', 'functional_fors_recovery_value'),
 ('fors-steps', 'fors_recover_value', 'auth 11)', 'auth 10)', 'auth 11)', 'auth 10)',
  'extracted_fors_recover_value', 'functional_fors_recovery_value'),
 ('merkle-kind', 'merkle_recover_value', 'tree 2 0', 'tree 3 0', 'tree 2 0', 'tree 3 0',
  'extracted_merkle_recover_value', 'functional_merkle_recovery_value'),
 ('merkle-keypair', 'merkle_recover_value', 'tree 2 0', 'tree 2 1', 'tree 2 0', 'tree 2 1',
  'extracted_merkle_recover_value', 'functional_merkle_recovery_value'),
 ('merkle-steps', 'merkle_recover_value', 'auth 9)', 'auth 8)', 'auth 9)', 'auth 8)',
  'extracted_merkle_recover_value', 'functional_merkle_recovery_value')]

def functional_definitions(lean):
    text = source(lean)
    prefix = 'def ' if lean else 'op '
    result = []
    for name in OPERATORS:
        match = re.search(r'(?ms)^' + prefix + name + r'\b.*?(?=\n\n|\Z)', text)
        if not match:
            raise ValueError('functional tree operator missing: ' + name)
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



# Exact ordinary proof diagnostics are calibrated by isolated compiler checks.
TREE_REASONS = {row[0]: '[by]: cannot close goals' for row in TREE_CHANGES}
TREE_REASONS['path-order'] = 'nothing to rewrite'


def functional_tree_outputs(port):
    from c10_representation_controls import changed
    from c10_functional_tree_fixtures import fixture_source
    original = functional_definitions(False)
    benign = changed(original, 'tree_path_step', 'height + 1', 'height + (2-1)', False)
    result = {port / 'scratch/c10_tree_value_positive.ec': native_fixture(port, original),
              port / 'scratch/c10_tree_value_preserving.ec': native_fixture(port, benign),
              port / 'scratch/c10_tree_value_fixtures.ec': fixture_source(False)}
    for name, operator, _, _, before, after, _, _ in TREE_CHANGES:
        altered = changed(original, operator, before, after, False)
        stem = 'c10_tree_value_' + name.replace('-', '_')
        result[port / 'scratch' / (stem + '_typed.ec')] = 'require import AllCore List IntDiv C10Representation.\n' + altered
        result[port / 'scratch' / (stem + '_reject.ec')] = native_fixture(port, altered)
    return {path: text.rstrip() + '\n' for path, text in result.items()}


def functional_tree_rows():
    rows = ['scratch/c10_tree_value_positive.ec\tMUST-PASS\t-',
            'scratch/c10_tree_value_preserving.ec\tMUST-PASS\t-',
            'scratch/c10_tree_value_fixtures.ec\tMUST-PASS\t-']
    for name, *_ in TREE_CHANGES:
        stem = 'scratch/c10_tree_value_' + name.replace('-', '_')
        rows += [stem + '_typed.ec\tMUST-PASS\t-',
                 stem + '_reject.ec\tMUST-FAIL\t' + TREE_REASONS[name]]
    return rows
