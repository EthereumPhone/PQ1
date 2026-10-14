"""Typed changes to paired shuffle expressions and operational oracle callers.

Positive definition checks precede unchanged-proof rejections. Rejection is
proof sensitivity, not a claim that every changed proposition is false.
"""
from c10_representation import source
from c10_caller_controls import mutate, definitions_only

# name, operator, Lean before/after, EasyCrypt before/after
SHUFFLE_CHANGES = [
    ('shuffle-forest-label-byte', 'shuffle_forest_label', '114, 115]', '114, 116]', '114; 115]', '114; 116]'),
    ('shuffle-layer-label-selection', 'shuffle_layer_label', 'layer = 0', 'layer = 1', 'layer = 0', 'layer = 1'),
    ('shuffle-layer-label-zero', 'shuffle_layer_label', '45, 48, 0]', '45, 49, 0]', '45; 48; 0]', '45; 49; 0]'),
    ('shuffle-layer-label-nonzero', 'shuffle_layer_label', '45, 49, 0]', '45, 48, 0]', '45; 49; 0]', '45; 48; 0]'),
    ('shuffle-layer-label-terminator', 'shuffle_layer_label', '45, 48, 0]', '45, 48, 1]', '45; 48; 0]', '45; 48; 1]'),
    ('shuffle-seed-tag', 'shuffle_seed_preimage', '[115,', '[114,', '[115;', '[114;'),
    ('shuffle-label', 'shuffle_seed_preimage', ' ++ label', ' ++ []', ' ++ label', ' ++ []'),
    ('shuffle-block-tag', 'shuffle_block_preimage', '[115,', '[114,', '[115;', '[114;'),
    ('shuffle-block-counter', 'shuffle_block_preimage', '(u32_bytes nonce)', '(u32_bytes (nonce % 65536))',
     '(u32_bytes nonce)', '(u32_bytes (nonce %% 65536))'),
    ('shuffle-byte-order', 'shuffle_choice', '(hi * 256) + lo', '(lo * 256) + hi',
     '(hi * 256) + lo', '(lo * 256) + hi'),
    ('shuffle-reduction', 'shuffle_choice', '/ 65536', '/ 65535', '%/ 65536', '%/ 65535'),
    ('shuffle-swap-value', 'shuffle_swap', '(List.getD order i 0)', '(List.getD order j 0)',
     '(nth 0 order i)', '(nth 0 order j)'),
    ('shuffle-initial-size', 'shuffle_order', '(List.range n)', '(List.range (n - 1))',
     '(mkseq (fun i => i) n)', '(mkseq (fun i => i) (n - 1))'),
    ('shuffle-direction', 'shuffle_order', 'List.foldr (fun i order =>', 'List.foldl (fun order i =>',
     'foldr (fun i order =>', 'foldl (fun order i =>'),
    ('shuffle-stream-index', 'shuffle_order', '(List.getD stream (2 * ((n - 1) - i)) 0)',
     '(List.getD stream ((2 * ((n - 1) - i)) + 1) 0)',
     '(nth 0 stream (2 * (max 0 ((max 0 (n - 1)) - i))))',
     '(nth 0 stream ((2 * (max 0 ((max 0 (n - 1)) - i))) + 1))'),
]

# name, module, procedure, before, after, intended theorem
SHUFFLE_CALLER_CHANGES = [
    ('derive-zero', 'PairedShuffle', 'derive', 'if (seed <> nseq 32 0)', 'if (true)', 'shuffle_derive_common'),
    ('derive-result', 'PairedShuffle', 'derive', 'result <- bits_to_bytes d', 'result <- rev (bits_to_bytes d)', 'shuffle_derive_common'),
    ('permutation-zero', 'PairedShuffle', 'permutation', 'seed <> nseq 32 0 /\\ 1 < n', '1 < n', 'shuffle_permutation_common'),
    ('permutation-short', 'PairedShuffle', 'permutation', 'seed <> nseq 32 0 /\\ 1 < n', 'seed <> nseq 32 0', 'shuffle_permutation_common'),
    ('block-count', 'PairedShuffle', 'permutation', 'while (blk < 4)', 'while (blk < 3)', 'shuffle_permutation_common'),
    ('block-order', 'PairedShuffle', 'permutation', 'shuffle_block_preimage seed blk', 'shuffle_block_preimage seed (3-blk)', 'shuffle_permutation_common'),
    ('block-stream', 'PairedShuffle', 'permutation', 'stream ++ bits_to_bytes d', 'bits_to_bytes d ++ stream', 'shuffle_permutation_common'),
    ('permutation-result', 'PairedShuffle', 'permutation', 'order <- shuffle_order n stream', 'order <- rev (shuffle_order n stream)', 'shuffle_permutation_common'),
]

SHUFFLE_REASONS = {'shuffle-seed-tag': '[by]: cannot close goals', 'shuffle-label': '[by]: cannot close goals', 'shuffle-block-tag': '[by]: cannot close goals', 'shuffle-block-counter': '[by]: cannot close goals', 'shuffle-byte-order': 'nothing to rewrite', 'shuffle-reduction': 'nothing to rewrite', 'shuffle-swap-value': 'nothing to rewrite', 'shuffle-initial-size': '[by]: cannot close goals', 'shuffle-direction': '[by]: cannot close goals', 'shuffle-stream-index': '[by]: cannot close goals', 'derive-zero': '[by]: cannot close goals', 'derive-result': 'nothing to rewrite', 'permutation-zero': '[by]: cannot close goals', 'permutation-short': '[by]: cannot close goals', 'block-count': '[by]: cannot close goals', 'block-order': 'nothing to introduce', 'block-stream': '[by]: cannot close goals', 'permutation-result': '[by]: cannot close goals'}

# First consuming theorem reached by each calibrated negative.
SHUFFLE_THEOREMS = {'shuffle-seed-tag': 'shuffle_seed_common', 'shuffle-label': 'shuffle_seed_common', 'shuffle-block-tag': 'shuffle_block_common', 'shuffle-block-counter': 'shuffle_block_common', 'shuffle-byte-order': 'shuffle_permutation_common', 'shuffle-reduction': 'shuffle_permutation_common', 'shuffle-swap-value': 'shuffle_permutation_common', 'shuffle-initial-size': 'shuffle_finish_initial', 'shuffle-direction': 'shuffle_finish_initial', 'shuffle-stream-index': 'shuffle_finish_initial', 'derive-zero': 'shuffle_derive_common', 'derive-result': 'shuffle_derive_common', 'permutation-zero': 'shuffle_permutation_common', 'permutation-short': 'shuffle_permutation_common', 'block-count': 'shuffle_permutation_common', 'block-order': 'shuffle_permutation_common', 'block-stream': 'shuffle_permutation_common', 'permutation-result': 'shuffle_permutation_common'}

for name in ('shuffle-forest-label-byte', 'shuffle-layer-label-selection', 'shuffle-layer-label-zero',
             'shuffle-layer-label-nonzero', 'shuffle-layer-label-terminator'):
    SHUFFLE_REASONS[name] = '[by]: cannot close goals'
    SHUFFLE_THEOREMS[name] = ('shuffle_forest_label_common' if name == 'shuffle-forest-label-byte'
                            else 'shuffle_layer_label_common')


def shuffle_outputs(port):
    # Import lazily: the common generator aggregates all control families.
    from c10_representation_controls import changed
    proof = (port / 'cdrafts-split/C10ShuffleBridge.ec').read_text()
    anchor = 'require import C10Representation.'
    if proof.count(anchor) != 1:
        raise ValueError('shuffle representation import drift')
    generated = source(False)
    outputs = {port / 'scratch/c10_shuffle_positive.ec': proof.replace(anchor, generated)}
    for name, func, _, _, before, after in SHUFFLE_CHANGES:
        definitions = changed(generated, func, before, after, False)
        stem = 'c10_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = definitions
        outputs[port / 'scratch' / (stem + '_reject.ec')] = proof.replace(anchor, definitions)
    for name, module, proc, before, after, _ in SHUFFLE_CALLER_CHANGES:
        changed_proof = mutate(proof, module, proc, before, after)
        stem = 'c10_shuffle_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(changed_proof).rstrip() + '\n'
        outputs[port / 'scratch' / (stem + '_reject.ec')] = changed_proof
    return outputs


def shuffle_rows():
    rows = ['scratch/c10_shuffle_positive.ec\tMUST-PASS\t-',
            'scratch/c10_shuffle_fixtures.ec\tMUST-PASS\t-']
    for prefix, changes in [('c10_', SHUFFLE_CHANGES), ('c10_shuffle_', SHUFFLE_CALLER_CHANGES)]:
        for name, *_ in changes:
            stem = 'scratch/' + prefix + name.replace('-', '_')
            rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                         stem + '_reject.ec\tMUST-FAIL\t' + SHUFFLE_REASONS[name]])
    return rows
