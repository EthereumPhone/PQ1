#!/usr/bin/env python3
"""Independent byte-construction examples for both functional tree printers.

The toy backend is public arithmetic, not SHA. Its weighted byte positions
observe address fields, parent/height and left/right nodes. Expected full-path
checkpoints are pinned below and independently recomputed using byte encodings.
"""
import argparse
from pathlib import Path
from c10_representation import check_outputs

WEIGHTS = ((32, 1), (36, 3), (43, 5), (47, 7), (51, 11),
           (59, 13), (60, 17), (63, 19), (64, 23), (96, 29))
CASES = (
    ('merkle_zero', False, 0, 0, 0, (3, 159, 123, 23, 243, 143, 107, 7, 227, 127)),
    ('merkle_odd', False, 0, 0, 1, (3, 111, 43, 231, 163, 95, 27, 215, 147, 79)),
    ('merkle_full', False, 2**32-1, 2**64-1, 2**32-1,
     (3, 194, 211, 78, 219, 250, 231, 76, 90, 158)),
    ('fors_zero', True, 0, 0, 0, (90, 119, 234, 23, 250, 55, 138, 215, 154, 247, 42, 151)),
    ('fors_odd', True, 0, 0, 1, (109, 120, 1, 40, 129, 88, 129, 8, 1, 56, 1, 232)),
    ('fors_outside', True, 1, 12, 2048, (227, 79, 219, 71, 83, 127, 235, 71, 203, 51, 61, 232)),
    ('fors_full', True, 2**32-1, 2**32-1, 2**32-1,
     (38, 185, 206, 189, 110, 161, 210, 235, 93, 245, 219, 151)),
)


def independent_values():
    def toy(q):
        return bytes([sum(w * (q[i] if i < len(q) else 0) for i, w in WEIGHTS) % 256] * 32)
    def address(layer, tree, kind, kp, height, index):
        return (layer.to_bytes(4, 'big') + tree.to_bytes(8, 'big') + kind.to_bytes(4, 'big')
                + kp.to_bytes(4, 'big') + bytes(4) + height.to_bytes(4, 'big') + index.to_bytes(4, 'big'))
    for name, fors, x, y, index, expected in CASES:
        layer, tree, kind, kp = (0, x, 3, y) if fors else (x, y, 2, 0)
        seed, node = bytes(32), bytes([3]*16)
        if fors:
            node = toy(seed + address(layer, tree, kind, kp, 0, index) + node + bytes(16))[:16]
        actual = [node[0]]
        for height in range(11 if fors else 9):
            sibling = bytes([7*height+11]*16)
            left, right = (node, sibling) if index % 2 == 0 else (sibling, node)
            index //= 2
            node = toy(seed + address(layer, tree, kind, kp, height+1, index)
                       + left + bytes(16) + right + bytes(16))[:16]
            actual.append(node[0])
        if tuple(actual) != expected:
            raise ValueError('independent path checkpoints changed: ' + name)


def fixture_source(lean):
    independent_values()
    rep = (lambda n, v: f'(List.replicate {n} {v})') if lean else (lambda n, v: f'(nseq {n} {v})')
    term = lambda i: f'bs.getD {i} 0' if lean else f'nth 0 bs {i}'
    weighted = ' + '.join(f'{w} * ({term(i)})' for i, w in WEIGHTS)
    if lean:
        lines = ['/- Generated independent functional tree examples. -/',
                 'import Extracted.C10Representation', 'import Aeneas',
                 'open C10Representation', 'set_option maxRecDepth 8192',
                 'set_option maxHeartbeats 2000000',
                 'namespace Extracted.C10FunctionalTreeFixtures',
                 f'def toy (bs : List Int) : List Int := List.replicate 32 (({weighted}) % 256)']
    else:
        lines = ['(* Generated independent functional tree examples. *)',
                 'require import AllCore List IntDiv Ring C10Representation C10FunctionalTreeValue.',
                 f'op toy (bs : int list) : int list = nseq 32 (({weighted}) %% 256).']
        for n in (16, 32):
            lines += [f'lemma tree_repeat{n} (x : int) : nseq {n} x = [' + '; '.join(['x']*n) + '].',
                      'proof. by rewrite ' + ' '.join(f'(nseqS {i} x) 1://' for i in reversed(range(n))) + ' nseq0. qed.']
        for n in (4, 8):
            lines += [f'lemma tree_indices{n} : iota_ 0 {n} = [' + '; '.join(map(str, range(n))) + '].',
                      'proof. by rewrite ' + ' '.join(f'(iotaS {i} {n-i-1}) 1://' for i in range(n)) + ' iota0 1://. qed.']
        for n in range(1, 12):
            lines += [f'lemma tree_pow{n} : 2^{n} = {2**n}.',
                      'proof. by rewrite ' + ' '.join(f'(IntID.exprS 2 {j}) 1://' for j in reversed(range(n))) + ' IntID.expr0. qed.']
        for n in range(16, 57, 8):
            lines += [f'lemma tree_pow{n} : 2^{n} = {2**n}.',
                      f'proof. by rewrite (_: {n}=8*{n//8}) 1:// IntID.exprM tree_pow8 '
                      + ' '.join(f'(IntID.exprS 256 {j}) 1://' for j in reversed(range(n//8))) + ' IntID.expr0. qed.']
        lines += ['''lemma tree_take_node (x : int) : take 16 (nseq 32 x) = nseq 16 x.
proof. by rewrite tree_repeat32 tree_repeat16 /=. qed.
op address_score (a : int list) = nth 0 a 0 + 3*nth 0 a 4 + 5*nth 0 a 11 +
  7*nth 0 a 15 + 11*nth 0 a 19 + 13*nth 0 a 27 + 17*nth 0 a 28 + 19*nth 0 a 31.
lemma tree_address_size l t k kp h p : size (address_words l t k kp 0 h p) = 32.
proof. by rewrite /address_words /u32_bytes /u64_bytes !size_cat !size_rev !size_mkseq. qed.
lemma tree_toy_pair a x y : size a = 32 =>
  tree_pair_value toy (nseq 32 0) a (nseq 16 x) (nseq 16 y) =
    nseq 16 ((address_score a + 23*x + 29*y) %% 256).
proof.
  move=> ha; rewrite /tree_pair_value /hash_bytes_node /toy /pair_preimage /pad_node.
  do ! (rewrite nth_cat 1:// ?size_cat ?size_nseq ?ha /max /=).
  by rewrite ?nth_nseq /= /address_score ?tree_take_node /=.
qed.
lemma tree_toy_leaf a x : size a = 32 =>
  hash_bytes_node toy (th_preimage (nseq 32 0) a (pad_node (nseq 16 x))) =
    nseq 16 ((address_score a + 23*x) %% 256).
proof.
  move=> ha; rewrite /hash_bytes_node /toy /th_preimage /pad_node.
  do ! (rewrite nth_cat 1:// ?size_cat ?size_nseq ?ha /max /=).
  by rewrite !tree_repeat16 /= /address_score tree_take_node ?tree_repeat16 /=.
qed.
lemma tree_address_score l t k kp h p :
  address_score (address_words l t k kp 0 h p) =
    l %/ 16777216 %% 256 + 3*(t %/ 72057594037927936 %% 256) + 5*(t %% 256) +
    7*(k %% 256) + 11*(kp %% 256) + 13*(h %% 256) +
    17*(p %/ 16777216 %% 256) + 19*(p %% 256).
proof.
  rewrite /address_score /address_words /u32_bytes /u64_bytes /mkseq tree_indices4 tree_indices8 /=.
  by rewrite ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
    ?IntID.expr0 !rev_cons !rev_nil /=.
qed.''']
    for name, fors, x, y, idx, states in CASES:
        height = 11 if fors else 9
        auth = '[' + (', ' if lean else '; ').join(rep(16, 7*h+11) for h in range(height)) + ']'
        value = f'fors_recover_value toy {rep(32, 0)} {x} {y} {idx} {rep(16, 3)} {auth}' if fors else (
            f'merkle_recover_value toy {rep(32, 0)} {x} {y} {rep(16, 3)} {idx} {auth}')
        if lean:
            lines.append(f'example : {value} = {rep(16, states[-1])} := by decide')
            continue
        layer, tree, kind, kp = (0, x, 3, y) if fors else (x, y, 2, 0)
        path = f'tree_path_value toy {rep(32, 0)} {layer} {tree} {kind} {kp} {rep(16, states[0])} {idx} {auth}'
        powers = ' '.join('?tree_pow'+str(n) for n in (*range(1, 12), *range(16, 57, 8)))
        for h, expected in enumerate(states):
            lines.append(f'lemma {name}_step{h} : {path} {h} = {rep(16, expected)}.')
            if h == 0:
                lines.append('proof. by rewrite functional_path_zero. qed.')
            else:
                lines += ['proof.', f'  rewrite (_: {h}={h-1}+1) 1:// functional_path_next 1:// {name}_step{h-1}.',
                          f'  rewrite /tree_path_step {powers} ?IntID.expr0 /=.',
                          '  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.', 'qed.']
        lines += [f'lemma {name}_complete : {value} = {rep(16, states[-1])}.', 'proof.']
        if fors:
            leaf = f'fors_leaf_value toy {rep(32, 0)} {x} {y} {idx} {rep(16, 3)}'
            lines += [f'  have leaf : {leaf} = {rep(16, states[0])}.',
                      '  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.',
                      f'  by rewrite /fors_recover_value leaf {name}_step{height}.']
        else:
            lines.append(f'  by rewrite /merkle_recover_value {name}_step{height}.')
        lines.append('qed.')
    if lean:
        lines.append('end Extracted.C10FunctionalTreeFixtures')
    return '\n'.join(lines)+'\n'


def outputs(port):
    return {port / 'scratch/c10_tree_value_fixtures.ec': fixture_source(False),
            port.parent.parent / 'extracted/Extracted/C10FunctionalTreeFixtures.lean': fixture_source(True)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    port = Path(__file__).resolve().parent.parent
    expected = outputs(port)
    if args.write:
        for path, text in expected.items():
            path.write_text(text)
    check_outputs(expected)
    print('OK functional tree printers: 7 independently checked complete paths, including full-width fields')


if __name__ == '__main__':
    main()
