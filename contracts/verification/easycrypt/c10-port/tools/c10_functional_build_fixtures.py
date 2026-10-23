#!/usr/bin/env python3
"""Independent complete-tree fold fixtures, with explicit arithmetic leaves.

These check the shared 2048/512-leaf construction and full-width tree addresses,
not SHA or the concrete FORS/WOTS leaf backends. Separate actual-caller proofs
and typed controls establish those leaf instantiations. Python builds every
node using byte encodings; the provers check each whole level algebraically.
"""
import argparse
from pathlib import Path
from c10_representation import check_outputs
from c10_functional_tree_fixtures import WEIGHTS, fixture_source as path_fixture_source

CASES = (
    ('fors_zero', 11, 0, 0, 3, 0, 235,
     ((20,166,101,78,47,240,49,114,179,244,53), (3,166,101,78,47,240,49,114,179,244,53),
      (225,181,68,173,14,15,240,129,106,127,170))),
    ('fors_full', 11, 0, 2**32-1, 3, 2**32-1, 155,
     ((20,150,21,254,223,160,225,34,99,164,229), (3,150,21,254,223,160,225,34,99,164,229),
      (225,165,244,93,190,191,160,49,26,47,90))),
    ('merkle_zero', 9, 0, 0, 2, 0, 70,
     ((20,159,242,235,12,205,14,79,144), (3,159,242,235,12,205,14,79,144),
      (225,174,81,10,203,220,197,218,5))),
    ('merkle_full', 9, 2**32-1, 2**64-1, 2, 0, 25,
     ((20,150,21,254,223,160,225,34,99), (3,150,21,254,223,160,225,34,99),
      (225,165,116,29,158,175,152,173,216))),
)


def address(layer, tree, kind, kp, height, index):
    return (layer.to_bytes(4, 'big') + tree.to_bytes(8, 'big') + kind.to_bytes(4, 'big')
            + kp.to_bytes(4, 'big') + bytes(4) + height.to_bytes(4, 'big') + index.to_bytes(4, 'big'))


def score(query):
    return sum(weight * (query[pos] if pos < len(query) else 0) for pos, weight in WEIGHTS)


def coefficients(case):
    _, total, layer, tree, kind, kp, _, _ = case
    rows = [(17, 3)]
    for height in range(1, total+1):
        a, b = rows[-1]
        constant = score(bytes(32) + address(layer, tree, kind, kp, height, 0))
        rows.append(((104*a+19) % 256, (constant+29*a+52*b) % 256))
    return rows


def independent_values():
    for case in CASES:
        name, total, layer, tree, kind, kp, root, paths = case
        levels = [[bytes([(17*i+3) % 256]*16) for i in range(2**total)]]
        for height in range(1, total+1):
            old = levels[-1]
            levels.append([bytes([score(bytes(32) + address(layer,tree,kind,kp,height,i)
                                       + old[2*i] + bytes(16) + old[2*i+1] + bytes(16)) % 256]*16)
                           for i in range(len(old)//2)])
        if levels[-1] != [bytes([root]*16)]:
            raise ValueError('independent root changed: ' + name)
        for target, expected in zip((0, 1, 2**total-1, 2**total, 2**32-1),
                                    (*paths, (0,)*total, (0,)*total)):
            actual = tuple(levels[h][(target >> h)^1][0] if ((target >> h)^1) < len(levels[h]) else 0
                           for h in range(total))
            if actual != expected:
                raise ValueError('independent authentication path changed: ' + name)
        for level, (a,b) in zip(levels, coefficients(case)):
            if level != [bytes([(a*i+b) % 256]*16) for i in range(len(level))]:
                raise ValueError('whole-level algebra disagrees with independent bytes: ' + name)


def native_source():
    independent_values()
    old = path_fixture_source(False)
    anchor = 'lemma merkle_zero_step0 :'
    if old.count(anchor) != 1:
        raise ValueError('shared fixture arithmetic boundary drift')
    lines = [old.split(anchor)[0].replace('C10FunctionalTreeValue.', 'C10FunctionalTreeValue C10FunctionalBuildValue.'),
             'op build_leaves (total : int) = mkseq (fun i => nseq 16 ((17*i+3) %% 256)) (2^total).']
    for n in (9, 11):
        lines += [f'lemma build_indices{n} : iota_ 0 {n} = [' + '; '.join(map(str,range(n))) + '].',
                  'proof. by rewrite ' + ' '.join(f'(iotaS {i} {n-i-1}) 1://' for i in range(n)) + ' iota0 1://. qed.']
    for case in CASES:
        name, total, layer, tree, kind, kp, root, paths = case
        args = f'toy (nseq 32 0) {layer} {tree} {kind} {kp} {total}'
        coeff = coefficients(case)
        for h, (a,b) in enumerate(coeff):
            width = 2**(total-h)
            lines += [f'lemma {name}_level{h} : tree_nodes_value {args} {h} (build_leaves {total}) =',
                      f'  mkseq (fun i => nseq 16 (({a}*i+{b}) %% 256)) {width}.', 'proof.']
            if h == 0:
                lines += [f'  by rewrite functional_build_zero /build_leaves tree_pow{total}.', 'qed.']
                continue
            lines += [f'  rewrite (_ : {h}={h-1}+1) 1:// functional_build_next 1:// {name}_level{h-1}.',
                      '  apply (eq_from_nth (nseq 16 0)).',
                      f'  + by rewrite functional_level_size size_mkseq /= ?tree_pow{total-h} ?IntID.expr0.',
                      f'  move=> i; rewrite functional_level_size /= ?tree_pow{total-h} ?IntID.expr0 => hi.',
                      f'  have hb : 0 <= i < 2^(max 0 ({total}-({h-1}+1))) by rewrite /= ?tree_pow{total-h} ?IntID.expr0.',
                      '  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.',
                      '  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.',
                      '  congr; smt().', 'qed.']
        lines += [f'lemma {name}_root : tree_root_value {args} (build_leaves {total}) = nseq 16 {root}.',
                  f'proof. by rewrite /tree_root_value {name}_level{total} nth_mkseq 1://. qed.']
        for target, expected in zip((0,1,2**total-1),paths):
            result = '[' + '; '.join(f'nseq 16 {v}' for v in expected) + ']'
            lines += [f'lemma {name}_auth{target} : tree_auth_values {args} (build_leaves {total}) {target} = {result}.',
                      'proof.', f'  rewrite /tree_auth_values /mkseq build_indices{total} /=.',
                      '  rewrite ' + ' '.join(f'{name}_level{h}' for h in range(total)) + '.',
                      '  rewrite ' + ' '.join(f'?tree_pow{h}' for h in range(1,total)) + ' ?IntID.expr0 /=.',
                      '  by do ! (rewrite nth_mkseq 1:// /=).', 'qed.']
        for target in (2**total,2**32-1):
            lines += [f'lemma {name}_auth{target} : tree_auth_values {args} (build_leaves {total}) {target} = nseq {total} (nseq 16 0).',
                      'proof.', f'  apply (functional_auth_outside {args} (build_leaves {total}) {target});',
                      f'    rewrite /build_leaves ?size_mkseq ?tree_pow{total}; smt().', 'qed.']
    return '\n'.join(lines)+'\n'



def lean_source():
    independent_values()
    weighted = ' + '.join(f'{weight}*(q.getD {pos} 0)' for pos,weight in WEIGHTS)
    lines = ['/- Generated complete-tree fold fixtures; arithmetic leaves, not a SHA claim. -/',
             'import Extracted.C10FunctionalBuildValues', 'import Aeneas',
             'open C10Representation Extracted.C10FunctionalBuildValues',
             'set_option maxRecDepth 8192', 'set_option maxHeartbeats 3000000',
             'namespace Extracted.C10FunctionalBuildFixtures',
             f'def toy (q : List Int) : List Int := List.replicate 32 (({weighted}) % 256)',
             'theorem toy_pair (l t k kp h i x y : Int) :\n  tree_pair_value toy (List.replicate 32 0) (address_words l t k kp 0 h i)\n    (List.replicate 16 x) (List.replicate 16 y) =\n  List.replicate 16 ((l / 16777216 % 256 + 3*(t / 72057594037927936 % 256) + 5*(t % 256) +\n    7*(k % 256) + 11*(kp % 256) + 13*(h % 256) + 17*(i / 16777216 % 256) +\n    19*(i % 256) + 23*x + 29*y) % 256) := by\n  simp [tree_pair_value, hash_bytes_node, toy, pair_preimage, pad_node, address_words,\n    u32_bytes, u64_bytes, List.range_succ, List.replicate_succ]',
             'def leaves (total : Nat) := (List.range (2^total)).map (fun (i : Nat) => List.replicate 16 ((17*(i:Int)+3)%256))',
             '''theorem affine_get (a b : Int) (n i : Nat) (hi : i < n) :
  ((List.range n).map (fun (j : Nat) => List.replicate 16 ((a*(j:Int)+b)%256))).getD i (List.replicate 16 0) =
    List.replicate 16 ((a*(i:Int)+b)%256) := by
  rw [List.getD_eq_getElem _ _ (by simpa only [List.length_map, List.length_range] using hi)]
  simp only [List.getElem_map, List.getElem_range]''']
    for case in CASES:
        name, total, layer, tree, kind, kp, root, paths = case
        args = f'toy (List.replicate 32 0) {layer} {tree} {kind} {kp} {total}'
        coeff = coefficients(case)
        for h, (a,b) in enumerate(coeff):
            width = 2**(total-h)
            lines += [f'theorem {name}_level{h} : tree_nodes_value {args} {h} (leaves {total}) =',
                      f'  (List.range {width}).map (fun (i : Nat) => List.replicate 16 (({a}*(i:Int)+{b})%256)) := by']
            if h == 0:
                lines += ['  rfl']
                continue
            a0, b0 = coeff[h-1]
            lines += [f'  rw [show {h} = {h-1}+1 from rfl, nodes_succ, {name}_level{h-1}]',
                      '  apply List.ext_getElem',
                      '  · simp only [tree_level_value, List.length_map, List.length_range]',
                      '  intro i hi hj',
                      f'  have hb : i < {width} := by simpa only [tree_level_value, List.length_map, List.length_range] using hi',
                      '  simp only [tree_level_value, List.getElem_map, List.getElem_range]',
                      f'  rw [affine_get {a0} {b0} {2*width} (2*i) (by omega),',
                      f'    affine_get {a0} {b0} {2*width} (2*i+1) (by omega), toy_pair]',
                      '  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)',
                      '  norm_num', '  simp only [hiz]', '  omega']
        a,b=coeff[-1]
        lines += [f'theorem {name}_root : tree_root_value {args} (leaves {total}) = List.replicate 16 {root} := by',
                  f'  rw [root_value, {name}_level{total}, affine_get {a} {b} 1 0 (by decide)]', '  rfl']
        for target, expected in zip((0,1,2**total-1), paths):
            result = '[' + ', '.join(f'List.replicate 16 {v}' for v in expected) + ']'
            lines += [f'theorem {name}_auth{target} : tree_auth_values {args} (leaves {total}) {target} = {result} := by',
                      '  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]',
                      '  simp only [' + ', '.join(f'{name}_level{h}' for h in range(total)) + ']',
                      '  norm_num [affine_get]']
        for target in (2**total,2**32-1):
            lines += [f'theorem {name}_auth{target} : tree_auth_values {args} (leaves {total}) {target} = List.replicate {total} (List.replicate 16 0) := by',
                      f'  exact auth_outside {args} (leaves {total}) {target} (by simp [leaves]) (by decide)']
    lines.append('end Extracted.C10FunctionalBuildFixtures')
    return '\n'.join(lines)+'\n'


def outputs(port):
    return {port/'scratch/c10_build_value_fixtures.ec': native_source(),
            port.parent.parent/'extracted/Extracted/C10FunctionalBuildFixtures.lean': lean_source()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    port = Path(__file__).resolve().parent.parent
    expected = outputs(port)
    if args.write:
        for path, text in expected.items(): path.write_text(text)
    check_outputs(expected)
    print('OK four independent complete trees and twenty paths, including full-width fields and outside targets')
