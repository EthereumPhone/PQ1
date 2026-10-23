#!/usr/bin/env python3
"""Independent complete forest recovery and rejected-layer continuation fixtures.

Expected forest nodes are computed with imperative byte encodings, then checked
by both printers. The arithmetic backend is not SHA. Whole trees and accepted
WOTS chains remain covered by the existing construction and WOTS fixtures.
"""
import argparse
from pathlib import Path
from c10_representation import check_outputs
import c10_functional_tree_fixtures as paths

INDICES = (0, 1, 2047, 2048, 2**32-1, 17, 31, 511, 512, 1023, 1024, 2046, 123456)
# Pinned full positional roots, including the separate root-as-secret leaf.
EXPECTED = {'forest_zero': ((151, 122, 238, 104, 135, 153, 156, 202, 180, 205, 158, 15, 222), 127), 'forest_full': ((71, 172, 154, 24, 51, 129, 130, 164, 244, 155, 192, 9, 217), 244)}


def independent_cases():
    def toy(query):
        return bytes([sum(weight * (query[pos] if pos < len(query) else 0)
                          for pos, weight in paths.WEIGHTS) % 256] * 32)
    def address(ht, kind, tree, height, index):
        return (bytes(4) + ht.to_bytes(8, 'big') + kind.to_bytes(4, 'big') +
                tree.to_bytes(4, 'big') + bytes(4) + height.to_bytes(4, 'big') + index.to_bytes(4, 'big'))
    result = []
    for name, ht in (('forest_zero', 0), ('forest_full', 2**32-1)):
        cases, roots = [], []
        for tree, index in enumerate(INDICES[:12]):
            leaf = toy(bytes(32) + address(ht,3,tree,0,index) + bytes([3]*16) + bytes(16))[:16]
            checkpoints = [leaf[0]]
            for height in range(11):
                sibling = bytes([7*height+11]*16)
                left, right = (leaf,sibling) if index % 2 == 0 else (sibling,leaf)
                index //= 2
                leaf = toy(bytes(32) + address(ht,3,tree,height+1,index) + left + bytes(16) + right + bytes(16))[:16]
                checkpoints.append(leaf[0])
            cases.append((name+'_'+str(tree), True, ht, tree, INDICES[tree], tuple(checkpoints)))
            roots.append(leaf[0])
        roots.append(toy(bytes(32)+address(ht,3,12,0,0)+bytes([3]*16)+bytes(16))[0])
        query = bytes(32)+address(ht,4,0,0,0)+b''.join(bytes([v]*16)+bytes(16) for v in roots)
        final = toy(query)[0]
        if EXPECTED and (tuple(roots),final) != EXPECTED[name]:
            raise ValueError('independent forest values changed: '+name)
        result.append((name,ht,cases,tuple(roots),final))
    return result


def fixture_source(lean):
    cases = independent_cases()
    old = paths.CASES
    try:
        paths.CASES = tuple(case for _,_,items,_,_ in cases for case in items)
        base = paths.fixture_source(lean)
    finally:
        paths.CASES = old
    rep = (lambda n,v: f'(List.replicate {n} {v})') if lean else (lambda n,v: f'(nseq {n} {v})')
    seq = lambda xs: '['+(', ' if lean else '; ').join(map(str,xs))+']'
    auth = seq(rep(16,7*h+11) for h in range(11))
    indices = seq(INDICES)
    secrets = rep(13,rep(16,3))
    auths = rep(12,auth)
    lines = [base.replace('C10FunctionalTreeFixtures','C10FunctionalCallerFixtures')]
    if lean:
        lines[0] = lines[0].rsplit('end Extracted.C10FunctionalCallerFixtures',1)[0]
    else:
        lines += ['lemma caller_indices12 : iota_ 0 12 = '+seq(range(12))+'.',
                  'proof. by rewrite '+' '.join(f'(iotaS {i} {11-i}) 1://' for i in range(12))+' iota0 1://. qed.']
    for name,ht,items,roots,final in cases:
        args = f'toy {rep(32,0)} {ht} {indices} {secrets} {auths}'
        want = seq(rep(16,v) for v in roots)
        if lean:
            lines += [f'example : forest_recover_roots {args} = {want} := by decide',
                      f'example : forest_recover_value {args} = {rep(16,final)} := by decide']
        else:
            lines += [f'lemma {name}_roots : forest_recover_roots {args} = {want}.', 'proof.',
                      '  rewrite /forest_recover_roots /mkseq caller_indices12 /=.',
                      '  do ! (rewrite nth_nseq 1:// /=).',
                      '  rewrite '+' '.join(n+'_complete' for n,*_ in items)+'.',
                      '  by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.', 'qed.',
                      f'lemma {name}_complete : forest_recover_value {args} = {rep(16,final)}.', 'proof.',
                      f'  rewrite /forest_recover_value {name}_roots /forest_compress_value /hash_bytes_node',
                      '    /toy /multi_preimage /pad_node /address_words /u32_bytes /u64_bytes',
                      '    !tree_repeat16 !tree_repeat32 /mkseq tree_indices4 tree_indices8 /=.',
                      '  by rewrite ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56',
                      '    ?IntID.expr0 !rev_cons !rev_nil /= ?tree_repeat16 ?tree_repeat32 /=.', 'qed.']
    if lean:
        lines += ['def zeroBackend (_ : List Int) : List Int := List.replicate 32 0']
        for counter in (0,9999999,10000000,2**32-1):
            lines += [f'example : layer_recover_value zeroBackend {rep(32,0)} 4294967295 18446744073709551615 4294967295',
                      f'  {rep(16,3)} [] {counter} [] = {rep(16,0)} := by decide']
        lines += ['end Extracted.C10FunctionalCallerFixtures']
    else:
        for n in (9,43):
            lines += [f'lemma caller_indices{n} : iota_ 0 {n} = '+seq(range(n))+'.',
                      'proof. by rewrite '+' '.join(f'(iotaS {i} {n-i-1}) 1://' for i in range(n))+' iota0 1://. qed.']
        lines += ['op zero_backend (_ : int list) = nseq 32 0.',
                  'lemma caller_zero_sum : wots_sum (nseq 32 0) = 0.',
                  'proof. by rewrite /wots_sum /wots_field /word_window /byte_word /byte_word_le',
                  '  tree_repeat32 /mkseq caller_indices43 /=. qed.']
        for counter in (0,9999999,10000000,2**32-1):
            lines += [f'lemma layer_rejected_{counter} : layer_recover_value zero_backend {rep(32,0)} 4294967295 18446744073709551615 4294967295',
                      f'  {rep(16,3)} [] {counter} [] = {rep(16,0)}.', 'proof.',
                      '  rewrite /layer_recover_value /wots_recover_value /zero_backend caller_zero_sum /wots_target /=.',
                      '  by rewrite /merkle_recover_value /tree_path_value /mkseq caller_indices9 /=',
                      '    /tree_path_step /tree_pair_value /hash_bytes_node /zero_backend !tree_repeat32 !tree_repeat16 /=.', 'qed.']
    return '\n'.join(lines)+'\n'


def outputs(port):
    return {port/'scratch/c10_caller_value_fixtures.ec':fixture_source(False),
            port.parent.parent/'extracted/Extracted/C10FunctionalCallerFixtures.lean':fixture_source(True)}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    port=Path(__file__).resolve().parent.parent
    expected=outputs(port)
    if args.write:
        for path,text in expected.items():path.write_text(text)
    check_outputs(expected)
    print('OK two complete forest recoveries, all26 roots, and four rejected-layer full-counter continuations')
