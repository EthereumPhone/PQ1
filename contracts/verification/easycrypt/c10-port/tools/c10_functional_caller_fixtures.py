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

# Digest byte, WOTS digit sum, then the zero sentinel and all nine XMSS nodes.
# Counter bytes are checked separately: rejection can make the final root
# independent of the counter even when its encoded query changes.
LAYER_EXPECTED = {
    'layer_zero': (69, 115, (0, 90, 72, 130, 144, 170, 216, 210, 32, 250)),
    'layer_odd': (80, 73, (0, 24, 90, 32, 194, 40, 42, 48, 146, 56)),
    **{f'layer_full_{c}': (49, 116, (0, 107, 248, 127, 104, 243, 28, 77, 119, 231))
       for c in (0, 9999999, 10000000, 2**32-1)},
}


def independent_layers():
    """Byte-level reference, independent of the expression AST and printers."""
    def toy(query):
        return bytes([sum(weight * (query[pos] if pos < len(query) else 0)
                          for pos, weight in paths.WEIGHTS) % 256] * 32)
    def address(layer, tree, kind, kp, height, index):
        return (layer.to_bytes(4, 'big') + tree.to_bytes(8, 'big') +
                kind.to_bytes(4, 'big') + kp.to_bytes(4, 'big') + bytes(4) +
                height.to_bytes(4, 'big') + index.to_bytes(4, 'big'))
    cases = [('layer_zero', 0, 0, 0, 0), ('layer_odd', 1, 512, 1, 9999999)]
    cases += [(f'layer_full_{c}', 2**32-1, 2**64-1, 2**32-1, c)
              for c in (0, 9999999, 10000000, 2**32-1)]
    result = []
    for name, layer, tree, position, count in cases:
        query = (bytes(32) + address(layer, tree, 0, position, 0, 0) +
                 bytes([3]*16) + bytes(16) + bytes(28) + count.to_bytes(4, 'big'))
        digest = toy(query)
        word = int.from_bytes(digest, 'big')
        digit_sum = sum((word >> (3*i)) & 7 for i in range(43))
        if digit_sum == 205:
            raise ValueError('rejected-layer reference unexpectedly accepts: ' + name)
        node, index, checkpoints = bytes(16), position, [0]
        for height in range(9):
            sibling = bytes([7*height+11]*16)
            left, right = (node, sibling) if index % 2 == 0 else (sibling, node)
            index //= 2
            node = toy(bytes(32) + address(layer, tree, 2, 0, height+1, index) +
                       left + bytes(16) + right + bytes(16))[:16]
            checkpoints.append(node[0])
        expected = (digest[0], digit_sum, tuple(checkpoints))
        if expected != LAYER_EXPECTED[name]:
            raise ValueError('independent layer checkpoints changed: ' + name)
        result.append((name, layer, tree, position, count, tuple(query), *expected))
    return result


def layer_fixture_source(lean):
    rep = (lambda n,v: f'(List.replicate {n} {v})') if lean else (lambda n,v: f'(nseq {n} {v})')
    seq = lambda xs: '['+(', ' if lean else '; ').join(map(str,xs))+']'
    lines = []
    if not lean:
        lines += ['lemma caller_repeat28 (x : int) : nseq 28 x = '+seq(['x']*28)+'.',
                  'proof. by rewrite '+' '.join(f'(nseqS {i} x) 1://' for i in reversed(range(28)))+' nseq0. qed.']
        for n in range(0, 127, 3):
            lines += [f'lemma caller_digit_pow{n} : 2^{n} = {2**n}.',
                      'proof. by rewrite ' + ' '.join(f'(IntID.exprS 2 {j}) 1://' for j in reversed(range(max(0,n-3),n))) +
                      (' IntID.expr0. qed.' if n == 0 else f' caller_digit_pow{n-3}. qed.')]
    auth = seq(rep(16, 7*h+11) for h in range(9))
    chains = rep(43, rep(16, 5))
    for name, layer, tree, position, count, query, digest, digit_sum, states in independent_layers():
        preimage = (f'wots_preimage {rep(32,0)} (address_words {layer} {tree} 0 {position} 0 0 0) '
                    f'(pad_node {rep(16,3)}) {count}')
        path = f'tree_path_value toy {rep(32,0)} {layer} {tree} 2 0 {rep(16,0)} {position} {auth}'
        value = f'layer_recover_value toy {rep(32,0)} {layer} {tree} {position} {rep(16,3)} {chains} {count} {auth}'
        if lean:
            lines += [f'theorem {name}_query : {preimage} = {seq(query)} := by decide',
                      f'theorem {name}_digest : toy ({preimage}) = {rep(32,digest)} := by decide',
                      f'theorem {name}_rejected : wots_sum (toy ({preimage})) = {digit_sum} := by decide']
            for height, expected in enumerate(states):
                lines.append(f'theorem {name}_step{height} : {path} {height} = {rep(16,expected)} := by decide')
            lines.append(f'theorem {name}_complete : {value} = {rep(16,states[-1])} := by decide')
        else:
            lines += [f'lemma {name}_query : {preimage} = {seq(query)}.',
                      'proof. by rewrite /wots_preimage /pad_node /address_words /u32_bytes /u64_bytes',
                      '  !tree_repeat16 !tree_repeat32 caller_repeat28 /mkseq tree_indices4 tree_indices8 /=',
                      '  ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56',
                      '  ?IntID.expr0 !rev_cons !rev_nil /=. qed.',
                      f'lemma {name}_digest : toy ({preimage}) = {rep(32,digest)}.',
                      f'proof. by rewrite {name}_query /toy /=. qed.',
                      f'lemma {name}_rejected : wots_sum (toy ({preimage})) = {digit_sum}.',
                      f'proof. rewrite {name}_digest /wots_sum /wots_field /word_window /byte_word /byte_word_le',
                      '  tree_repeat32 /mkseq caller_indices43 /=.',
                      '  by rewrite '+' '.join(f'?caller_digit_pow{n}' for n in range(0,127,3))+' /=. qed.']
            powers = ' '.join('?tree_pow'+str(n) for n in (*range(1, 12), *range(16, 57, 8)))
            for height, expected in enumerate(states):
                lines += [f'lemma {name}_step{height} : {path} {height} = {rep(16,expected)}.']
                if height == 0:
                    lines += ['proof. by rewrite functional_path_zero. qed.']
                else:
                    lines += ['proof.', f'  rewrite (_: {height}={height-1}+1) 1:// functional_path_next 1:// {name}_step{height-1}.',
                              f'  rewrite /tree_path_step {powers} ?IntID.expr0 /=.',
                              '  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.', 'qed.']
            lines += [f'lemma {name}_complete : {value} = {rep(16,states[-1])}.', 'proof.',
                      f'  rewrite /layer_recover_value /wots_recover_value {name}_rejected /wots_target /=.',
                      '  try rewrite /merkle_recover_value.',
                      f'  by rewrite ?{name}_step9. qed.']
    return '\n'.join(lines)+'\n'


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
        lines += [layer_fixture_source(True), 'end Extracted.C10FunctionalCallerFixtures']
    else:
        for n in (9,43):
            lines += [f'lemma caller_indices{n} : iota_ 0 {n} = '+seq(range(n))+'.',
                      'proof. by rewrite '+' '.join(f'(iotaS {i} {n-i-1}) 1://' for i in range(n))+' iota0 1://. qed.']
        lines.append(layer_fixture_source(False))
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
    print('OK two complete forest recoveries, all26 roots, four zero-backend checks, and six input-sensitive rejected-layer query/digest/path continuations')
