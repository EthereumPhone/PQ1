#!/usr/bin/env python3
"""Independent boundary fixtures for both shuffle expression printers.

Expected orders also match the existing actual-Rust/independent-Rust corpus.
Python hashlib supplies public streams; this is corpus evidence, not a theorem
equating concrete SHA with an ideal oracle. No shared-expression evaluator is
used to compute expected values.
"""
import argparse
import hashlib
from pathlib import Path
import re
from c10_representation import check_outputs


def fixtures(port):
    root = port.parents[1] / 'extracted'
    corpus = (root / 'Extracted/ShuffleDiffVectors.lean').read_text()
    rows = re.findall(r'\{ seed := #\[([0-9, ]+)\], n := (\d+), order := #\[([0-9, ]+)\] \}', corpus)
    if len(rows) != 72:
        raise ValueError('actual shuffle corpus inventory changed')
    rust = {(bytes(map(int, seed.split(','))), int(n)): list(map(int, order.split(',')))
            for seed, n, order in rows}
    cases = []
    for seed in (bytes([1] * 32), bytes(range(32))):
        stream = b''.join(hashlib.sha256(b'sphincs-c10-fisher-yates-v1' + seed + i.to_bytes(4, 'big')).digest()
                          for i in range(4))
        for n in (0, 1, 2, 13, 43, 64):
            order = list(range(n))
            for step, i in enumerate(range(n-1, 0, -1)):
                sample = int.from_bytes(stream[2*step:2*step+2], 'little')
                j = sample * (i+1) // 65536
                order[i], order[j] = order[j], order[i]
            if rust[seed, n] != order + [0] * (64-n):
                raise ValueError('independent Python/Rust shuffle disagreement')
            cases.append((n, list(stream), order))

    def nums(xs, lean):
        return '[' + (', ' if lean else '; ').join(map(str, xs)) + ']'

    ec = ['(* Generated independent shuffle corpus; see c10_shuffle_fixtures.py. *)',
          'require import AllCore List IntDiv Ring.', 'require import C10Representation.']
    lean = ['/- Generated independent shuffle corpus; see c10_shuffle_fixtures.py. -/',
            'import Extracted.C10Representation', 'open C10Representation',
            'namespace C10ShuffleFixtures', 'def check : IO Unit := do']

    def add(name, left, expected, proof):
        ec.extend([f'lemma {name} : {left(False)} = {nums(expected, False)}.',
                   'proof.', proof, 'qed.'])
        lean.append(f'  unless {left(True)} == {nums(expected, True)} do')
        lean.append(f'    throw (IO.userError "{name} disagrees")')

    def expand_iota(n):
        return '  rewrite ' + ' '.join(f'(iotaS {i} {n-i-1}) 1://' for i in range(n)) + ' iota0 1:// /=.'

    for k, (n, stream, order) in enumerate(cases):
        if n == 0:
            proof = '  by rewrite /shuffle_order /mkseq /= !iota0 //=.'
        elif n == 1:
            proof = '  by rewrite /shuffle_order /mkseq /= iota1 iota0 1:// /=.'
        else:
            steps, current = [], list(range(n))
            for pos, i in enumerate(range(n-1, 0, -1)):
                j = (stream[2*pos+1]*256 + stream[2*pos])*(i+1)//65536
                before = nums(current, False)
                current[i], current[j] = current[j], current[i]
                steps.append(f'  have step_{i} : shuffle_swap {before} {i} {j} = {nums(current, False)}'
                             ' by rewrite /shuffle_swap /put /=.')
                steps.append(f'  rewrite step_{i}.')
            proof = '\n'.join(['  rewrite /shuffle_order /mkseq /=.', expand_iota(n), expand_iota(n-1),
                                '  rewrite /shuffle_choice /max /=.'] + steps + ['  done.'])
        add(f'shuffle_order_fixture_{k}', lambda l: f'shuffle_order {n} {nums(stream,l)}', order, proof)
    seed = list(range(32))
    for k, label in enumerate((b'', b'wots0', b'fors', bytes([0, 255, 0, 128]))):
        add(f'shuffle_label_fixture_{k}',
            lambda l: f'shuffle_seed_preimage {nums(seed,l)} {nums(label,l)}',
            list(b'sphincs-c10-shuffle-v1') + seed + list(label),
            '  by rewrite /shuffle_seed_preimage /=.')
    for k, counter in enumerate((0, 1, 3, 255, 65536, 4294967295)):
        add(f'shuffle_counter_fixture_{k}',
            lambda l: f'shuffle_block_preimage {nums(seed,l)} {counter}',
            list(b'sphincs-c10-fisher-yates-v1') + seed + list(counter.to_bytes(4, 'big')),
            '\n'.join(['  have h8 : 2^8 = 256 by rewrite (_: 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.',
                       '  have h16 : 2^16 = 65536 by rewrite (_: 16=2*2*2*2) 1:// !IntID.exprM !IntID.expr2.',
                       '  have h24 : 2^24 = 16777216 by rewrite (_: 24=8*3) 1:// IntID.exprM h8 (IntID.exprS _ 2) 1:// IntID.expr2.',
                       '  rewrite /shuffle_block_preimage /u32_bytes /mkseq /=.', expand_iota(4),
                       '  by rewrite ?h8 ?h16 ?h24 ?IntID.expr0 /=.']))
    for k, (order, i, j, expected) in enumerate((([0,1,2], 0, 2, [2,1,0]),
                                               ([0,1], 1, 1, [0,1]),
                                               ([4,5], 8, 0, [0,5]),
                                               ([], 0, 0, []))):
        add(f'shuffle_swap_fixture_{k}', lambda l: f'shuffle_swap {nums(order,l)} {i} {j}', expected,
            '  by rewrite /shuffle_swap /put /=.')
    # Constant integer division, including both ends of the byte domain.
    for k, (lo, hi, bound) in enumerate(((0,0,64),(255,255,64),(255,0,13),(0,255,43))):
        expected = (hi*256+lo)*bound//65536
        ec.extend([f'lemma shuffle_choice_fixture_{k} : shuffle_choice {lo} {hi} {bound} = {expected}.',
                   'proof. by rewrite /shuffle_choice /=. qed.'])
        lean.extend([f'  unless shuffle_choice {lo} {hi} {bound} == {expected} do',
                     f'    throw (IO.userError "shuffle_choice_fixture_{k} disagrees")'])
    lean.extend(['  IO.println "OK: 30 independent paired shuffle fixtures; 12 orders agree with actual Rust corpus"',
                 '#eval check', 'end C10ShuffleFixtures'])
    return {port / 'scratch/c10_shuffle_fixtures.ec': '\n'.join(ec)+'\n',
            root / 'Extracted/C10ShuffleFixtures.lean': '\n'.join(lean)+'\n'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    outputs = fixtures(Path(__file__).resolve().parents[1])
    if args.write:
        for path, text in outputs.items():
            path.write_text(text)
    check_outputs(outputs)
    print('PASS exact independent shuffle fixtures in Lean and EasyCrypt')
