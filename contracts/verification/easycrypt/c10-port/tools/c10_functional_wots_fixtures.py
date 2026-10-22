#!/usr/bin/env python3
"""Independent arithmetic/ordering checks for the paired functional extension.

The toy backend is deliberately not SHA. It produces 32 bounded bytes and makes
the address position and prior node observable, so a reversed walk changes the
result. Expected values below are also checked by a separate imperative byte
construction using Python's big-endian integer encoding.
"""
import argparse
from pathlib import Path
from c10_representation import COUNT, INT, HASH, BYTES, var, count_as_int, int_as_count, hash_apply, render, check_outputs

CASES = ((0, 0, 3), (5, 1, 12), (5, 2, 31), (255, 2, 13), (2147483648, 1, 7))


def independent_values():
    for start, steps, expected in CASES:
        node = bytes([3] * 16)
        for position in range(start, start + steps):
            address = bytearray(32)
            address[24:28] = position.to_bytes(4, 'big')
            query = bytes(32) + address + node + bytes(16)
            node = bytes([(query[59] + 2 * query[64] + 1) % 256] * 16)
        if node != bytes([expected] * 16):
            raise ValueError('independent chain witness changed')


def fixture_source(lean):
    independent_values()
    clamp = render(int_as_count(var('x', INT)), lean)
    embed = render(count_as_int(var('n', COUNT)), lean)
    call = render(hash_apply(var('f', HASH), var('xs', BYTES)), lean)
    if lean:
        lines = ['/- Generated functional-printer boundary and independent chain checks. -/',
                 'import Extracted.C10Representation', 'import Aeneas',
                 'open C10Representation', 'set_option maxRecDepth 8192',
                 'namespace Extracted.C10FunctionalWotsFixtures',
                 f'def clamp (x : Int) : Nat := {clamp}',
                 f'def embed (n : Nat) : Int := {embed}',
                 f'def applyBackend (f : List Int → List Int) (xs : List Int) : List Int := {call}',
                 'example : clamp (-1) = 0 := by decide',
                 'example : clamp 0 = 0 := by decide',
                 'example : clamp 7 = 7 := by decide',
                 'example (n : Nat) : clamp (embed n) = n := by simp [clamp, embed]',
                 'example (f : List Int → List Int) (xs : List Int) : applyBackend f xs = f xs := rfl',
                 'def toy (bs : List Int) : List Int := List.replicate 32 ((bs.getD 59 0 + 2 * bs.getD 64 0 + 1) % 256)']
        for start, steps, expected in CASES:
            lines.append(f'example : wots_chain_value toy (List.replicate 32 0) (List.replicate 32 0)'
                         f' (List.replicate 16 3) {start} {steps} = List.replicate 16 {expected} := by decide')
        lines.append('end Extracted.C10FunctionalWotsFixtures')
    else:
        lines = ['(* Generated functional-printer boundary and independent chain checks. *)',
                 'require import AllCore List IntDiv Ring C10Representation.',
                 f'op clamp (x : int) : int = {clamp}.',
                 f'op embed (n : int) : int = {embed}.',
                 f'op apply_backend (f : int list -> int list) (xs : int list) : int list = {call}.',
                 'lemma clamp_negative : clamp (-1) = 0. proof. by rewrite /clamp. qed.',
                 'lemma clamp_zero : clamp 0 = 0. proof. by rewrite /clamp. qed.',
                 'lemma clamp_positive : clamp 7 = 7. proof. by rewrite /clamp. qed.',
                 'lemma count_roundtrip n : 0 <= n => clamp (embed n) = n. proof. rewrite /clamp /embed; smt(). qed.',
                 'lemma backend_application f xs : apply_backend f xs = f xs. proof. by rewrite /apply_backend. qed.',
                 'op toy (bs : int list) : int list = nseq 32 ((nth 0 bs 59 + 2 * nth 0 bs 64 + 1) %% 256).']
        for n in (16, 32):
            lines += [f'lemma fixture_repeat{n} (x : int) : nseq {n} x = [' + '; '.join(['x'] * n) + '].',
                      'proof. by rewrite ' + ' '.join(f'(nseqS {i} x) 1://' for i in reversed(range(n))) + ' nseq0. qed.']
        for n in (2, 4):
            lines += [f'lemma fixture_indices{n} : iota_ 0 {n} = [' + '; '.join(map(str, range(n))) + '].',
                      'proof. by rewrite ' + ' '.join(f'(iotaS {i} {n-i-1}) 1://' for i in range(n)) + ' iota0 1://. qed.']
        for start, steps, expected in CASES:
            lines += [f'lemma chain_{start}_{steps} : wots_chain_value toy (nseq 32 0) (nseq 32 0)'
                      f' (nseq 16 3) {start} {steps} = nseq 16 {expected}.']
            if steps == 0:
                lines.append('proof. by rewrite /wots_chain_value /mkseq iota0 1://. qed.')
                continue
            lines += ['proof.',
                      '  have h8 : 2^8 = 256 by rewrite (_: 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.',
                      '  have h16 : 2^16 = 65536 by rewrite (_: 16=2*2*2*2) 1:// !IntID.exprM !IntID.expr2.',
                      '  have h24 : 2^24 = 16777216 by rewrite (_: 24=8*3) 1:// IntID.exprM h8 (IntID.exprS _ 2) 1:// IntID.expr2.',
                      '  rewrite /wots_chain_value /mkseq ' + ('iota1' if steps == 1 else 'fixture_indices2') + ' /=.',
                      '  rewrite /hash_bytes_node /toy /th_preimage /chain_position_words /u32_bytes /pad_node'
                      ' !fixture_repeat16 !fixture_repeat32 /mkseq fixture_indices4 /=.',
                      '  by rewrite ?h8 ?h16 ?h24 ?IntID.expr0 !rev_cons !rev_nil /= /foldr'
                      ' ?fixture_repeat32 /=.', 'qed.']
    return '\n'.join(lines) + '\n'


def outputs(port):
    return {port / 'scratch/c10_wots_value_fixtures.ec': fixture_source(False),
            port.parent.parent / 'extracted/Extracted/C10FunctionalWotsFixtures.lean': fixture_source(True)}


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
    print('OK functional WOTS printer boundaries and 5 independently checked chain cases')


if __name__ == '__main__':
    main()
