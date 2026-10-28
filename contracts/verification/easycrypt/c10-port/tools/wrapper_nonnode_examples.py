#!/usr/bin/env python3
"""Exact illustrative evaluation, not proof of the EasyCrypt theorem or tightness.

All comparisons use rational arithmetic; decimal strings are display-only.
The formulas are owned by WrapperRefinedNumericalBound and its dependencies.
"""
from fractions import Fraction
from functools import lru_cache
from math import prod
import json


@lru_cache(None)
def digit_count(length, total):
    if length == 0:
        return int(total == 0)
    if total < 0 or total > 7 * length:
        return 0
    return sum(digit_count(length - 1, total - digit) for digit in range(8))


@lru_cache(None)
def stirling(length, blocks):
    if length == 0:
        return int(blocks == 0)
    if blocks <= 0 or blocks > length:
        return 0
    return blocks * stirling(length - 1, blocks) + stirling(length - 1, blocks - 1)


def charges(qr, qs):
    if not isinstance(qr, int) or not isinstance(qs, int) or min(qr, qs) < 0:
        raise ValueError('caps must be nonnegative integers')
    q = 155135 + qr + qs * (2 * (3 * 10000000 + 364892) + 771) + 771
    wots = 155135 + qr + qs * 727934 + 771
    leaf = 155135 + qr + qs * (2 * 364892 + 771) + 771
    exceptional = qr + 775 * qs + 771
    n = qr + 3 * qs + 1
    count = digit_count(43, 205)
    assert count == 22169393903687611906220091621190388
    acceptance = Fraction(count, 2**129)
    retained = {
        'node': min(Fraction(q * (q - 1), 2 * 2**128), Fraction(exceptional * (exceptional + 1), 2**128)),
        'zero': Fraction(q, 2**128),
        'encoding': Fraction(q * (q - 1), 2 * 2**129),
        'wots': Fraction(632475648 * (wots + 88), 2**128),
        'fors': Fraction(6442450944 * (q + 12), 2**128),
        'coverage': sum((Fraction(n**(j + 1) * j**12, 2**(132 + 18*j)) for j in range(1, 13)), Fraction()),
        'prefix': Fraction(q, 2**256),
    }
    refined = dict(retained)
    refined.update(
        encoding=retained['encoding'] * acceptance,
        fors=min(retained['fors'], Fraction(6442450944 * (leaf + 2 + 12), 2**128)),
        coverage=sum((Fraction(n * prod(max(0, n - 1 - i) for i in range(j)) * stirling(12, j),
                               2**(132 + 18*j)) for j in range(1, 13)), Fraction()),
    )
    assert all(refined[key] <= retained[key] for key in retained)
    return {'qr': qr, 'qs': qs, 'Q': q, 'Vwots': wots, 'Vleaf': leaf, 'Rwrapper': exceptional, 'n': n,
            'retained_addressed': retained, 'refined': refined}


def serializable(row):
    result = dict(row)
    for variant in ['retained_addressed', 'refined']:
        terms = row[variant]
        total = sum(terms.values(), Fraction())
        result[variant] = {'terms': {name: str(value) for name, value in terms.items()},
                           'exact_total': str(total), 'approximate_total': format(float(total), '.9g')}
    return result


if __name__ == '__main__':
    print(json.dumps({'scope': 'Illustrative exact rational arithmetic, not deployment policy or attack costs.',
                      'examples': [serializable(charges(qr, qs)) for qr, qs in [(0, 0), (50000, 50000), (1000000, 1000)]]},
                     indent=2))
