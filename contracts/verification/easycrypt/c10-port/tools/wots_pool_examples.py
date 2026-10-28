#!/usr/bin/env python3
"""Exact illustrative evaluation of the ordinary and wrapper pool charges.

The formulas are owned by WotsPoolNumericalBound and
WrapperWotsPoolNumericalBound. This utility is not a native proof, deployment
policy, attack-cost estimate or concrete SHA-256 security claim.
"""
from fractions import Fraction
from math import prod
import json

from wrapper_nonnode_examples import charges as wrapper_charges, digit_count, stirling


def charges(qr, qs, wrapper=False):
    if type(qr) is not int or type(qs) is not int or min(qr, qs) < 0:
        raise ValueError('caps must be nonnegative integers')
    cardinality = digit_count(43, 205)
    assert cardinality == 22169393903687611906220091621190388
    if wrapper:
        inherited = wrapper_charges(qr, qs)
        previous = dict(inherited['refined'])
        q, n = inherited['Q'], qr + 10 * qs + 2
    else:
        q = 155135 + qr + qs * (3 * 10000000 + 364892) + 771
        candidates = 155135 + qr + qs * 364892 + 771
        exceptional = qr + 2 * qs + 771
        hmsg = qr + qs + 1
        previous = {
            'node': min(Fraction(candidates * (candidates - 1), 2 * 2**128),
                        Fraction(exceptional * (exceptional + 1), 2**128)),
            'zero': Fraction(q, 2**128),
            'encoding': Fraction(q * (q - 1) * cardinality, 2 * 2**258),
            'wots': min(Fraction(632475648 * (q + 86), 2**128),
                        Fraction(632475648 * (candidates + 88), 2**128)),
            'fors': min(Fraction(6442450944 * (q + 12), 2**128),
                        Fraction(6442450944 * (candidates + 14), 2**128)),
            'coverage': sum((Fraction(hmsg * prod(max(0, hmsg - 1 - i) for i in range(j)) * stirling(12, j),
                                      2**(132 + 18*j)) for j in range(1, 13)), Fraction()),
            'prefix': Fraction(q, 2**256),
        }
        n = qr + 4 * qs + 2
    conditional = Fraction(n * (n - 1), 2 * cardinality)
    refined = dict(previous)
    refined['encoding'] = min(previous['encoding'], conditional)
    assert all(refined[name] == value for name, value in previous.items() if name != 'encoding')
    assert refined['encoding'] <= previous['encoding']
    return {'experiment': 'wrapper' if wrapper else 'ordinary', 'qr': qr, 'qs': qs,
            'Q': q, 'accepted_call_cap': n, 'conditional_encoding': conditional,
            'previous': previous, 'refined': refined}


def serializable(row):
    result = {key: value for key, value in row.items() if key not in ('previous', 'refined', 'conditional_encoding')}
    result['conditional_encoding'] = str(row['conditional_encoding'])
    for variant in ['previous', 'refined']:
        terms = row[variant]
        total = sum(terms.values(), Fraction())
        result[variant] = {'terms': {name: str(value) for name, value in terms.items()},
                           'exact_total': str(total), 'approximate_total': format(float(total), '.9g')}
    return result


if __name__ == '__main__':
    print(json.dumps({'scope': __doc__.strip(),
                      'examples': [serializable(charges(qr, qs, wrapper))
                                   for wrapper in [False, True]
                                   for qr, qs in [(0, 0), (65536, 65536), (1000000, 1000)]]}, indent=2))
