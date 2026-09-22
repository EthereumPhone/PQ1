"""Illustration of certified formulas; not a forgery/security-level estimate."""
from decimal import Decimal, localcontext
from fractions import Fraction
import json
B = 10_000_000
p = Fraction(22169393903687611906220091621190388, 2**129)
fresh = 32768 * 305
birthday = Fraction(B * (B-1), 2 * 2**128)
assert B-fresh == 5760 and p >= Fraction(1, 32768)
with localcontext() as ctx:
    ctx.prec = 100
    acceptance = Decimal(p.numerator) / Decimal(p.denominator)
    result = {
        'scope': 'Classical ideal experiments only. No numerical EUF-CMA or QROM claim.',
        'B': B,
        'acceptance_fraction': [p.numerator, p.denominator],
        'acceptance_decimal': str(acceptance),
        'fresh_trials_required': fresh,
        'known_inputs_allowed': B-fresh,
        'proved_exhaustion_upper_bound': '2^-305',
        'ideal_all_fresh_exhaustion_log2': str(B * (1-acceptance).ln() / Decimal(2).ln()),
        'R_collision_budget_scope': 'At most B independent uniform 128-bit R samples in the WHOLE experiment; adaptive stopping is allowed under the explicit theorem premises.',
        'R_birthday_fraction': [birthday.numerator, birthday.denominator],
        'R_birthday_log2': str((Decimal(birthday.numerator)/Decimal(birthday.denominator)).ln()/Decimal(2).ln()),
        'not_established': ['actual shared-SHA simulation', 'zero-charge bounded hypertree composition', 'costed reductions', 'numerical ITSR/EUF-CMA bound'],
    }
print(json.dumps(result, indent=2))
