"""Addressed-node controls: finite counterexamples and proof sensitivity.

Finite contradictory twins are backed by checked counterexamples. Contract
twins establish exact statement sensitivity, not probability lower bounds.
Program mutants must typecheck; equivalent rewrites must continue to pass.
"""
import re

from c10_caller_controls import mutate
from c10_wrapper_security_controls import only_definitions, replace_once


FINITE = [
    ('exception-included', ': exceptional_fors_query control_exception',
     ': !exceptional_fors_query control_exception', 'control_exception_included'),
    ('two-exception-calls', ': exceptional_fors_count [control_exception;control_exception]=2',
     ': exceptional_fors_count [control_exception;control_exception]=1', 'control_two_exception_calls'),
    ('distinct-same-label', ': addressed_excess control_memo=1',
     ': addressed_excess control_memo=0', 'control_distinct_same_label'),
    ('cached-key', ': addressed_excess empty.[control_key0<-control_digest].[control_key0<-control_digest]=0',
     ': addressed_excess empty.[control_key0<-control_digest].[control_key0<-control_digest]=1', 'control_cached_key'),
    ('raw-prepopulation', 's seed : size seed=32 => 1<=nonordinary_count control_memo s seed',
     's seed : size seed=32 => nonordinary_count control_memo s seed=0', '(control_raw_prepopulation s seed)'),
    ('collision-witness', ': addressed_node_collision control_memo',
     ': !addressed_node_collision control_memo', 'control_collision_witness'),
    ('first-sample', ': !(1<=addressed_excess empty.[control_key0<-control_digest])',
     ': 1<=addressed_excess empty.[control_key0<-control_digest]', 'control_first_sample_no_excess'),
    ('different-address', ': addressed_label control_key0<>addressed_label control_key2',
     ': addressed_label control_key0=addressed_label control_key2', 'control_different_address'),
]

CONTRACTS = [
    ('address-equality', 'AddressedOrdinaryInputs', 'ordinary_public_node_unique',
     '  same_node_address x y => x=y.', '  x=y.',
     '(ordinary_public_node_unique h s seed x y)'),
    ('exception-charge', 'AddressedMemoCount', 'nonordinary_count_sign_suffix',
     '    exceptional_fors_count queries-exceptional_fors_count base.', '    0.',
     '(nonordinary_count_sign_suffix h h\' s s\' seed base queries)'),
    ('partial-refusal', 'AddressedSignerExceptionCount', 'raw_signer_sign_exception_bound',
     'q<=exceptional_fors_count Independent.queries<=q+2',
     'exceptional_fors_count Independent.queries=q+2', '(raw_signer_sign_exception_bound q)'),
    ('ordinary-success', 'AddressedOrdinarySigner', 'raw_signer_sign_ordinary_inputs',
     '==>\n    ordinary_new_inputs', '==>\n    res<>None /\\ ordinary_new_inputs',
     '(raw_signer_sign_ordinary_inputs seed0 old)'),
    ('ordinary-hypothesis', 'AddressedBuckets', 'addressed_excess_bound',
     'size seed=32 => ', '', '(addressed_excess_bound h s seed)'),
    ('actual-byte-count', 'AddressedMemoSession', 'nonordinary_byte_game_count',
     '<=exceptional_public_budget qr qs]', '<=exceptional_public_budget qr qs-1]',
     '(nonordinary_byte_game_count A qr qs)'),
    ('actual-game-link', 'AddressedByteCollision', 'byte_addressed_node_collision',
     'Pr[IndependentGame(ByteContext(A)).run()', 'Pr[RealGame(ByteContext(A)).run()',
     '(byte_addressed_node_collision A qr qs &m)'),
    ('physical-transfer', 'AddressedNumericalBound', 'physical_byte_addressed_node_euf_bound',
     '<= addressed_node_physical_euf_charge qr qs.', '<= addressed_node_independent_euf_charge qr qs.',
     '(physical_byte_addressed_node_euf_bound A qr qs &m)'),
]


def lemma_block(source, name):
    start = source.index('lemma '+name)
    end = source.index('qed.', start)+len('qed.')
    return source[start:end]+'\n'


def imports(source):
    return '\n'.join(re.findall(r'^(?:require import|import) .+$', source, re.M))+'\n'


def audit_projection_source(port):
    source = (port/'cdrafts-split/AddressedAudit.ec').read_text()
    proof = lemma_block(source, 'addressed_audit_hash_projection')
    # A false alignment goal must reject immediately, not be judged by an SMT
    # resource timeout or a later tactic trying to operate on that pure goal.
    proof = proof.replace('+ auto.', '+ by auto.').replace('  auto.\nqed.', '  by auto.\nqed.')
    return only_definitions(source)+proof


def signer_comparison_source(port, procedure):
    source = (port/'cdrafts-split/RawSigner.ec').read_text()
    definitions = only_definitions(source)
    definitions = replace_once(definitions, 'module RawSigner ', 'module ControlSigner ')
    return ('require import RawSigner.\n'+definitions+f'''
lemma signer_comparison (O <: PrefixOracle) :
  equiv [ControlSigner(O).{procedure} ~ RawSigner(O).{procedure} :
    ={{arg,glob O}} ==> ={{res,glob O}}].
proof. proc; sim; auto. qed.
''')


MUTATIONS = [
    ('cached-resampling', 'audit', 'AddressedAudit', 'hash',
     'if (x \\notin rawhistory)', 'if (true)', 'addressed_audit_hash_projection'),
    ('returned-memo', 'audit', 'AddressedAudit', 'hash',
     'return oget rawhistory.[x];', 'return nseq 256 false;', 'addressed_audit_hash_projection'),
    ('header-refusal', 'sign', 'ControlSigner', 'sign',
     'if (accepted <> None)', 'if (true)', 'signer_comparison'),
    ('layer-refusal', 'finish', 'ControlSigner', 'finish',
     'while (layer < 2 /\\ ok)', 'while (layer < 2)', 'signer_comparison'),
]

# Filled only after exact-source development calibration, then checked by the
# complete native gate. A parser/timeout/resource failure is never enrolled.
REASONS = {'cached-resampling': '[by]: cannot close goals', 'returned-memo': '[by]: cannot close goals', 'header-refusal': 'cannot save an incomplete proof', 'layer-refusal': 'cannot save an incomplete proof'}


def addressed_node_outputs(port):
    outputs = {}
    header = ('require import AllCore List FSet FMap.\n'
              'require import C10RawOracle AddressedNodeCollision AddressedBuckets '
              'AddressedMemoCount AddressedControlFacts AddressedForsException AddressedForsExceptionCount.\n')
    for name, positive, negative, application in FINITE:
        for mode, claim in [('positive', positive), ('reject', negative)]:
            outputs[port/'scratch'/('addressed_node_'+name.replace('-', '_')+'_'+mode+'.ec')] = (
                header+'lemma checked '+claim+'.\nproof. exact '+application+'. qed.\n')
    for name, file, theorem, before, after, application in CONTRACTS:
        source = (port/'cdrafts-split'/(file+'.ec')).read_text()
        statement = lemma_block(source, theorem).split('proof.')[0]
        statement = statement.replace('lemma '+theorem, 'lemma checked', 1)
        changed = replace_once(statement, before, after)
        for mode, claim in [('positive', statement), ('reject', changed)]:
            outputs[port/'scratch'/('addressed_node_'+name.replace('-', '_')+'_'+mode+'.ec')] = (
                imports(source)+'require import '+file+'.\n'+claim+
                'proof. exact '+application+'. qed.\n')
    sources = {'audit': audit_projection_source(port),
               'sign': signer_comparison_source(port, 'sign'),
               'finish': signer_comparison_source(port, 'finish')}
    for key, source in sources.items():
        outputs[port/'scratch'/('addressed_node_'+key+'_positive.ec')] = source
    for name, key, module, proc, before, after, _ in MUTATIONS:
        changed = mutate(sources[key], module, proc, before, after)
        stem = 'addressed_node_'+name.replace('-', '_')
        outputs[port/'scratch'/(stem+'_typed.ec')] = only_definitions(changed)
        outputs[port/'scratch'/(stem+'_reject.ec')] = changed
    outputs[port/'scratch/addressed_node_audit_preserving.ec'] = mutate(
        sources['audit'], 'AddressedAudit', 'hash',
        'if (x \\notin rawhistory)', 'if (!!(x \\notin rawhistory))')
    outputs[port/'scratch/addressed_node_refusal_preserving.ec'] = mutate(
        sources['sign'], 'ControlSigner', 'sign',
        'if (accepted <> None)', 'if ((accepted <> None))')
    return outputs


def addressed_node_rows():
    rows = []
    for name, *_ in FINITE+CONTRACTS:
        stem = 'scratch/addressed_node_'+name.replace('-', '_')
        reason = ('[by]: cannot close goals' if name == 'ordinary-hypothesis'
                  else 'the given proof-term proves:')
        rows.extend([stem+'_positive.ec\tMUST-PASS\t-',
                     stem+'_reject.ec\tMUST-FAIL\t'+reason])
    for key in ['audit', 'sign', 'finish', 'audit_preserving', 'refusal_preserving']:
        suffix = '.ec' if key.endswith('preserving') else '_positive.ec'
        rows.append('scratch/addressed_node_'+key+suffix+'\tMUST-PASS\t-')
    for name, *_ in MUTATIONS:
        stem = 'scratch/addressed_node_'+name.replace('-', '_')
        rows.extend([stem+'_typed.ec\tMUST-PASS\t-',
                     stem+'_reject.ec\tMUST-FAIL\t'+REASONS[name]])
    return rows
