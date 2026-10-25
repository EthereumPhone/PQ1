"""Controls for the initialized byte-wrapper reduction.

Each altered program/operator has a definition-only typecheck. Rejection is
credited only after the raw diagnostic is located in the named consumer; a
timeout is not rejection evidence. These controls establish proof sensitivity,
not a general counterexample for every altered probability bound.
"""
import re

from c10_caller_controls import mutate
from cert_cone import _decl_span


# name, source module, program module, procedure, before, after, first consumer
CHANGES = [
    ('released-only', 'WrapperExposureLog', 'WrapperExposureSession', 'sign',
     'if (result <> None)', 'if (true)', 'wrapper_exposure_records'),
    ('query-cap', 'WrapperExposureLog', 'WrapperQueryExposureSession', 'hash',
     'raw_calls < WrapperSession.raw_limit', 'raw_calls <= WrapperSession.raw_limit',
     'wrapper_query_hash_exact'),
    ('forest-address', 'WrapperForestRelease', 'WrapperForestRelease', 'values',
     'F.secret(ht,t,forest_index digest t)', 'F.secret(ht,t+1,forest_index digest t)',
     'wrapper_forest_release_recorded'),
    ('fors-guard', 'WrapperReleasedFors', 'WrapperReleasedFors', 'sign',
     'if (final_guard)', 'if (!final_guard)', 'wrapper_release_plan_projection'),
    ('byte-length', 'WrapperByteSession', 'WrapperByteDriver', 'run',
     'size forged.`1 = 32', 'size forged.`1 = 31', 'wrapper_byte_driver_equiv'),
    ('byte-format', 'WrapperByteSession', 'WrapperByteDriver', 'run',
     'byte_signature forged.`2', 'true', 'wrapper_byte_driver_equiv'),
    ('wots-guard', 'WrapperChainReleasedWots', 'WrapperChainReleasedWots', 'sign',
     'if (final_guard)', 'if (!final_guard)', 'wrapper_chain_released_projection'),
    ('candidate-budget', 'WrapperWotsCandidateBudget', None, None,
     'op wrapper_wots_candidate_budget qr qs = 155135+qr+qs*727934+771.',
     'op wrapper_wots_candidate_budget qr qs = 155135+qr+qs*363666+771.',
     'wrapper_wots_context_candidate_cost'),
    ('aggregate-wots', 'WrapperNumericalBound', None, None,
     '632475648%r*', '0%r*', 'wrapper_query_byte_euf_bound'),
    ('aggregate-fors', 'WrapperNumericalBound', None, None,
     '6442450944%r*', '0%r*', 'wrapper_query_byte_euf_bound'),
    ('aggregate-hop', 'WrapperNumericalBound', None, None,
     '(wrapper_total_public_budget qr qs)%r*(1%r/2%r)^256.',
     '0%r*(1%r/2%r)^256.', 'wrapper_physical_byte_euf_bound'),
]
CONSUMERS = {row[0]: row[-1] for row in CHANGES}
CONSUMERS['wots-early-value'] = 'wrapper_chain_layer_plan_unopened'


def only_definitions(source):
    """Remove complete lemma/proof blocks, including one-line proofs."""
    result, count = re.subn(r'(?ms)^lemma\b.*?\bqed\.\s*', '', source)
    if not count or count != len(re.findall(r'(?m)^lemma\b', source)):
        raise ValueError('wrapper control lemma boundary drift')
    if re.search(r'(?m)^(lemma|proof|qed)\b', result):
        raise ValueError('wrapper typed control retained a proof')
    return result


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('wrapper control anchor drift: ' + before)
    return source.replace(before, after)


def bound_contract(source, file, consumer):
    """Check an altered local charge against its original proved contract.

    Direct proof-term matching avoids asking SMT to search for a proof of an
    undercharged bound. Positive and altered variants use the same proof.
    This is statement/charge sensitivity, not a counterexample to the bound.
    """
    definitions = only_definitions(source)
    start = source.index('lemma '+consumer+'\n')
    stop = source.index('\nproof.', start)
    statement = source[start:stop]
    if file == 'WrapperNumericalBound':
        proof = ('move=> ha hr hs hqr hqs; exact ('+file+'.'+consumer+
                 ' A qr qs &m ha hr hs hqr hqs).')
    else:
        proof = ('move=> hr hs; exact ('+file+'.'+consumer+' A qr qs hr hs).')
    # Import the proved source before defining the altered local charge.
    return ('require import '+file+'.\n'+definitions+'\n'+statement+
            '\nproof. '+proof+' qed.\n')


def early_value_sources(port):
    """Retain the actual endpoint planner and its unopened-cut theorem.

    The mutant adds one value call and the corresponding existing call rule.
    The final logical postcondition and all assumptions remain unchanged. This
    avoids scoring a mere extra-program-statement tactic-shape rejection.
    """
    source = (port/'cdrafts-split/WrapperChainLayerPlan.ec').read_text()
    imports = '\n'.join(re.findall(r'(?m)^require import [^\n]+', source))+'\n'
    start = source.index('module WrapperChainLayerPlan ')
    module = _decl_span(source, start)
    start = source.index('lemma wrapper_chain_layer_plan_unopened ')
    lemma = source[start:source.index('qed.', start)+4]
    positive = (imports+'\n'+module+'\n\n'+lemma+'\n').replace(
        'WrapperChainLayerPlan', 'WotsEarlyValueControl')
    changed = replace_once(positive, 'var built, subseed, signed, result;',
                           'var built, subseed, signed, result, early;')
    changed = replace_once(changed,
        'built <@ ChainMerkle(O).build(seed,layer,tree,leaf);',
        'built <@ ChainMerkle(O).build(seed,layer,tree,leaf);\n'
        '    early <@ O.value(seed,layer,tree,0,0,0);')
    changed = replace_once(changed,
        '  call (observed_merkle_unopened seed0 layer0 tree0 opened0); auto.',
        '  call (observed_value_opening seed0 layer0 tree0 0 0 0 opened0).\n'
        '  call (observed_merkle_unopened seed0 layer0 tree0 opened0); auto.')
    return positive, changed


def byte_driver_source(source):
    """Compare the actual byte driver directly with its unchanged original.

    Keeping the structured adapter out of this focused equivalence avoids a
    large irrelevant codec expansion when a guard is deliberately different.
    """
    imports = '\n'.join(re.findall(r'(?m)^require import [^\n]+', source))+'\n'
    module = _decl_span(source, source.index('module WrapperByteDriver '))
    module = module.replace('module WrapperByteDriver ', 'module WrapperByteGuardControl ')
    return (imports+'require import WrapperByteSession.\n\n'+module+'''

lemma wrapper_byte_driver_equiv
    (A <: WrapperByteClient {-WrapperSession})
    (O <: PrefixOracle {-A,-WrapperSession}) :
  equiv[WrapperByteGuardControl(A,O).run ~ WrapperByteDriver(A,O).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob O,glob WrapperSession}].
proof. proc; sim. qed.
''')


def wrapper_security_outputs(port):
    outputs = {}
    for name, file, module, proc, before, after, _ in CHANGES:
        source = (port/'cdrafts-split'/(file+'.ec')).read_text()
        if file == 'WrapperByteSession':
            source = byte_driver_source(source)
            module = 'WrapperByteGuardControl'
        if module:
            changed = mutate(source, module, proc, before, after)
        else:
            source = bound_contract(source, file, CONSUMERS[name])
            changed = replace_once(source, before, after)
        prefix = port/'scratch'/('c10_wrapper_security_'+name.replace('-', '_'))
        outputs[prefix.with_name(prefix.name+'_typed.ec')] = only_definitions(changed)
        outputs[prefix.with_name(prefix.name+'_reject.ec')] = changed
        positive_name = file if module else name.replace('-', '_')
        outputs[port/'scratch'/('c10_wrapper_security_'+positive_name+'_positive.ec')] = source
    positive, changed = early_value_sources(port)
    prefix = port/'scratch/c10_wrapper_security_wots_early_value'
    outputs[prefix.with_name(prefix.name+'_positive.ec')] = positive
    outputs[prefix.with_name(prefix.name+'_typed.ec')] = only_definitions(changed)
    outputs[prefix.with_name(prefix.name+'_reject.ec')] = changed
    # Semantics-preserving changes must continue to pass.
    source = (port/'cdrafts-split/WrapperExposureLog.ec').read_text()
    outputs[port/'scratch/c10_wrapper_security_release_preserving.ec'] = replace_once(
        source, 'if (result <> None)', 'if ((fun b => b) (result <> None))')
    source = (port/'cdrafts-split/WrapperForestRelease.ec').read_text()
    outputs[port/'scratch/c10_wrapper_security_forest_preserving.ec'] = replace_once(
        source, 'secrets <- rcons secrets secret;', 'secrets <- rcons secrets ((fun x => x) secret);')
    source = (port/'cdrafts-split/WrapperReleasedFors.ec').read_text()
    outputs[port/'scratch/c10_wrapper_security_guard_preserving.ec'] = replace_once(
        source, 'if (final_guard)', 'if ((final_guard))')
    return outputs


# Filled from exact-source, isolated native calibration before enrollment.
REASONS = {'aggregate-fors': 'the given proof-term proves:', 'aggregate-hop': 'the given proof-term proves:', 'aggregate-wots': 'the given proof-term proves:', 'byte-format': 'cannot save an incomplete proof', 'byte-length': 'cannot save an incomplete proof', 'candidate-budget': 'the given proof-term proves:', 'forest-address': 'cannot apply `split/None` on that goal', 'fors-guard': 'expecting a goal of the form: hoare, ehoare, phoare, equiv', 'query-cap': '[by]: cannot close goals', 'released-only': '[by]: cannot close goals', 'wots-early-value': 'cannot save an incomplete proof', 'wots-guard': 'expecting a goal of the form: hoare[S], ehoare[S], phoare[S], equiv[S]'}


def wrapper_security_rows():
    from pathlib import Path
    port = Path(__file__).resolve().parents[1]
    if set(REASONS) != set(CONSUMERS):
        raise ValueError('wrapper security control reason census drift')
    rows = []
    for path in sorted(wrapper_security_outputs(port)):
        file = str(path.relative_to(port))
        if file.endswith('_reject.ec'):
            key = path.stem.removeprefix('c10_wrapper_security_').removesuffix('_reject').replace('_', '-')
            rows.append(file+'\tMUST-FAIL\t'+REASONS[key])
        else:
            rows.append(file+'\tMUST-PASS\t-')
    return rows
