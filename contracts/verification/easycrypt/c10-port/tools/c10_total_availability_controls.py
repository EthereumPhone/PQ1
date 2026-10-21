"""Typed procedure and contract controls for native total signing availability.

Each procedure change has a definition-only type check. Baseline and equivalent
procedures retain the original consuming proof. Count, finish and session first
check relational correspondence with the canonical procedure using deterministic
simulation, so an inconclusive SMT attempt on a changed invariant cannot count
as rejection. Contract mutations check the pinned proof term's sensitivity;
rejection alone does not establish that every changed statement is mathematically
false. Resource errors never count.
"""
import re

from c10_caller_controls import mutate


# Definition source/module, consumer source/lemma, selected procedure,
# equivalent procedure-local replacement. Only sign needs canonical helpers.
GROUPS = {
    'cache': ('C10RawOracle', 'Shared', 'MemoRejectCompletion',
              'memo_reject_hash_potential', 'hash', 'calls <- calls + 1;', 'calls <- calls + (2-1);'),
    'count': ('RawWots', 'RawWots', 'WotsPhysicalFailure',
              'physical_count_rejected', 'count', 'i <- i+1;', 'i <- i+(2-1);'),
    'wots': ('RawWots', 'RawWots', 'WotsSignerFailure',
             'physical_wots_failure', 'sign', 'result <- Some (sigma,(oget accepted).`1);',
             'result <- Some (sigma,(oget accepted).`1+0);'),
    'layer': ('RawLayer', 'RawLayer', 'WotsSignerFailure',
              'physical_layer_failure', 'sign', 'result <- Some (sig,root);',
              'result <- Some (sig,root ++ []);'),
    'finish': ('RawSigner', 'RawSigner', 'WotsSignerFailure',
               'physical_finish_failure', 'finish', 'layer <- layer+1;', 'layer <- layer+(2-1);'),
    'session': ('FullRSession', 'FullRSession', 'FullAvailabilityTrace',
                'full_availability_sign', 'sign', 'FullSession.sign_calls+1',
                'FullSession.sign_calls+(2-1)'),
    'driver': ('FullRGame', 'FullRDriver', 'FullAvailabilityTrace',
               'full_availability_driver', 'run', 'return result;', 'return !!result;'),
    'context': ('FullRGame', 'FullRContext', 'FullAvailabilityTrace',
                'full_availability_context', 'run', 'FullLimits.raw_cap,FullLimits.sign_cap',
                'FullLimits.raw_cap+0,FullLimits.sign_cap+0'),
}

TOTAL_AVAILABILITY_CHANGES = [
    ('cache-overwrite', 'cache', 'if (x \\notin history)', 'if (true)'),
    ('cache-key', 'cache', 'history.[x] <- y;', 'history.[[]] <- y;'),
    ('cache-distribution', 'cache', 'y <$ full_digest;', 'y <$ dunit (nseq 256 true);'),
    ('count-short', 'count', 'i < signing_budget /\\', 'i < signing_budget-1 /\\'),
    ('count-start', 'count', 'i <- 0; result <- None;', 'i <- 1; result <- None;'),
    ('count-skip', 'count', 'i <- i+1;', 'i <- i+2;'),
    ('count-input', 'count', '++ be 32 i)', '++ be 32 0)'),
    ('count-acceptance', 'count', 'if (count_accepts d)', 'if (!count_accepts d)'),
    ('count-invent-failure', 'count', 'return result;', 'return None;'),
    ('wots-invent-failure', 'wots', 'result <- Some (sigma,(oget accepted).`1);', 'result <- None;'),
    ('layer-invent-failure', 'layer', 'result <- Some (sig,root);', 'result <- None;'),
    ('finish-invent-failure', 'finish', 'if (ok)', 'if (false)'),
    ('finish-node-width', 'finish', 'current <- forest.`3;', 'current <- nseq 17 0;'),
    ('session-refusal-failure', 'session', 'result <- None;', 'result <- None; FullSession.failed <- true;'),
    ('session-seed', 'session', '.sign(FullSession.seed,FullSession.root,', '.sign([],FullSession.root,'),
    ('session-clear-r', 'session', 'FullSession.failed <- true;', 'FullSession.failed <- true; RFailure.bad <- false;'),
    ('driver-force-failure', 'driver', 'return result;', 'FullSession.failed <- true; return result;'),
    ('driver-seed', 'driver', '.init(seed,root,qr,qs);', '.init([],root,qr,qs);'),
    ('context-seed', 'context', 'inputs.`3,inputs.`4,', 'inputs.`4,inputs.`4,'),
]

TOTAL_AVAILABILITY_REASONS = {
    name: 'cannot save an incomplete proof' for name, *_ in TOTAL_AVAILABILITY_CHANGES
}

TOTAL_AVAILABILITY_REASONS.update({
    'cache-overwrite': '[by]: cannot close goals',
    'cache-key': 'nothing to rewrite',
    'cache-distribution': 'nothing to rewrite',
    'session-refusal-failure': 'invalid first instruction',
    'driver-force-failure': '[by]: cannot close goals',
    'driver-seed': 'expecting a goal of the form: hoare[S], phoare[S]',
})

# Exact theorem application, with an intentionally altered typed contract.
CONTRACT_CHECKS = [
    ('distinct-inputs', 'MemoRejectCompletion', 'memo_reject_initialized_bound',
     'uniq xs =>', 'true =>', '(memo_reject_initialized_bound A accept xs &m)'),
    ('prefilled-cache', 'MemoRejectCompletion', 'memo_reject_prefilled_bound',
     'memo_reject_completion accept Shared.history{m} xs.',
     'memo_reject_completion accept empty xs.', '(memo_reject_prefilled_bound A accept xs &m)'),
    ('context-bytes', 'WotsRejectDomain', 'wots_context_covered',
     'byte_values message =>', 'true =>', '(wots_context_covered seed layer tree kp message)'),
    ('context-width', 'WotsRejectDomain', 'wots_context_covered',
     'size message=16 =>', 'true =>', '(wots_context_covered seed layer tree kp message)'),
    ('context-cardinality', 'WotsRejectDomain', 'wots_context_cardinality',
     '=2^256.', '=2^255.', 'wots_context_cardinality'),
    ('counter-wrap', 'WotsRejectDomain', 'wots_count_schedule_unique',
     '0<=n<=2^256 =>', '0<=n<=2^257 =>', '(wots_count_schedule_unique stem n)'),
    ('physical-charge', 'PhysicalRejectBound', 'physical_wots_domain_bound',
     'wots_domain_charge n.', 'wots_domain_charge n-1%r.', '(physical_wots_domain_bound A seed n &m)'),
    ('byte-raw-cap', 'ByteTotalAvailability', 'byte_total_initialized_availability',
     'FullLimits.raw_cap{m}=qr =>', 'true =>', '(byte_total_initialized_availability A qr qs &m)'),
    ('byte-sign-cap', 'ByteTotalAvailability', 'byte_total_initialized_availability',
     'FullLimits.sign_cap{m}=qs =>', 'true =>', '(byte_total_initialized_availability A qr qs &m)'),
    ('byte-failed-event', 'ByteTotalAvailability', 'byte_total_initialized_availability',
     ': FullSession.failed]', ': !FullSession.failed]', '(byte_total_initialized_availability A qr qs &m)'),
    ('byte-total-charge', 'ByteTotalAvailability', 'byte_total_initialized_availability',
     'byte_total_availability_charge qr qs.', 'byte_total_availability_charge qr qs-1%r.',
     '(byte_total_initialized_availability A qr qs &m)'),
    ('numerical-budget', 'AvailabilityNumerics', 'total_availability_numerical',
     '(2^32) (2^20)', '(2^32) (2^25)', 'total_availability_numerical'),
    ('numerical-target', 'AvailabilityNumerics', 'total_availability_numerical',
     '(1%r/2%r)^38.', '(1%r/2%r)^80.', 'total_availability_numerical'),
]

CORRESPONDENCE_PROOFS = {
    'count': '''proof.
  proc; while (={seed,layer,tree,kp,message,i,result,glob Physical,glob Shared}).
  + wp; call (_ : ={glob Physical,glob Shared}); first by sim.
    auto => />.
  auto => />.
qed.
''',
    'finish': '''proof.
  proc; wp; while (={seed,randomizer,shuffle,forest,current,idx_tree,layer,layers,ok,glob Physical,glob Shared}).
  + wp; call (_ : ={glob Physical,glob Shared}); first by sim.
    auto => />.
  wp; call (_ : ={glob Physical,glob Shared}); first by sim.
  auto => />.
qed.
''',
    'session': '''proof.
  proc; sp 1 1; if; first by auto.
  + wp; call (_ : ={glob Physical,glob Shared,glob RFailure}); first by sim.
    auto => />.
  auto => />.
qed.
''',
}


def _lemma(source, name):
    matches = list(re.finditer(r'(?ms)^lemma ' + re.escape(name) + r'\b.*?\bqed\.', source))
    if len(matches) != 1:
        raise ValueError('total availability lemma boundary drift: ' + name)
    return matches[0].group() + '\n'


def _header(source):
    return '\n'.join(re.findall(r'^(?:require import|import) .+$', source, re.M)) + '\n'


def _fixture(port, group):
    definition, module, consumer, theorem, proc, *_ = GROUPS[group]
    source = (port / 'cdrafts-split' / (definition + '.ec')).read_text()
    text = (port / 'cdrafts-split' / (consumer + '.ec')).read_text()
    start = source.index('module ' + module + ' ')
    end = source.index('\n}.', start) + len('\n}.')
    block = source[start:end]
    if group == 'wots':
        begin = block.index('  proc sign(')
        stop = block.index('  proc recover(', begin)
        block = ('module ControlledTotalAvailability (O : PreparationOracle) = {\n'
                 '  proc count = RawWots(O).count\n'
                 '  proc chain = RawWots(O).chain\n' + block[begin:stop] + '}.')
    else:
        block = re.sub(r'\b' + re.escape(module) + r'\b', 'ControlledTotalAvailability', block)
    checked = _lemma(text, theorem).replace('lemma ' + theorem, 'lemma checked', 1)
    checked = re.sub(r'\b' + re.escape(module) + r'\b', 'ControlledTotalAvailability', checked)
    if group in ('count', 'finish', 'session'):
        argument = 'PreparationView(Physical)' if group == 'count' else 'Physical'
        state = 'glob Physical,glob Shared'
        if group == 'session':
            state += ',glob FullSession,glob RFailure'
        correspondence = (
            'lemma checked :\n'
            '  equiv[ControlledTotalAvailability(' + argument + ').' + proc +
            ' ~ ' + module + '(' + argument + ').' + proc + ' :\n'
            '    ={arg,' + state + '} ==> ={res,' + state + '}].\n'
            + CORRESPONDENCE_PROOFS[group] + '\n')
        checked = correspondence + checked.replace('lemma checked', 'lemma consumer_checked', 1)
    header = _header(source) + _header(text) + 'require import ' + definition + ' ' + consumer + '.\n\n'
    return header, block + '\n\n', checked


def total_availability_outputs(port):
    outputs = {}
    for group, (_, _, _, _, proc, before, after) in GROUPS.items():
        header, block, proof = _fixture(port, group)
        stem = 'c10_total_availability_' + group
        outputs[port / 'scratch' / (stem + '_positive.ec')] = header + block + proof
        preserving = mutate(block, 'ControlledTotalAvailability', proc, before, after)
        outputs[port / 'scratch' / (stem + '_preserving.ec')] = header + preserving + proof
    for name, group, before, after in TOTAL_AVAILABILITY_CHANGES:
        header, block, proof = _fixture(port, group)
        changed = mutate(block, 'ControlledTotalAvailability', GROUPS[group][4], before, after)
        stem = 'c10_total_availability_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = header + changed
        outputs[port / 'scratch' / (stem + '_reject.ec')] = header + changed + proof
    for name, module, theorem, before, after, application in CONTRACT_CHECKS:
        text = (port / 'cdrafts-split' / (module + '.ec')).read_text()
        statement = _lemma(text, theorem).split('proof.', 1)[0].replace('lemma ' + theorem, 'lemma checked', 1)
        if statement.count(before) != 1:
            raise ValueError('total availability contract anchor drift: ' + name)
        header = _header(text) + 'require import ' + module + '.\n\n'
        proof = 'proof. exact ' + application + '. qed.\n'
        stem = 'c10_total_availability_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_positive.ec')] = header + statement + proof
        outputs[port / 'scratch' / (stem + '_reject.ec')] = header + statement.replace(before, after) + proof
    return outputs


def total_availability_rows():
    rows = []
    for group in GROUPS:
        for suffix in ['positive', 'preserving']:
            rows.append('scratch/c10_total_availability_' + group + '_' + suffix + '.ec\tMUST-PASS\t-')
    for name, *_ in TOTAL_AVAILABILITY_CHANGES:
        stem = 'scratch/c10_total_availability_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + TOTAL_AVAILABILITY_REASONS[name]])
    for name, *_ in CONTRACT_CHECKS:
        stem = 'scratch/c10_total_availability_' + name.replace('-', '_')
        rows.extend([stem + '_positive.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\tthe given proof-term proves:'])
    return rows
