"""Typed mutation controls for initialized sessions and wrapper composition."""
import re

NATIVE_GROUPS = {
    'keygen': ('C10FunctionalKeygen',),
    'session': ('C10FunctionalSession', 'C10FunctionalInitialization'),
    'wrapper': ('C10FunctionalWrapper',),
    'wrapper_context': ('C10FunctionalWrapperSession',),
}
# Name, group, exact source replacement, first consuming theorem.
NATIVE_CHANGES = [
    ('keygen-layer', 'keygen', 'key 1 0).', 'key 0 0).', 'fixed_functional_key_preparation'),
    ('keygen-secret', 'keygen', '(functional_public_seed public) key 1 0',
     '(functional_public_seed public) (functional_public_seed public) 1 0', 'fixed_functional_key_preparation'),
    ('keygen-padding', 'keygen', '= pad_node (node public).', '= node public.', 'fixed_functional_key_preparation'),
    ('raw-cap', 'session', 'FullSession.raw_calls < FullSession.raw_limit',
     'FullSession.raw_calls <= FullSession.raw_limit', 'functional_session_hash'),
    ('failure-latch', 'session', 'else { FullSession.failed <- true; }',
     'else { FullSession.failed <- false; }', 'functional_session_sign'),
    ('returned-ledger', 'session', 'rcons FullSession.signed_messages message;',
     'rcons FullSession.signed_messages random;', 'functional_session_sign'),
    ('forge-freshness', 'session', '!List.mem FullSession.signed_messages forged.`1',
     'List.mem FullSession.signed_messages forged.`1', 'functional_byte_driver'),
    ('initialized-backend', 'session', 'FixedBackend.init(fn); FixedPrefix.key <- key;\n    result <@ ByteContext',
     'FixedBackend.init(fn); FixedPrefix.key <- [];\n    result <@ ByteContext', 'functional_initialized_byte_session'),
    ('shared-encoding', 'session', 'result <- Some (paired_signature_bytes (oget s));',
     'result <- Some (nseq 0 0);', 'functional_byte_view_sign'),
    ('shared-decoding', 'session', 'word_decode forged.`2',
     'word_decode []', 'functional_byte_driver'),
    ('wrapper-guard', 'wrapper', 'signed <> None /\\ guard /\\',
     'signed <> None /\\ true /\\', 'fixed_functional_wrapper'),
    ('wrapper-second-cost', 'wrapper', 'functional_signer_cost f key seed root random message shb +',
     '0 +', 'fixed_functional_wrapper'),
    ('wrapper-verification-cost', 'wrapper', 'functional_verifier_cost f seed root message\n        (oget',
     '0 * functional_verifier_cost f seed root message\n        (oget', 'fixed_functional_wrapper'),
    ('wrapper-second-history', 'wrapper', 'functional_signer_state f first second key seed root random message shb',
     'functional_signer_state f initial second key seed root random message shb', 'fixed_functional_wrapper'),
    ('wrapper-refusal-charge', 'wrapper_context',
     'WrapperSession.sign_calls <- WrapperSession.sign_calls+1;',
     'if (ready) { WrapperSession.sign_calls <- WrapperSession.sign_calls+1; }',
     'functional_wrapper_session_sign'),
    ('wrapper-retry', 'wrapper_context',
     'size shuffle_b = 32 /\\ WrapperSession.sign_calls < WrapperSession.sign_limit',
     'size shuffle_b = 32 /\\ WrapperSession.sign_calls = 0 /\\ WrapperSession.sign_calls < WrapperSession.sign_limit',
     'functional_wrapper_session_sign'),
    ('wrapper-freshness', 'wrapper_context',
     '!List.mem WrapperSession.signed_messages forged.`1',
     'List.mem WrapperSession.signed_messages forged.`1',
     'functional_wrapper_driver'),
]


def replace_once(text, before, after):
    if before == after or text.count(before) != 1:
        raise ValueError('session mutation anchor drift: '+repr(before))
    return text.replace(before, after, 1)


def native_fixture(port, group, mutation=None, typed=False, preserving=False):
    from cert_cone import _decl_span
    modules = NATIVE_GROUPS[group]
    imports, bodies = [], []
    for module in modules:
        text = (port/'cdrafts-split'/(module+'.ec')).read_text()
        def collect(match):
            for name in match.group(1).split():
                if name not in modules and name not in imports:
                    imports.append(name)
            return ''
        bodies.append(re.sub(r'(?m)^require import ([^.]+)\.', collect, text))
    body = '\n'.join(bodies)
    if preserving:
        before, after = {
            'keygen': ('= pad_node (node public).', '= pad_node ((fun d => node d) public).'),
            'session': ('result <- nseq 256 false;', 'result <- (fun d => d) (nseq 256 false);'),
            'wrapper': ('if ready /\\ signed <> None', 'if (fun b => b) ready /\\ signed <> None'),
            'wrapper_context': ('result <- nseq 256 false;', 'result <- (fun d => d) (nseq 256 false);'),
        }[group]
        body = replace_once(body, before, after)
    if mutation:
        body = replace_once(body, *mutation)
    if typed:
        declarations = [_decl_span(body, m.start()) for m in re.finditer(r'(?m)^(?:op|module) \w+', body)]
        if not declarations or any('\nlemma ' in d for d in declarations):
            raise ValueError('session declaration extraction drift')
        body = '\n\n'.join(declarations)
    return 'require import '+' '.join(imports)+'.\n\n'+body+'\n'


def session_outputs(port):
    result = {}
    for group in NATIVE_GROUPS:
        for label, preserving in [('positive', False), ('preserving', True)]:
            result[port/'scratch'/('c10_session_'+group+'_'+label+'.ec')] = native_fixture(
                port, group, preserving=preserving)
    for name, group, before, after, _ in NATIVE_CHANGES:
        stem = 'c10_session_'+name.replace('-', '_')
        for label, typed in [('typed', True), ('reject', False)]:
            result[port/'scratch'/(stem+'_'+label+'.ec')] = native_fixture(
                port, group, (before, after), typed=typed)
    return {path: text.rstrip()+'\n' for path, text in result.items()}


LEAN_MODULES = {'keygen': 'C10FunctionalKeygen', 'wrapper': 'C10FunctionalWrapper'}
# Mutate the claim while retaining its proof; a separate definition of its
# proposition must typecheck, so parser/type errors cannot count as rejection.
LEAN_CHANGES = [
    ('root-layer', 'keygen', 'extracted_public_root', '(byteInts secret.val) 1 0',
     '(byteInts secret.val) 0 0'),
    ('root-padding', 'keygen', 'extracted_public_root', '(byteInts (pad16Pure seed).val)',
     '(byteInts seed.val)'),
    ('initialized-message', 'keygen', 'initialized_release_bytes', '(byteInts message.val)',
     '(byteInts secret.val)'),
    ('initialized-output', 'keygen', 'initialized_release_bytes', '.ok (encodeWords words)',
     '.ok ([] : List Int)'),
    ('wrapper-sign-bytes', 'wrapper', 'wrapper_functional_release', '.ok (signatureBytes sig)',
     '.ok ([] : List Int)'),
    ('wrapper-verifier', 'wrapper', 'wrapper_functional_release',
     '(word_decode (signatureBytes sig)) = true', '(word_decode (signatureBytes sig)) = false'),
    ('wrapper-sign-count', 'wrapper', 'wrapper_functional_release', 'before.trace + 2',
     'before.trace + 1'),
    ('wrapper-verify-count', 'wrapper', 'wrapper_functional_release',
     'traceCallCost 0 1 before.trace + 1', 'traceCallCost 0 1 before.trace'),
]


def lean_fixture(root, group, mutation=None, typed=False, preserving=False):
    module = LEAN_MODULES[group]
    text = (root/'Extracted'/(module+'.lean')).read_text()
    namespace = ('Extracted.C10FunctionalKeygen' if group == 'keygen' else 'secure_wrapper_model')
    text = text.replace('namespace '+namespace+'\n', 'namespace '+namespace+'.SessionProbe\n', 1)
    text = text.replace('end '+namespace+'\n', 'end '+namespace+'.SessionProbe\n', 1)
    if preserving:
        theorem, before, after = {
            'keygen': ('extracted_public_root', '(byteInts secret.val)',
                       '((fun xs => xs) (byteInts secret.val))'),
            'wrapper': ('wrapper_functional_release', '.ok (signatureBytes sig)',
                        '.ok ((fun xs => xs) (signatureBytes sig))'),
        }[group]
        start = text.index('theorem '+theorem+' ')
        end = text.index(' := by', start)
        text = text[:start]+replace_once(text[start:end], before, after)+text[end:]
    if mutation:
        theorem, before, after = mutation
        start = text.index('theorem '+theorem+' ')
        end = text.index(' := by', start)
        # The selected mutation is in the proposition, never its proof.
        text = text[:start]+replace_once(text[start:end], before, after)+text[end:]
    if typed:
        pattern = r'(?ms)^theorem (\w+) (.*?)(?=^theorem |^end(?: |\n)|\Z)'
        def proposition(match):
            body = match.group(2)
            statement = body[:body.index(' := by')]
            pos = statement.index(' :\n')
            return 'def '+match.group(1)+' '+statement[:pos]+' : Prop :=\n'+statement[pos+3:]+'\n\n'
        text, count = re.subn(pattern, proposition, text)
        if count != 2 or re.search(r'(?m)^theorem ', text):
            raise ValueError('session proposition extraction drift')
    return text


NATIVE_REASONS = {'keygen-layer': 'cannot prove goal (strict)', 'keygen-secret': 'cannot prove goal (strict)', 'keygen-padding': 'cannot prove goal (strict)', 'raw-cap': '[by]: cannot close goals', 'failure-latch': '[by]: cannot close goals', 'returned-ledger': '[by]: cannot close goals', 'forge-freshness': '[by]: cannot close goals', 'initialized-backend': 'cannot clear _ that is/are used in the conclusion', 'shared-encoding': 'nothing to rewrite', 'shared-decoding': 'the given proof-term proves:', 'wrapper-guard': 'cannot prove goal (strict)', 'wrapper-second-cost': 'cannot prove goal (strict)', 'wrapper-verification-cost': 'cannot prove goal (strict)', 'wrapper-second-history': 'cannot prove goal (strict)', 'wrapper-refusal-charge': '[by]: cannot close goals', 'wrapper-retry': '[by]: cannot close goals', 'wrapper-freshness': '[by]: cannot close goals'}

def session_rows():
    if set(NATIVE_REASONS) != {row[0] for row in NATIVE_CHANGES}:
        raise ValueError('session rejection reason census drift')
    rows = []
    for group in NATIVE_GROUPS:
        for label in ('positive', 'preserving'):
            rows.append('scratch/c10_session_'+group+'_'+label+'.ec	MUST-PASS	-')
    for name, *_ in NATIVE_CHANGES:
        stem = 'scratch/c10_session_'+name.replace('-', '_')
        rows.extend([stem+'_typed.ec	MUST-PASS	-',
                     stem+'_reject.ec	MUST-FAIL	'+NATIVE_REASONS[name]])
    return rows
