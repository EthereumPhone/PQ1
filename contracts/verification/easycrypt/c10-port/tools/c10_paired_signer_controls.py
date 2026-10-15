"""Typed caller changes for paired acceptance through the complete signer."""
from c10_caller_controls import mutate, definitions_only

# name, module, procedure, before, after, first consuming theorem
PAIRED_SIGNER_CHANGES = [
    ('wots-counter', 'PairedSigningWots', 'sign',
     'Some (sigma,(oget accepted).`1)', 'Some (sigma,(oget accepted).`1+1)', 'paired_wots_sign'),
    ('wots-digest', 'PairedSigningWots', 'sign',
     'kp,(oget accepted).`2,shuffle', 'kp,[],shuffle', 'paired_wots_sign'),
    ('wots-exhaustion', 'PairedSigningWots', 'sign',
     'return result;', 'return if result = None then Some ([],0) else result;', 'paired_wots_sign'),
    ('layer-counter', 'PairedSigningLayer', 'recover',
     'message,sig.`1,sig.`2)', 'message,sig.`1,sig.`2+1)', 'paired_layer_recover'),
    ('layer-path', 'PairedSigningLayer', 'sign',
     '(oget signed).`2,built.`1)', '(oget signed).`2,[])', 'paired_layer_sign'),
    ('signer-layer-order', 'PairedSigningSigner', 'finish',
     'layers <- rcons layers (oget signed).`1', 'layers <- (oget signed).`1 :: layers', 'paired_signer_finish'),
    ('signer-root-input', 'PairedSigningSigner', 'sign',
     '.run(random,message,seed,root)', '.run(random,message,seed,seed)', 'paired_signer_sign'),
    ('verify-accept', 'PairedSigningSigner', 'verify',
     'fors_zero_field (bits_to_bytes digest) = 0', 'fors_zero_field (bits_to_bytes digest) <> 0', 'paired_signer_verify'),
    ('verify-root', 'PairedSigningSigner', 'verify',
     'result <- pad current = root', 'result <- pad current <> root', 'paired_signer_verify'),
]

PAIRED_SIGNER_REASONS = {name: '[by]: cannot close goals' for name, *_ in PAIRED_SIGNER_CHANGES}


def paired_signer_outputs(port):
    source = (port / 'cdrafts-split/C10PairedSigner.ec').read_text()
    preserving = mutate(source, 'PairedSigningWots', 'sign',
                        'Some (sigma,(oget accepted).`1)', 'Some (sigma,(oget accepted).`1+0)')
    preserving = mutate(preserving, 'PairedSigningSigner', 'verify',
                        '= 0)', '= (1-1))')
    outputs = {
        port / 'scratch/c10_paired_signer_positive.ec': source,
        port / 'scratch/c10_paired_signer_preserving.ec': preserving,
    }
    for name, module, procedure, before, after, _ in PAIRED_SIGNER_CHANGES:
        changed = mutate(source, module, procedure, before, after)
        stem = 'c10_paired_signer_' + name.replace('-', '_')
        outputs[port / 'scratch' / (stem + '_typed.ec')] = definitions_only(changed).rstrip() + '\n'
        outputs[port / 'scratch' / (stem + '_reject.ec')] = changed
    return outputs


def paired_signer_rows():
    rows = ['scratch/c10_paired_signer_positive.ec\tMUST-PASS\t-',
            'scratch/c10_paired_signer_preserving.ec\tMUST-PASS\t-']
    for name, *_ in PAIRED_SIGNER_CHANGES:
        stem = 'scratch/c10_paired_signer_' + name.replace('-', '_')
        rows.extend([stem + '_typed.ec\tMUST-PASS\t-',
                     stem + '_reject.ec\tMUST-FAIL\t' + PAIRED_SIGNER_REASONS[name]])
    return rows
