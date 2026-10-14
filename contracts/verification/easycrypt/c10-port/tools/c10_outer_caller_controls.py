"""Typed controls for forest/layer/signer common-input caller composition.

Changed definitions must compile before the unchanged intended proof rejects.
These controls check proof sensitivity, not falsity of every mutated proposition.
"""
from c10_caller_controls import definitions_only, mutate

# name, module, procedure, old text, new text, intended theorem
OUTER_CALLER_CHANGES = [
    ('forest-shuffle-label', 'CommonInputForest', 'sign',
     'derive(shuffle,shuffle_forest_label)', 'derive(shuffle,[102;111;114;116])', 'caller_forest_sign'),
    ('forest-shuffle-seed', 'CommonInputForest', 'sign',
     'permutation(subseed,12)', 'permutation(shuffle,12)', 'caller_forest_sign'),
    ('forest-shuffle-size', 'CommonInputForest', 'sign',
     'permutation(subseed,12)', 'permutation(subseed,11)', 'caller_forest_sign'),
    ('layer-shuffle-seed', 'CommonInputLayer', 'sign',
     'derive(shuffle,shuffle_layer_label layer)', 'derive(seed,shuffle_layer_label layer)', 'caller_layer_sign'),
    ('forest-one-secret', 'CommonInputForest', 'one',
     'return (sig.`1,sig.`2,root)', 'return (root,sig.`2,root)', 'caller_forest_one'),
    ('forest-secret-position', 'CommonInputForest', 'sign',
     'secrets <- put secrets t sig.`1', 'secrets <- put secrets 0 sig.`1', 'caller_forest_sign'),
    ('forest-path-position', 'CommonInputForest', 'sign',
     'auths <- put auths t sig.`2', 'auths <- put auths 0 sig.`2', 'caller_forest_sign'),
    ('forest-last-secret', 'CommonInputForest', 'sign',
     'secrets <- put secrets 12 last', 'secrets <- put secrets 11 last', 'caller_forest_sign'),
    ('forest-last-domain', 'CommonInputForest', 'sign',
     'address_words 0 ht 3 12 0 0 0', 'address_words 0 ht 4 12 0 0 0', 'caller_forest_sign'),
    ('forest-root-order', 'CommonInputForest', 'sign',
     'address_words 0 ht 4 0 0 0 0) roots', 'address_words 0 ht 4 0 0 0 0) (rev roots)', 'caller_forest_sign'),
    ('forest-recover-count', 'CommonInputForest', 'recover',
     'while (t < 12)', 'while (t < 11)', 'caller_forest_recover'),
    ('forest-recover-last', 'CommonInputForest', 'recover',
     '(nth (nseq 16 0) secrets 12)', '(nth (nseq 16 0) secrets 11)', 'caller_forest_recover'),
    ('layer-full-counter', 'CommonInputLayer', 'recover',
     'message,sig.`1,sig.`2)', 'message,sig.`1,(sig.`2 %% signing_budget))', 'caller_layer_recover'),
    ('layer-recover-path', 'CommonInputLayer', 'recover',
     'tree,pk,leaf,sig.`3)', 'tree,pk,leaf,[])', 'caller_layer_recover'),
    ('layer-shuffle-label', 'CommonInputLayer', 'sign',
     'derive(shuffle,shuffle_layer_label layer)', 'derive(shuffle,shuffle_layer_label 0)', 'caller_layer_sign'),
    ('layer-exhaustion', 'CommonInputLayer', 'sign',
     'result <- None', 'result <- Some (([],0,[]),[])', 'caller_layer_sign'),
    ('layer-sign-path', 'CommonInputLayer', 'sign',
     '(oget signed).`2,built.`1', '(oget signed).`2,[]', 'caller_layer_sign'),
    ('signer-coordinate', 'CommonInputSigner', 'finish',
     'idx_tree <- idx_tree %/ 512', 'idx_tree <- idx_tree %/ 256', 'caller_signer_finish'),
    ('signer-layer-count', 'CommonInputSigner', 'finish',
     'while (layer < 2 /\\ ok)', 'while (layer < 1 /\\ ok)', 'caller_signer_finish'),
    ('signer-layer-failure', 'CommonInputSigner', 'finish',
     'ok <- false', 'ok <- true', 'caller_signer_finish'),
    ('signer-randomizer', 'CommonInputSigner', 'finish',
     'Some (randomizer,forest.`1,forest.`2,layers)', 'Some ([],forest.`1,forest.`2,layers)', 'caller_signer_finish'),
    ('signer-randomness', 'CommonInputSigner', 'sign',
     'run(random,message,seed,root)', 'run([],message,seed,root)', 'caller_signer_sign'),
    ('signer-grind-failure', 'CommonInputSigner', 'sign',
     'result <- None', 'result <- Some ([],[],[],[])', 'caller_signer_sign'),
    ('verify-root-binding', 'CommonInputSigner', 'verify',
     'hmsg_preimage seed root', 'hmsg_preimage seed seed', 'caller_signer_verify'),
    ('verify-acceptance', 'CommonInputSigner', 'verify',
     'if (accept_digest digest)', 'if (true)', 'caller_signer_verify'),
    ('verify-coordinate', 'CommonInputSigner', 'verify',
     'idx_tree <- idx_tree %/ 512', 'idx_tree <- idx_tree %/ 256', 'caller_signer_verify'),
    ('verify-layer-count', 'CommonInputSigner', 'verify',
     'while (layer < 2)', 'while (layer < 1)', 'caller_signer_verify'),
    ('verify-root-result', 'CommonInputSigner', 'verify',
     'result <- pad current = root', 'result <- pad current = seed', 'caller_signer_verify'),
    ('verify-default-counter', 'CommonInputSigner', 'verify',
     'nth ([],0,[]) sig.`4 layer', 'nth ([],1,[]) sig.`4 layer', 'caller_signer_verify'),
]

OUTER_CALLER_REASONS = {'forest-one-secret': 'cannot save an incomplete proof', 'forest-secret-position': '[by]: cannot close goals', 'forest-path-position': '[by]: cannot close goals', 'forest-last-secret': 'cannot apply `split/None` on that goal', 'forest-last-domain': 'the given proof-term proves:', 'forest-root-order': 'the given proof-term proves:', 'forest-recover-count': 'cannot apply `split/None` on that goal', 'forest-recover-last': 'the given proof-term proves:', 'layer-full-counter': '[by]: cannot close goals', 'layer-recover-path': '[by]: cannot close goals', 'layer-shuffle-label': '[by]: cannot close goals', 'layer-exhaustion': '[by]: cannot close goals', 'layer-sign-path': '[by]: cannot close goals', 'signer-coordinate': '[by]: cannot close goals', 'signer-layer-count': '[by]: cannot close goals', 'signer-layer-failure': '[by]: cannot close goals', 'signer-randomizer': '[by]: cannot close goals', 'signer-randomness': 'expecting a goal of the form: equiv[S]', 'signer-grind-failure': '[by]: cannot close goals', 'verify-root-binding': 'nothing to rewrite', 'verify-acceptance': '[by]: cannot close goals', 'verify-coordinate': '[by]: cannot close goals', 'verify-layer-count': '[by]: cannot close goals', 'verify-root-result': '[by]: cannot close goals', 'verify-default-counter': '[by]: cannot close goals'}

OUTER_CALLER_REASONS.update({
    'forest-shuffle-label': '[by]: cannot close goals',
    'forest-shuffle-seed': '[by]: cannot close goals',
    'forest-shuffle-size': '[by]: cannot close goals',
    'layer-shuffle-seed': '[by]: cannot close goals',
})


def outer_caller_outputs(port):
    source = (port / "cdrafts-split/C10OuterCallerBridge.ec").read_text()
    outputs = {port / "scratch/c10_outer_caller_positive.ec": source}
    for name, module, proc, before, after, _ in OUTER_CALLER_CHANGES:
        changed = mutate(source, module, proc, before, after)
        stem = "c10_outer_caller_" + name.replace("-", "_")
        outputs[port / "scratch" / (stem + "_typed.ec")] = definitions_only(changed).rstrip() + "\n"
        outputs[port / "scratch" / (stem + "_reject.ec")] = changed
    return outputs


def outer_caller_rows():
    rows = ["scratch/c10_outer_caller_positive.ec\tMUST-PASS\t-"]
    for name, *_ in OUTER_CALLER_CHANGES:
        stem = "scratch/c10_outer_caller_" + name.replace("-", "_")
        rows.extend([stem + "_typed.ec\tMUST-PASS\t-",
                     stem + "_reject.ec\tMUST-FAIL\t" + OUTER_CALLER_REASONS[name]])
    return rows
