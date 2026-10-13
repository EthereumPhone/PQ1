"""Typed procedural mutations for WOTS private-input caller composition.

Every changed definition must compile before its unchanged proof rejects.
The same-oracle equivalences are tested, including failure and effect order;
the controls do not establish that each mutated proposition is false.
"""
from c10_caller_controls import definitions_only, mutate


# name, procedure, old text, new text, intended theorem
PRIVATE_CALLER_CHANGES = [
    ("leaf-keypair", "leaf", "wots_private_preimage [] layer tree kp i",
     "wots_private_preimage [] layer tree 0 i", "caller_leaf_chains"),
    ("leaf-tree-high", "leaf", "wots_private_preimage [] layer tree kp i",
     "wots_private_preimage [] layer (tree %% 4294967296) kp i", "caller_leaf_chains"),
    ("leaf-chain-stop", "leaf", "kp,i,node d,0,7", "kp,i,node d,0,6", "caller_leaf_chains"),
    ("leaf-order", "leaf", "elements <- rcons elements current",
     "elements <- current :: elements", "caller_leaf_chains"),
    ("leaf-compression-kind", "leaf", "address_words layer tree 1 kp 0 0 0",
     "address_words layer tree 0 kp 0 0 0", "caller_leaf_chains"),
    ("sign-shuffle", "fill", ".permutation(shuffle,43)",
     ".permutation(nseq 32 0,43)", "caller_wots_fill"),
    ("sign-private-index", "fill", "wots_private_preimage [] layer tree kp i",
     "wots_private_preimage [] layer tree kp (i+1)", "caller_wots_fill"),
    ("sign-digit-stop", "fill", "0,digit 3 accepted i", "0,7", "caller_wots_fill"),
    ("sign-placement", "fill", "put sigma i current", "put sigma step current", "caller_wots_fill"),
    ("sign-exhaustion", "sign", "result <- None",
     "result <- Some ([],0)", "caller_wots_sign_factored"),
    ("sign-count", "sign", "Some (sigma,(oget accepted).`1)",
     "Some (sigma,(oget accepted).`1+1)", "caller_wots_sign_factored"),
]

PRIVATE_CALLER_REASONS = {
    "leaf-keypair": "the given proof-term proves:",
    "leaf-tree-high": "the given proof-term proves:",
    "leaf-chain-stop": "cannot apply `split/None` on that goal",
    "leaf-order": "nothing to rewrite",
    "leaf-compression-kind": "the given proof-term proves:",
    "sign-shuffle": "[by]: cannot close goals",
    "sign-private-index": "the given proof-term proves:",
    "sign-digit-stop": "cannot apply `split/None` on that goal",
    "sign-placement": "cannot apply `split/None` on that goal",
    "sign-exhaustion": "[by]: cannot close goals",
    "sign-count": "[by]: cannot close goals"
}


def private_caller_outputs(port):
    source = (port / "cdrafts-split/C10PrivateCallerBridge.ec").read_text()
    outputs = {port / "scratch/c10_private_caller_positive.ec": source}
    for name, proc, before, after, _ in PRIVATE_CALLER_CHANGES:
        changed = mutate(source, "CommonPrivateWots", proc, before, after)
        stem = "c10_private_caller_" + name.replace("-", "_")
        outputs[port / "scratch" / (stem + "_typed.ec")] = definitions_only(changed)
        outputs[port / "scratch" / (stem + "_reject.ec")] = changed
    return outputs


def private_caller_rows():
    rows = ["scratch/c10_private_caller_positive.ec\tMUST-PASS\t-"]
    for name, *_ in PRIVATE_CALLER_CHANGES:
        stem = "scratch/c10_private_caller_" + name.replace("-", "_")
        rows.extend([stem + "_typed.ec\tMUST-PASS\t-",
                     stem + "_reject.ec\tMUST-FAIL\t" + PRIVATE_CALLER_REASONS[name]])
    return rows
