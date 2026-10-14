"""Typed semantic controls for FORS and Merkle common-input callers.

Mutated definitions must compile before their unchanged relational proofs reject.
Controls check proof sensitivity, not falsity of each mutated proposition.
"""
from c10_caller_controls import definitions_only, mutate


# name, module, procedure, old text, new text, intended theorem
TREE_CALLER_CHANGES = [
    ("fors-private-ht", "CommonInputFors", "tree",
     "fors_private_preimage [] ht tree j", "fors_private_preimage [] 0 tree j", "caller_fors_tree"),
    ("fors-private-index", "CommonInputFors", "tree",
     "fors_private_preimage [] ht tree j", "fors_private_preimage [] ht tree (j+1)", "caller_fors_tree"),
    ("fors-leaf-address", "CommonInputFors", "tree",
     "address_words 0 ht 3 tree 0 0 j", "address_words 0 ht 3 tree 0 0 (j+1)", "caller_fors_tree"),
    ("fors-pair-order", "CommonInputFors", "tree",
     "(pad_node sibling) (pad_node current)", "(pad_node current) (pad_node sibling)", "caller_fors_tree"),
    ("fors-auth-position", "CommonInputFors", "tree",
     "auth <- put auth height sibling", "auth <- put auth (height+1) sibling", "caller_fors_tree"),
    ("fors-root-result", "CommonInputFors", "root",
     "return result.`1", "return nseq 16 0", "caller_fors_root"),
    ("fors-sign-secret", "CommonInputFors", "sign",
     "fors_private_preimage [] ht tree target", "fors_private_preimage [] ht tree 0", "caller_fors_sign"),
    ("fors-sign-path", "CommonInputFors", "sign",
     "tree(seed,ht,tree,target)", "tree(seed,ht,tree,0)", "caller_fors_sign"),
    ("fors-recover-count", "CommonInputFors", "recover",
     "while (h < 11)", "while (h < 10)", "caller_fors_recover"),
    ("fors-recover-target", "CommonInputFors", "recover",
     "address_words 0 ht 3 tree 0 0 target", "address_words 0 ht 3 tree 0 0 (target %% 2048)", "caller_fors_recover"),
    ("merkle-root-leaf", "CommonInputMerkle", "root",
     "CommonPrivateWots(O).leaf(seed,layer,tree,kp)", "CommonPrivateWots(O).leaf(seed,layer,tree,0)", "caller_keygen_root"),
    ("merkle-root-order", "CommonInputMerkle", "root",
     "(pad_node sibling) (pad_node current)", "(pad_node current) (pad_node sibling)", "caller_keygen_root"),
    ("merkle-build-path", "CommonInputMerkle", "build",
     "keep <- put keep height left", "keep <- put keep (height+1) left", "caller_merkle_build"),
    ("merkle-build-parent", "CommonInputMerkle", "build",
     "parent <- kp %/ (2^(height+1))", "parent <- kp %/ (2^height)", "caller_merkle_build"),
    ("merkle-recover-order", "CommonInputMerkle", "recover",
     "(pad_node left) (pad_node right)", "(pad_node right) (pad_node left)", "caller_merkle_recover"),
    ("merkle-recover-count", "CommonInputMerkle", "recover",
     "while (h < 9)", "while (h < 8)", "caller_merkle_recover"),
]

TREE_CALLER_REASONS = {'fors-private-ht': 'the given proof-term proves:', 'fors-private-index': 'the given proof-term proves:', 'fors-leaf-address': 'the given proof-term proves:', 'fors-pair-order': '[by]: cannot close goals', 'fors-auth-position': '[by]: cannot close goals', 'fors-root-result': 'cannot save an incomplete proof', 'fors-sign-secret': 'the given proof-term proves:', 'fors-sign-path': 'the given proof-term proves:', 'fors-recover-count': 'cannot apply `split/None` on that goal', 'fors-recover-target': 'the given proof-term proves:', 'merkle-root-leaf': 'nothing to introduce', 'merkle-root-order': '[by]: cannot close goals', 'merkle-build-path': '[by]: cannot close goals', 'merkle-build-parent': '[by]: cannot close goals', 'merkle-recover-order': 'the given proof-term proves:', 'merkle-recover-count': 'cannot apply `split/None` on that goal'}


def tree_caller_outputs(port):
    source = (port / "cdrafts-split/C10TreeCallerBridge.ec").read_text()
    outputs = {port / "scratch/c10_tree_caller_positive.ec": source}
    for name, module, proc, before, after, _ in TREE_CALLER_CHANGES:
        changed = mutate(source, module, proc, before, after)
        stem = "c10_tree_caller_" + name.replace("-", "_")
        outputs[port / "scratch" / (stem + "_typed.ec")] = definitions_only(changed)
        outputs[port / "scratch" / (stem + "_reject.ec")] = changed
    return outputs


def tree_caller_rows():
    rows = ["scratch/c10_tree_caller_positive.ec\tMUST-PASS\t-"]
    for name, *_ in TREE_CALLER_CHANGES:
        stem = "scratch/c10_tree_caller_" + name.replace("-", "_")
        rows.extend([stem + "_typed.ec\tMUST-PASS\t-",
                     stem + "_reject.ec\tMUST-FAIL\t" + TREE_CALLER_REASONS[name]])
    return rows
