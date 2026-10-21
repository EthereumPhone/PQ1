#!/usr/bin/env python3
"""Source-bound typed changes for the paired C10 representation proofs.

Each negative preserves syntax/types and changes one value/layout rule. The
full split gate must compile every changed definition successfully and reject
its unchanged endpoint proof at the recorded normal proof diagnostic. A proof
rejection alone does not assert logical falsity; time/resource errors are not
control evidence. Lean executes the layout change list with a strict classifier.
Additional EasyCrypt-only procedural mutations cover common-input callers.
"""
import argparse
from pathlib import Path
from c10_representation import source, check_outputs
from c10_caller_controls import caller_outputs, caller_rows
from c10_private_caller_controls import private_caller_outputs, private_caller_rows
from c10_tree_caller_controls import tree_caller_outputs, tree_caller_rows
from c10_outer_caller_controls import outer_caller_outputs, outer_caller_rows
from c10_shuffle_controls import shuffle_outputs, shuffle_rows
from c10_wrapper_cost_controls import wrapper_cost_outputs, wrapper_cost_rows
from c10_acceptance_controls import acceptance_outputs, acceptance_rows
from c10_paired_signer_controls import paired_signer_outputs, paired_signer_rows
from c10_digest_caller_controls import digest_caller_outputs, digest_caller_rows
from stirling_coverage_controls import stirling_outputs, stirling_rows
from accepted_encoding_controls import accepted_encoding_outputs, accepted_encoding_rows
from node_domain_controls import node_domain_outputs, node_domain_rows
from leaf_candidate_controls import leaf_candidate_outputs, leaf_candidate_rows
from chain_candidate_controls import chain_candidate_outputs, chain_candidate_rows
from c10_paired_session_controls import paired_session_outputs, paired_session_rows
from c10_paired_keygen_controls import paired_keygen_outputs, paired_keygen_rows
from c10_r_availability_controls import r_availability_outputs, r_availability_rows
from c10_total_availability_controls import total_availability_outputs, total_availability_rows
from c10_search_acceptance_controls import search_acceptance_outputs, search_acceptance_rows

CHANGES = [
    ("word-endian", "byte_word", "List.reverse bs", "bs", "rev bs", "bs"),
    ("word-base", "byte_word_le", "256", "255", "256", "255"),
    ("ht-bit", "ht_field", "143", "142", "143", "142"),
    ("fors-width", "fors_field", "11)", "10)", "11)", "10)"),
    ("wots-stride", "wots_field", "3 * i", "4 * i", "3 * i", "4 * i"),
    ("counter-width", "word_layer", "List.take 4", "List.take 3", "take 4", "take 3"),
    ("counter-high-bits", "word_layer", "(byte_word (List.take 4 (List.drop (off + 688) bs)))", "((byte_word (List.take 4 (List.drop (off + 688) bs))) % 65536)", "(byte_word (take 4 (drop (off + 688) bs)))", "((byte_word (take 4 (drop (off + 688) bs))) %% 65536)"),
    ("auth-last-node", "word_layer", "word_nodes 9", "word_nodes 8", "word_nodes 9", "word_nodes 8"),
    ("layer-stride", "word_decode", "836 * l", "835 * l", "836 * l", "835 * l"),
    ("forest-last-tree", "word_decode", "List.range 12", "List.range 11", ") 12)", ") 11)"),
    ("hmsg-order", "hmsg_preimage", "seed ++ root", "root ++ seed", "seed ++ root", "root ++ seed"),
    ("hmsg-domain", "hmsg_preimage", "List.replicate 32 255", "List.replicate 31 255", "nseq 32 255", "nseq 31 255"),
    ("node-padding", "pad_node", "value ++ (List.replicate 16 0)", "(List.replicate 16 0) ++ value", "value ++ (nseq 16 0)", "(nseq 16 0) ++ value"),
    ("u32-endian", "u32_bytes", "List.reverse", "id", "rev", "idfun"),
    ("u32-stride", "u32_bytes", "8 * i", "7 * i", "8 * i", "7 * i"),
    ("th-value", "th_preimage", "address ++ value", "address ++ address", "address ++ value", "address ++ address"),
    ("pair-order", "pair_preimage", "left ++ right", "right ++ left", "left ++ right", "right ++ left"),
    ("multi-order", "multi_preimage", "(pad_node value) ++ tail", "tail ++ (pad_node value)", "(pad_node value) ++ tail", "tail ++ (pad_node value)"),
    ("wots-padding", "wots_preimage", "List.replicate 28 0", "List.replicate 27 0", "nseq 28 0", "nseq 27 0"),
    ("randomizer-tag", "r_preimage", "[82,", "[83,", "[82;", "[83;"),
    ("randomizer-random", "r_preimage", " ++ random", " ++ []", " ++ random", " ++ []"),
    ('u64-width', 'u64_bytes', 'List.range 8', 'List.range 7', ') 8)', ') 7)'),
    ('u64-high', 'u64_bytes', '(nonce /', '((nonce % 4294967296) /', '(nonce %/', '((nonce %% 4294967296) %/'),
    ('address-kind', 'address_words', '(u32_bytes kind) ++ (u32_bytes kp)', '(u32_bytes kp) ++ (u32_bytes kind)', '(u32_bytes kind) ++ (u32_bytes kp)', '(u32_bytes kp) ++ (u32_bytes kind)'),
    ('address-tail', 'address_words', '(u32_bytes ha)', '(u32_bytes cp)', '(u32_bytes ha)', '(u32_bytes cp)'),
    ('chain-index-window', 'chain_index_words', 'List.take 20', 'List.take 19', 'take 20', 'take 19'),
    ('chain-position-window', 'chain_position_words', 'List.take 24', 'List.take 23', 'take 24', 'take 23'),
    ('wots-private-tag', 'wots_private_preimage', '[119,', '[118,', '[119;', '[118;'),
    ('wots-tree-padding', 'wots_private_preimage', 'List.replicate 24 0', 'List.replicate 23 0', 'nseq 24 0', 'nseq 23 0'),
    ('wots-private-kp', 'wots_private_preimage', '(u32_bytes kp) ++ (u32_bytes ci)', '(u32_bytes ci) ++ (u32_bytes kp)', '(u32_bytes kp) ++ (u32_bytes ci)', '(u32_bytes ci) ++ (u32_bytes kp)'),
    ('fors-private-tag', 'fors_private_preimage', '[102,', '[103,', '[102;', '[103;'),
    ('fors-private-ht', 'fors_private_preimage', '(u32_bytes ht)', '(u32_bytes tree)', '(u32_bytes ht)', '(u32_bytes tree)'),
]

def changed(text, name, before, after, lean):
    prefix = "def " if lean else "op "
    start = text.index(prefix + name + " ")
    end = text.find("\n\n", start)
    if end < 0: end = len(text)
    chunk = text[start:end]
    if chunk.count(before) != 1: raise RuntimeError((name,before,"mutation ambiguous"))
    return text[:start] + chunk.replace(before,after) + text[end:]

REASONS = {'word-endian': 'nothing to rewrite', 'word-base': '[by]: cannot close goals', 'ht-bit': '[by]: cannot close goals', 'fors-width': '[by]: cannot close goals', 'wots-stride': '[by]: cannot close goals', 'counter-width': 'cannot save an incomplete proof', 'counter-high-bits': 'cannot save an incomplete proof', 'auth-last-node': 'cannot save an incomplete proof', 'layer-stride': 'the given proof-term proves:', 'forest-last-tree': 'the given proof-term proves:'}
REASONS.update({row[0]: '[by]: cannot close goals' for row in CHANGES[10:]})
REASONS["u32-endian"] = "not a congruence"
REASONS["u64-width"] = "the given proof-term proves:"

def control_outputs(port):
    proof=(port/"cdrafts-split/C10RepresentationBridge.ec").read_text()
    anchor="require import C10Representation."
    if proof.count(anchor)!=1: raise ValueError("representation proof import drift")
    hash_proof=(port/"cdrafts-split/C10HashInputBridge.ec").read_text()
    if hash_proof.count(anchor)!=1: raise ValueError("hash-input proof import drift")
    proof += "\n" + hash_proof.replace(anchor, "")
    address_proof=(port/"cdrafts-split/C10AddressInputBridge.ec").read_text()
    if address_proof.count(anchor)!=1: raise ValueError("address-input proof import drift")
    proof += "\n" + address_proof.replace(anchor, "")
    generated=source(False)
    result={port/"scratch/c10_rep_positive.ec":proof.replace(anchor,generated)}
    for name,func,lb,la,eb,ea in CHANGES:
        changed_defs=changed(generated,func,eb,ea,False)
        stem="c10_rep_"+name.replace("-","_")
        result[port/"scratch"/(stem+"_typed.ec")]=changed_defs
        result[port/"scratch"/(stem+"_reject.ec")]=proof.replace(anchor,changed_defs)
    result.update(caller_outputs(port))
    result.update(private_caller_outputs(port))
    result.update(tree_caller_outputs(port))
    result.update(outer_caller_outputs(port))
    result.update(shuffle_outputs(port))
    result.update(wrapper_cost_outputs(port))
    result.update(acceptance_outputs(port))
    result.update(paired_signer_outputs(port))
    result.update(digest_caller_outputs(port))
    result.update(stirling_outputs(port))
    result.update(accepted_encoding_outputs(port))
    result.update(node_domain_outputs(port))
    result.update(leaf_candidate_outputs(port))
    result.update(chain_candidate_outputs(port))
    result.update(paired_session_outputs(port))
    result.update(paired_keygen_outputs(port))
    result.update(r_availability_outputs(port))
    result.update(total_availability_outputs(port))
    result.update(search_acceptance_outputs(port))
    return result

def control_rows():
    rows=["scratch/c10_rep_positive.ec\tMUST-PASS\t-"]
    for name,*_ in CHANGES:
        stem="scratch/c10_rep_"+name.replace("-","_")
        rows.extend([stem+"_typed.ec\tMUST-PASS\t-",
                     stem+"_reject.ec\tMUST-FAIL\t"+REASONS[name]])
    return rows + caller_rows() + private_caller_rows() + tree_caller_rows() + outer_caller_rows() + shuffle_rows() + wrapper_cost_rows() + acceptance_rows() + paired_signer_rows() + digest_caller_rows() + stirling_rows() + accepted_encoding_rows() + node_domain_rows() + leaf_candidate_rows() + chain_candidate_rows() + paired_session_rows() + paired_keygen_rows() + r_availability_rows() + total_availability_rows() + search_acceptance_rows()

def check_manifest_rows(rows):
    expected=control_rows()
    live=[row for row in rows if row.startswith(("scratch/c10_rep_", "scratch/c10_caller_", "scratch/c10_private_caller_", "scratch/c10_tree_caller_", "scratch/c10_outer_caller_", "scratch/c10_shuffle_", "scratch/c10_wrapper_cost_", "scratch/c10_wrapper_session_cost_", "scratch/c10_acceptance_", "scratch/c10_search_acceptance_", "scratch/c10_paired_signer_", "scratch/c10_digest_caller_", "scratch/stirling_", "scratch/accepted_encoding_", "scratch/node_domain_", "scratch/leaf_candidate_", "scratch/chain_candidate_", "scratch/c10_paired_session_", "scratch/c10_paired_keygen_", "scratch/c10_r_availability_", "scratch/c10_total_availability_"))]
    if sorted(live)!=sorted(expected):
        raise ValueError("paired representation control enrollment changed")

def self_test():
    rows=control_rows()
    check_manifest_rows(rows)
    for broken in (rows[1:],rows+[rows[0]],
                   [rows[0].replace("MUST-PASS","MUST-FAIL"),*rows[1:]],
                   [*rows[:-1],rows[-1].split("\t")[0]+"\tMUST-FAIL\tparse error"]):
        try:check_manifest_rows(broken)
        except ValueError:pass
        else:raise RuntimeError("control enrollment self-test accepted drift")
    print("PASS control enrollment: missing/duplicate/polarity/reason changes rejected")

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--write",action="store_true")
    p.add_argument("--self-test",action="store_true")
    args=p.parse_args()
    port=Path(__file__).resolve().parents[1]
    expected=control_outputs(port)
    if args.write:
        for path,text in expected.items():path.write_text(text)
    check_outputs(expected)
    check_manifest_rows((port/"cert-controls-split.tsv").read_text().splitlines())
    if args.self_test:self_test()
    print(f"PASS C10 representation controls: {len(expected)} exact generated EasyCrypt fixtures")
