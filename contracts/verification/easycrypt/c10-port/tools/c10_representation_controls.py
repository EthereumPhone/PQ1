#!/usr/bin/env python3
"""Source-bound typed changes for the paired C10 representation proofs.

Each negative preserves syntax/types and changes one value/layout rule. The
full split gate must compile every changed definition successfully and reject
its unchanged endpoint proof at the recorded normal proof diagnostic. A proof
rejection alone does not assert logical falsity; time/resource errors are not
control evidence. Lean executes the same change list with a strict classifier.
"""
import argparse
from pathlib import Path
from c10_representation import source, check_outputs

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

def control_outputs(port):
    proof=(port/"cdrafts-split/C10RepresentationBridge.ec").read_text()
    anchor="require import C10Representation."
    if proof.count(anchor)!=1: raise ValueError("representation proof import drift")
    generated=source(False)
    result={port/"scratch/c10_rep_positive.ec":proof.replace(anchor,generated)}
    for name,func,lb,la,eb,ea in CHANGES:
        changed_defs=changed(generated,func,eb,ea,False)
        stem="c10_rep_"+name.replace("-","_")
        result[port/"scratch"/(stem+"_typed.ec")]=changed_defs
        result[port/"scratch"/(stem+"_reject.ec")]=proof.replace(anchor,changed_defs)
    return result

def control_rows():
    rows=["scratch/c10_rep_positive.ec\tMUST-PASS\t-"]
    for name,*_ in CHANGES:
        stem="scratch/c10_rep_"+name.replace("-","_")
        rows.extend([stem+"_typed.ec\tMUST-PASS\t-",
                     stem+"_reject.ec\tMUST-FAIL\t"+REASONS[name]])
    return rows

def check_manifest_rows(rows):
    expected=control_rows()
    live=[row for row in rows if row.startswith("scratch/c10_rep_")]
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
