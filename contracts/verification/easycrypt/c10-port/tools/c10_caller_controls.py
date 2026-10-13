"""Typed procedural controls for the common-input caller equivalences.

Mutate only the comparison procedure, retaining every theorem and proof.
The definition-only fixture must typecheck before rejection is credited.
The coordinator also checks the diagnostic against the intended theorem;
resource failures are not semantic rejection evidence.
"""
import re


# name, module, procedure, old text, new text, intended theorem
CALLER_CHANGES = [
    ("count-budget", "CommonInputWots", "count",
     "i < signing_budget /\\ result = None", "i < signing_budget-1 /\\ result = None",
     "caller_wots_count"),
    ("count-result", "CommonInputWots", "count",
     "result <- Some (i,d)", "result <- Some (i+1,d)", "caller_wots_count"),
    ("chain-position", "CommonInputWots", "chain",
     "address_words layer tree 0 kp index j 0", "address_words layer tree 0 kp index (j+1) 0",
     "caller_wots_chain"),
    ("chain-result", "CommonInputWots", "chain",
     "current <- node d", "current <- nseq 16 0", "caller_wots_chain"),
    ("recover-counter", "CommonInputWots", "recover",
     "(pad_node message) count", "(pad_node message) (count %% 65536)", "caller_wots_recover"),
    ("recover-sentinel", "CommonInputWots", "recover",
     "result <- nseq 16 0", "result <- nseq 16 1", "caller_wots_recover"),
    ("recover-order", "CommonInputWots", "recover",
     "elements <- rcons elements current", "elements <- current :: elements", "caller_wots_recover"),
    ("nonce-random", "CommonInputGrind", "run",
     "r_preimage [] random message i", "r_preimage [] [] message i", "caller_nonce_grind"),
    ("nonce-accept", "CommonInputGrind", "run",
     "if (accept_digest hd)", "if (!accept_digest hd)", "caller_nonce_grind"),
    ("nonce-exhaustion", "CommonInputGrind", "run",
     "return result;", "return if result = None then Some ([],[]) else result;", "caller_nonce_grind"),
]

CALLER_REASONS = {
    "count-budget": "cannot apply `split/None` on that goal",
    "count-result": "[by]: cannot close goals",
    "chain-position": "the given proof-term proves:",
    "chain-result": "[by]: cannot close goals",
    "recover-counter": "the given proof-term proves:",
    "recover-sentinel": "[by]: cannot close goals",
    "recover-order": "nothing to rewrite",
    "nonce-random": "the given proof-term proves:",
    "nonce-accept": "nothing to introduce",
    "nonce-exhaustion": "[by]: cannot close goals",
}


def mutate(source, module, procedure, before, after):
    start = source.index("module " + module + " ")
    end = source.index("\n}.", start) + len("\n}.")
    block = source[start:end]
    proc = re.search(r"^  proc " + re.escape(procedure) + r"\(", block, re.M)
    if proc is None:
        raise ValueError("caller procedure missing")
    next_proc = re.search(r"^  proc ", block[proc.end():], re.M)
    stop = proc.end() + next_proc.start() if next_proc else len(block)
    body = block[proc.start():stop]
    if body.count(before) != 1:
        raise ValueError("caller mutation anchor drift: " + module + "." + procedure)
    changed = block[:proc.start()] + body.replace(before, after) + block[stop:]
    return source[:start] + changed + source[end:]


def definitions_only(source):
    # Each checked lemma ends at its own qed line. No admits or proof skips.
    result, count = re.subn(r"(?ms)^lemma\b.*?^qed\.\n", "", source)
    if count != len(re.findall(r"(?m)^lemma\b", source)) or count == 0:
        raise ValueError("caller lemma boundary drift")
    if re.search(r"(?m)^(lemma|proof|qed)\b", result):
        raise ValueError("caller typecheck fixture retained a proof")
    return result


def caller_outputs(port):
    source = (port / "cdrafts-split/C10CallerInputBridge.ec").read_text()
    outputs = {port / "scratch/c10_caller_positive.ec": source}
    for name, module, proc, before, after, _ in CALLER_CHANGES:
        changed = mutate(source, module, proc, before, after)
        stem = "c10_caller_" + name.replace("-", "_")
        outputs[port / "scratch" / (stem + "_typed.ec")] = definitions_only(changed)
        outputs[port / "scratch" / (stem + "_reject.ec")] = changed
    return outputs


def caller_rows():
    rows = ["scratch/c10_caller_positive.ec\tMUST-PASS\t-"]
    for name, *_ in CALLER_CHANGES:
        stem = "scratch/c10_caller_" + name.replace("-", "_")
        rows.extend([stem + "_typed.ec\tMUST-PASS\t-",
                     stem + "_reject.ec\tMUST-FAIL\t" + CALLER_REASONS[name]])
    return rows
