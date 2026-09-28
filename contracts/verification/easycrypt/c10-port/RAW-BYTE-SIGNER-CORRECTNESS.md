# Actual serialized-signature correctness

`ActualByteSignerCorrect.total_actual_byte_signer_correct` proves honest
total correctness through the actual structured signer and its byte codec.
The harness initializes the independent oracle, generates the top root,
signs with that root, encodes a returned signature, decodes those bytes,
and calls the actual verifier against the earlier padded root.

Every returned encoding is exactly 4,008 bytes with each element in [0,256),
and its parsed signature verifies. Grinding or WOTS count failure returns
`None`; the theorem does not replace bounded search with guaranteed success.
Termination is included in the probability-one statement.

## Exact codec and value premises

The encode-then-decode theorem requires the declared structured widths and
the four-byte count range. It proves the randomizer, all FORS secrets and
authentication rows, and both 836-byte layer blocks are recovered exactly.
It complements the earlier decode-then-encode result for valid byte strings.

Actual node/chain/tree/forest/layer signing supplies byte-valued components,
even for the model's totalized off-support digest inputs. Actual count search
supplies its count range. The independent oracle preserves initialized,
256-bit-valued memo tables, which supplies the grinder's 16-byte randomizer
width. The fresh harness discharges that table premise itself.

The existing retained-opening results identify the signature's accepting
H_msg digest and its forest/layer trace. Encoding and decoding do not change
that witness; the verifier reaches the earlier key-generation root.

## Boundary

This is a theorem about the independent-oracle manual model and exact codec.
It is not Rust extraction or a theorem about concrete SHA-256. The [shared-oracle transfer](RAW-PHYSICAL-HONEST-CORRECTNESS.md) now
bounds the physical honest-error event. The adaptive unforgeability reduction
remains separate. There is no QROM or numerical end-to-end forgery claim.
The broader remaining work is tracked under #100/#295; the owner-triggered
combined playbook pass #509 stays deferred.
