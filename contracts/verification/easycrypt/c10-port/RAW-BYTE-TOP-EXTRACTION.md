# Top-layer extraction from the actual C10 byte game

`ByteGameTopExtraction.byte_game_top_extraction` now applies to the same
initialized `IndependentGame(ByteContext(A))` used by the existing byte-game
probability bounds. On success, its final public history contains a public-node
collision, contains a zero node, or supplies a new-message top-layer opening
against the actual key-generation root. The adversary retains its adaptive
public hash and signing interface. No reference-building oracle calls are added.

The bridge has four parts:

- `RootCoverage.root_reference_at` derives a WOTS key and nine-node reference
  path for every valid index from the existing complete root witness. The
  actual key-generation root already supplies that witness. The index can be
  chosen after key generation and after the adaptive session.
- `RootSessionHistory.full_client_root_preserved` retains that witness through
  arbitrary permitted hash and signing calls, including failed signing calls.
- `VerifierTopExtraction.verifier_extracts_top_opening` follows the actual
  two-layer verifier. Its result retains the message-hash input and accepted
  digest, the digest-derived top index, and the supplied top WOTS nodes and
  full-u32 count. The reference is selected from the existing keygen history.
- The session and byte-game theorems retain the actual new-message guard,
  exact signature widths, initial public seed, and final signed-message list.
  The byte/structured equivalence preserves the result and oracle/session
  state; it does not replace the client with a different attacker.

`ByteTopOpeningHop.byte_top_opening_hop` adds this proved structure to the
existing collision-free, zero-free successful-forgery residual. The public
collision, public zero and secret-prefix terms are unchanged, and all terms
refer to the same initialized client game. The residual still explicitly
contains `res`; it is not replaced with an assumption or assigned a numerical
probability.

The intermediate lower-tree value in `top_layer_opening` is existential.
This theorem does not yet extract a lower-layer or FORS opening, prove that a
WOTS opening was previously unexposed, or charge any such event. Honest
signatures also have top openings. The next obligations are to distinguish
new and previously signed component messages, descend to the lower layer and
FORS, account for adaptive accumulated openings, and bound private
preimage/guess and encoding events. No smaller numerical forgery bound follows
from this bridge alone. Issues #100 and #295 remain open.

The nine added modules are whole-file direct and default-interactive targets,
with statement/operator pins and source bindings. Nineteen controls comprise
six positives, five scope probes and eight rejected exact theorem applications. The
positive index examples check the concrete endpoints 0 and 511, rejection of
512 as a valid leaf index, and the maximum eighteen-bit index's two-layer
geometry. They do not demonstrate a complete nonvacuous forgery game. An
expected `exact` mismatch does not establish falsity or premise necessity.

No project axiom, admit, clone assumption, runtime behavior, byte format or
parameter is added or changed. This remains a manually written classical
ideal-oracle model. Rust extraction, concrete SHA-256, QROM and production
assurance remain separate boundaries.

The later [subtree bridge](RAW-SUBTREE-EXTRACTION.md) records both actual
recovery layers and conditionally descends to the lower WOTS opening. It keeps
an explicit unrecorded-top-message alternative and supplies no new numerical
charge; FORS and adaptive coverage remain open.
