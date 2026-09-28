# Accumulated adaptive signing responses

This milestone accounts for every successful response of the actual permitted
signing oracle in the manual classical C10 model. `ExposureSession` delegates
to `FullSession` and appends the returned `(message, signature)` only on success.
It records the structured response used by the unchanged byte adapter. Repeated
messages and signatures remain separate list entries. Refused or failed calls
append nothing; the original failure flag, counters and cap guards still apply.

The private observer makes no hash or private-derivation calls of its own.
`exposure_client_projection`, the driver/context projections and
`byte_exposure_game_projection` preserve the same client's results and state,
the common public/private oracle histories and the complete session state.
The client is restricted from reading observer state, just as it is restricted
from accessing the underlying session and oracle globals directly.
`byte_exposure_probability` proves equality of the original initialized byte
game's successful-forgery probability and the observed game's probability.
There is no substituted adversary and no smaller numerical bound here.

## Accumulated guarantee

`exposures_supported` quantifies over **every entry**, including multiple outputs
for one message. Every entry has the accepted H_msg record, its complete forest
reference and actual returned forest opening, and the complete lower subtree
reference for the top-layer message. These are the previously proved signing
references, accumulated through unconditional history extension. Failed calls
do not invalidate earlier entries. The final verifier preserves them as well.

`exposure_accounting` identifies the ledger's message projection with the actual
`FullSession.signed_messages` list, in order and with multiplicity. The number
of successful responses is at most the counted attempts, which are at most the
nonnegative signing cap. It does not equate successes with attempts or assume
that grinding succeeds. `byte_exposure_count` supplies these results after the
initialized adaptive byte game, even if the final result is false.

`logged_digest_references` joins the forest and subtree references on the same
accepted digest recorded for a logged message and returned randomizer. It
retains their distinct intermediate roots; it does not assert a newly proved
equality between the lower root of one reference and the upper reference.
`logged_fors_value` identifies literal returned ordinary components at trees
0 through 11 and the digest-selected index. `logged_special_root` separately
identifies component 12, which contains a complete tree root rather than an
ordinary private leaf. Each such logged value implies some complete forest
reference at that hypertree coordinate.

The contrapositive `absent_forest_excludes_logged_fors` requires **no complete
forest reference at any root for that coordinate**. Merely missing a reference
for one candidate root is insufficient. Neither statement says the value is
secret or unavailable through public queries, another coordinate, authentication
paths or other prior computations.

`byte_exposure_forgery_accounted` combines the ledger invariant with the existing
actual-verifier extraction. Its new-message guard now uses the exact ledger
projection. The original `res`, public collision/zero alternatives and all
missing-reference/private-opening cases remain explicit. The previous numerical
public collision, zero and prefix-query charges are unchanged and are not
reproved or reduced by this bookkeeping milestone.

## Evidence and remaining obligations

Nine selected modules have whole-file direct and default-CLI checks. Enrollment
pins every new statement and defined operator and preserves all existing
statement and assumption rows. Positive applications, repeated-message and
special-component examples, refused-call preservation, scope probes and
declared exact-application rejections accompany the sources. Rejection controls
are diagnostic checks, not proofs of premise necessity, falsity or complete-game
nonvacuity. The frozen candidate still requires the full cold two-driver gate
and bounded independent review before landing; its receipt records those results.

This closes accumulated **returned-output reference and count accounting**.
It does not close full adaptive information exposure, private preimage/guess
events, WOTS chain disclosure, encoding/ITSR event charges or a nontrivial
composed numerical forgery bound. A fresh message may reuse previously exposed
component coordinates or values. #100 and #295 remain open. No new project
axiom, admit, clone assumption, runtime, wire or parameter change is introduced.
Rust extraction, concrete SHA-256, QROM and production assurance remain separate;
the owner-triggered combined playbook pass #509 remains deferred.
