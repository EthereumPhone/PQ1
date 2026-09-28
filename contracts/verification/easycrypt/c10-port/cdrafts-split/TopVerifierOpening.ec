(* This event retains the actual message-hash address and top WOTS signature.
   The intermediate lower-tree value is existential; no lower-tree extraction
   or probability bound is asserted here. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains RawKeygen RawForest RawSigner.
require import VerifierWotsOpening.

op top_layer_opening h s seed d (sig : raw_signature) =
  exists lower leaf,
    wots_verifier_opening h s seed 1 0 (hypertree_index d %/ 512) lower leaf
      ((nth ([],0,[]) sig.`4 1).`1,(nth ([],0,[]) sig.`4 1).`2).

op verified_top_opening h s seed root message (sig : raw_signature) =
  exists d, accept_digest d /\ h.[hmsg_input seed (pad root) (pad sig.`1) message]=Some d /\
    top_layer_opening h s seed d sig.
