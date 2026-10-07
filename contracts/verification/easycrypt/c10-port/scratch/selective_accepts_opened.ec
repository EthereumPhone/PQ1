require import AllCore List Distr.
require import C10RawOracle C10Randomizer PrefixGuess RawKeygen LeafCommitmentHybrid LeafOpeningBound SelectiveHidingControls.
module OpenedGuessControl (A : LeafOpeningContext) = {
  proc run() : bool = {
    var key, outputs;
    key <$ full_digest; LeafCommitmentReal.key <- node key;
    RealLeafOpening.revealed <- false;
    Shared.init(); outputs <@ A(RealLeafOpening).run();
    return mem outputs (node key);
  }
}.
lemma opened_candidate_must_reject :
  hoare [OpenedGuessControl(RevealCandidate).run : true ==> !res].
proof.
  proc; inline RevealCandidate(RealLeafOpening).run RealLeafOpening.reveal Shared.init; by auto.
qed.
