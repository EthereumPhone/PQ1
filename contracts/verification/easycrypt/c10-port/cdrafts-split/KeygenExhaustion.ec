(* Instantiation for the manually transcribed top-subtree key generation.
   Public input digest contributes its high 128 bits as pk_seed; all R and
   WOTS derivations use one freshly sampled 256-bit secret in PreparedRawGame. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid KeygenPrefixes PreparedRaw PreparedGrind.
require import RawKeygen RawKeygenCost GrindExhaustion.

module KeygenInputs = {
  var public_seed : digest
  var random, message : raw_input
}.
module KeygenPreparation (O : PreparationOracle) = {
  proc run() : raw_input * raw_input * raw_input * raw_input = {
    var seed, root;
    seed <- pad (node KeygenInputs.public_seed);
    root <@ RawKeygen(O).root(seed,1,0);
    return (KeygenInputs.random,KeygenInputs.message,seed,pad root);
  }
}.

lemma keygen_preparation_cost :
  hoare[KeygenPreparation(PreparationView(Independent)).run : Independent.queries = [] ==>
    size Independent.queries <= 155135 /\ size res.`3 = 32 /\ size res.`4 = 32].
proof.
  proc; call (root_public_cost 0); auto; smt(node_width size_cat size_nseq).
qed.

lemma keygen_preparation_lossless (V <: PreparationOracle {-KeygenPreparation}) :
  islossless V.hash => islossless V.wots => islossless V.fors =>
  islossless KeygenPreparation(V).run.
proof. move=> hh hw hf; proc; call (root_lossless V hh hw); auto. qed.

lemma keygen_then_shared_grind_exhaustion &m :
  Pr[PreparedRawGame(KeygenPreparation).run() @ &m : res] <=
    exhaustion_charge 155135 + (155135+signing_budget)%r * (1%r/2%r)^256.
proof.
  apply (prepared_raw_exhaustion KeygenPreparation 155135 &m) => //.
  + exact keygen_preparation_lossless.
  exact keygen_preparation_cost.
qed.
