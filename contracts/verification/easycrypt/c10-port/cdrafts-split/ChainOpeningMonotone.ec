(* Once the selected cut is opened, later oracle calls cannot clear that fact. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import ChainValueView ChainStageSampling CachedChainOracle RedactedChainOracle.

lemma observed_derive_opened :
  hoare [ChainObservedPrefix(Independent).derive : ChainRevelation.opened ==> ChainRevelation.opened].
proof. proc; inline Independent.derive; sp; if; auto; smt(). qed.
lemma redacted_derive_opened :
  hoare [RedactedChainPrefix.derive : ChainRedaction.opened ==> ChainRedaction.opened].
proof. proc; if; auto; call (_ : true); auto. qed.
lemma observed_concrete_opened :
  hoare [ConcreteChain(ChainObservedPrefix(Independent)).value : ChainRevelation.opened ==> ChainRevelation.opened].
proof.
  proc; inline RawWots(PreparationView(ChainObservedPrefix(Independent))).chain.
  wp; while ChainRevelation.opened.
  + wp; call (_ : true); auto.
  wp; inline PreparationView(ChainObservedPrefix(Independent)).wots; wp.
  call observed_derive_opened; auto.
qed.
lemma redacted_concrete_opened :
  hoare [ConcreteChain(RedactedChainPrefix).value : ChainRedaction.opened ==> ChainRedaction.opened].
proof.
  proc; inline RawWots(PreparationView(RedactedChainPrefix)).chain.
  wp; while ChainRedaction.opened.
  + wp; call (_ : true); auto.
  wp; inline PreparationView(RedactedChainPrefix).wots; wp.
  call redacted_derive_opened; auto.
qed.
lemma cached_value_opened :
  hoare [CachedChain.value : ChainRevelation.opened ==> ChainRevelation.opened].
proof. proc; if; first by auto; smt(). call observed_concrete_opened; auto. qed.
lemma redacted_value_opened :
  hoare [RedactedCachedChain.value : ChainRedaction.opened ==> ChainRedaction.opened].
proof. proc; if; first by if; auto. call redacted_concrete_opened; auto. qed.

lemma observed_derive_opened_sure :
  phoare [ChainObservedPrefix(Independent).derive : ChainRevelation.opened ==> ChainRevelation.opened] = 1%r.
proof.
  have [hh hd] := chain_observed_prefix_lossless Independent independent_hash_ll independent_derive_ll.
  conseq hd observed_derive_opened; smt().
qed.
lemma redacted_derive_opened_sure :
  phoare [RedactedChainPrefix.derive : ChainRedaction.opened ==> ChainRedaction.opened] = 1%r.
proof. conseq redacted_chain_derive_lossless redacted_derive_opened; smt(). qed.
lemma cached_value_opened_sure :
  phoare [CachedChain.value : ChainRevelation.opened ==> ChainRevelation.opened] = 1%r.
proof. conseq cached_chain_value_lossless cached_value_opened; smt(). qed.
lemma redacted_value_opened_sure :
  phoare [RedactedCachedChain.value : ChainRedaction.opened ==> ChainRedaction.opened] = 1%r.
proof. conseq redacted_chain_value_lossless redacted_value_opened; smt(). qed.
