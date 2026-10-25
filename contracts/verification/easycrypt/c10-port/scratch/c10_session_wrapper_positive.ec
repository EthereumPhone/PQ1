require import AllCore List FMap C10RawOracle RawSigner RawSignature RawWrapper C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge C10FunctionalWotsValue C10FunctionalSigner C10FunctionalSignerBytes C10FunctionalVerifier C10FunctionalVerifierState C10FunctionalCalls.

(* Exact fixed-backend wrapper values and executed-prefix effects. The
   environmental readiness/final guard remain abstract; a refusal is not an
   absorbing session failure. No physical call-cost or fault claim is made. *)






op paired_wrapper_result (fn : raw_input -> raw_input) (key seed root random message : raw_input)
    (ready guard : bool) =
  let signed = paired_signer_result fn key seed root random message in
  if ready /\ signed <> None /\ guard /\ paired_verifier_result fn seed root message (oget signed)
  then signed else None.
op functional_wrapper_cost (f : raw_input -> digest) (key seed root random message sha shb : raw_input)
    (ready : bool) =
  if !ready then 0 else
    functional_signer_cost f key seed root random message sha +
    (if paired_signer_result (interpreted_backend f) key seed root random message = None then 0 else
      functional_signer_cost f key seed root random message shb +
      functional_verifier_cost f seed root message
        (oget (paired_signer_result (interpreted_backend f) key seed root random message))).
op functional_wrapper_state (f : raw_input -> digest) (initial final : (raw_input,digest) fmap)
    (key seed root random message sha shb : raw_input) (ready : bool) =
  if !ready then final = initial else
    exists first,
      functional_signer_state f initial first key seed root random message sha /\
      (if paired_signer_result (interpreted_backend f) key seed root random message = None
       then final = first else
         exists second, functional_signer_state f first second key seed root random message shb /\
           final = functional_verifier_history f second seed root message
             (oget (paired_signer_result (interpreted_backend f) key seed root random message))).

lemma functional_signature_counters sig : signature_width sig => outer_counters sig.
proof.
  move=> hw; have hn : size sig.`4 = 2 by move: hw; rewrite /signature_width; smt().
  have ha : all layer_width sig.`4 by move: hw; rewrite /signature_width; smt().
  rewrite /outer_counters; move=> i hi.
  have hl : layer_width (nth ([],0,[]) sig.`4 i) by smt(allP mem_nth).
  move: hl; rewrite /layer_width; smt().
qed.

lemma fixed_functional_wrapper f h c key0 seed0 root0 random0 message0 sha0 shb0 ready0 guard0 :
  hoare[RawWrapper(FixedPrefix).sign :
    seed = seed0 /\ root = root0 /\ random = random0 /\ message = message0 /\
      shuffle_a = sha0 /\ shuffle_b = shb0 /\ ready = ready0 /\ final_guard = guard0 /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_width f /\
      backend_consistent FixedBackend.history f /\ FixedBackend.history = h /\ FixedBackend.calls = c ==>
    res = paired_wrapper_result (interpreted_backend f) key0 seed0 root0 random0 message0 ready0 guard0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c + functional_wrapper_cost f key0 seed0 root0 random0 message0 sha0 shb0 ready0 /\
    functional_wrapper_state f h FixedBackend.history key0 seed0 root0 random0 message0 sha0 shb0 ready0].
proof.
  proc; sp 1; if.
  + seq 1 : (seed = seed0 /\ root = root0 /\ random = random0 /\ message = message0 /\
      shuffle_a = sha0 /\ shuffle_b = shb0 /\ ready = ready0 /\ final_guard = guard0 /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_width f /\
      backend_consistent FixedBackend.history f /\ ready0 /\ result = None /\
      first = paired_signer_result (interpreted_backend f) key0 seed0 root0 random0 message0 /\
      (first <> None => outer_counters (oget first)) /\
      FixedBackend.calls = c + functional_signer_cost f key0 seed0 root0 random0 message0 sha0 /\
      functional_signer_state f h FixedBackend.history key0 seed0 root0 random0 message0 sha0).
    - call (fixed_signer_call f h c key0 seed0 root0 random0 message0 sha0);
        auto; smt(functional_signature_counters).
    exists* FixedBackend.history; elim* => h1.
    if.
    - seq 1 : (seed = seed0 /\ root = root0 /\ random = random0 /\ message = message0 /\
      shuffle_a = sha0 /\ shuffle_b = shb0 /\ ready = ready0 /\ final_guard = guard0 /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_width f /\
      backend_consistent FixedBackend.history f /\ ready0 /\ result = None /\
        first = paired_signer_result (interpreted_backend f) key0 seed0 root0 random0 message0 /\ second = first /\ first <> None /\ outer_counters (oget first) /\
        FixedBackend.calls = c + functional_signer_cost f key0 seed0 root0 random0 message0 sha0 + functional_signer_cost f key0 seed0 root0 random0 message0 shb0 /\
        functional_signer_state f h h1 key0 seed0 root0 random0 message0 sha0 /\ functional_signer_state f h1 FixedBackend.history key0 seed0 root0 random0 message0 shb0).
      + call (fixed_signer_call f h1 (c+functional_signer_cost f key0 seed0 root0 random0 message0 sha0) key0 seed0 root0 random0 message0 shb0); auto; smt().
      if; last by auto => />; rewrite /paired_wrapper_result /functional_wrapper_cost /functional_wrapper_state; smt().
      exists* FixedBackend.history; elim* => h2.
      wp; call (fixed_verifier_call f h2 (c+functional_signer_cost f key0 seed0 root0 random0 message0 sha0+functional_signer_cost f key0 seed0 root0 random0 message0 shb0)
        key0 seed0 root0 message0 (oget (paired_signer_result (interpreted_backend f) key0 seed0 root0 random0 message0))).
      auto => />; rewrite /paired_wrapper_result /functional_wrapper_cost /functional_wrapper_state; smt().
    auto => />; rewrite /paired_wrapper_result /functional_wrapper_cost /functional_wrapper_state; smt().
  auto => />; rewrite /paired_wrapper_result /functional_wrapper_cost /functional_wrapper_state; smt().
qed.

lemma fixed_functional_wrapper_lossless : islossless RawWrapper(FixedPrefix).sign.
proof.
  proc; sp 1; if; last by auto.
  seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call raw_functional_signer_lossless; auto.
  if; last by auto.
  seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call raw_functional_signer_lossless; auto.
  if; auto; wp; call raw_functional_verifier_lossless; auto.
qed.
