(* Actual native search callers consume the same generated first-hit selectors
   as the extracted Rust endpoints, under the disclosed backend interpretation.
   All state is equal across callers, and the queried prefix/cost is exact.
   These are paired functional endpoints, not a cross-kernel session theorem. *)
require import AllCore List FMap.
require import C10Representation C10RawOracle C10Counter RawWots RoleGrind KeygenPrefixes.
require import C10CallerInputBridge C10SearchAcceptance C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWots C10FunctionalFors.

lemma raw_wots_fixed_lossless :
  islossless RawWots(PreparationView(FixedPrefix)).count.
proof. exact (raw_count_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.

lemma role_nonce_fixed_lossless : islossless RoleGrind(FixedPrefix).run.
proof.
  proc; while true (signing_budget-i).
  + move=> z; wp; call fixed_hash_ll; wp; call fixed_derive_ll; auto; smt().
  auto; smt().
qed.

lemma raw_wots_functional_selector f h c seed0 layer0 tree0 kp0 message0 :
  equiv[RawWots(PreparationView(FixedPrefix)).count ~
        PairedAcceptanceWots(PreparationView(FixedPrefix)).count :
    ={seed,layer,tree,kp,message,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ kp{1} = kp0 /\ message{1} = message0 /\
    caller_fields layer0 tree0 kp0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    let slot = wots_first_slot (functional_wots_digests f seed0 layer0 tree0 kp0 message0) in
    let steps = if slot = 0 then signing_budget else slot in
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+steps /\
    FixedBackend.history{1} = backend_history f h
      (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) steps) /\
    res{1} = (if slot = 0 then None else Some (slot-1,
      f (functional_wots_query seed0 layer0 tree0 kp0 message0 (slot-1))))].
proof.
  conseq (raw_fixed_wots_paired f) (_ : true ==> true)
    (fixed_wots_selector f h c seed0 layer0 tree0 kp0 message0) => //; smt().
qed.

lemma role_nonce_functional_selector f h c key0 random0 message0 seed0 root0 :
  equiv[RoleGrind(FixedPrefix).run ~ PairedAcceptanceGrind(FixedPrefix).run :
    ={random,message,seed,root,glob FixedPrefix} /\
    random{1} = random0 /\ message{1} = message0 /\ seed{1} = seed0 /\ root{1} = root0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    let slot = fors_first_slot (functional_fors_digests f key0 random0 message0 seed0 root0) in
    let steps = if slot = 0 then signing_budget else slot in
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\ FixedBackend.calls{1} = c+2*steps /\
    FixedBackend.history{1} = functional_fors_history f h key0 random0 message0 seed0 root0 steps /\
    res{1} = (if slot = 0 then None else Some (functional_randomizer f key0 random0 message0 (slot-1),
      f (functional_fors_query f key0 random0 message0 seed0 root0 (slot-1))))].
proof.
  conseq (role_fixed_nonce_paired f) (_ : true ==> true)
    (fixed_fors_selector f h c key0 random0 message0 seed0 root0) => //; smt().
qed.
