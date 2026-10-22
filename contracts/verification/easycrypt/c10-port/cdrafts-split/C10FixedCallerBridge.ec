(* The existing actual EasyCrypt callers retain their entire oracle state
   under the fixed-backend interpretation. This does not couple that backend
   to the sampled Shared oracle or transfer its probability bounds. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter C10RawGrind C10Bytes RawWots RoleGrind.
require import KeygenPrefixes C10CallerInputBridge C10SearchAcceptance.
require import C10FixedBackend.

op backend_width (f : raw_input -> digest) = forall x, size (f x) = 256.

lemma backend_width_witness : backend_width (fun (_ : raw_input) => nseq 256 false).
proof. by rewrite /backend_width => x; rewrite size_nseq. qed.

lemma fixed_hash_width f :
  hoare[FixedBackend.hash :
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ backend_width f ==>
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ size res = 256].
proof.
  proc; sp 1; if; auto => />; rewrite /backend_consistent /backend_width;
    smt(get_setE get_set_sameE domE).
qed.

lemma fixed_hash_paired f :
  equiv[FixedBackend.hash ~ FixedBackend.hash :
    ={x,glob FixedBackend} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\ backend_width f ==>
    ={res,glob FixedBackend} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\ size res{1} = 256].
proof.
  conseq (_ : ={x,glob FixedBackend} ==> ={res,glob FixedBackend})
    (fixed_hash_width f) (fixed_hash_width f) => //.
  by sim.
qed.

lemma fixed_derive_paired f :
  equiv[FixedPrefix.derive ~ FixedPrefix.derive :
    ={tail,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\ backend_width f ==>
    ={res,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\ size res{1} = 256].
proof. proc; call (fixed_hash_paired f); auto. qed.

lemma fixed_wots_paired f :
  equiv[CommonInputWots(PreparationView(FixedPrefix)).count ~
        PairedAcceptanceWots(PreparationView(FixedPrefix)).count :
    ={seed,layer,tree,kp,message,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\ backend_width f ==>
    ={res,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc; while (={seed,layer,tree,kp,message,i,result,glob FixedPrefix} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\ backend_width f).
  + wp; call (fixed_hash_paired f); auto => /> *.
    by rewrite wots_accept_bits.
  by auto.
qed.

lemma fixed_nonce_paired f :
  equiv[CommonInputGrind(FixedPrefix).run ~ PairedAcceptanceGrind(FixedPrefix).run :
    ={random,message,seed,root,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\ backend_width f ==>
    ={res,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  proc; while (={random,message,seed,root,i,result,glob FixedPrefix} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\ backend_width f).
  + wp; call (fixed_hash_paired f); wp; call (fixed_derive_paired f).
    auto => /> *; by rewrite fors_accept_bits.
  by auto.
qed.

lemma raw_fixed_wots_paired f :
  equiv[RawWots(PreparationView(FixedPrefix)).count ~
        PairedAcceptanceWots(PreparationView(FixedPrefix)).count :
    ={seed,layer,tree,kp,message,glob FixedPrefix} /\ caller_fields layer{1} tree{1} kp{1} /\
    FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\ backend_width f ==>
    ={res,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  transitivity CommonInputWots(PreparationView(FixedPrefix)).count
    (={seed,layer,tree,kp,message,glob FixedPrefix} /\ caller_fields layer{1} tree{1} kp{1}
      ==> ={res,glob FixedPrefix})
    (={seed,layer,tree,kp,message,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
      backend_consistent FixedBackend.history{1} f /\ backend_width f ==>
      ={res,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f) => //.
  + smt().
  + exact (caller_wots_count (PreparationView(FixedPrefix))).
  exact (fixed_wots_paired f).
qed.

lemma role_fixed_nonce_paired f :
  equiv[RoleGrind(FixedPrefix).run ~ PairedAcceptanceGrind(FixedPrefix).run :
    ={random,message,seed,root,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f /\ backend_width f ==>
    ={res,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
    backend_consistent FixedBackend.history{1} f].
proof.
  transitivity CommonInputGrind(FixedPrefix).run
    (={random,message,seed,root,glob FixedPrefix} ==> ={res,glob FixedPrefix})
    (={random,message,seed,root,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
      backend_consistent FixedBackend.history{1} f /\ backend_width f ==>
      ={res,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f) => //.
  + smt().
  + exact (caller_nonce_grind FixedPrefix).
  exact (fixed_nonce_paired f).
qed.
