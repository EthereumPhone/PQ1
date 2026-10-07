(* Count all hash and derive calls in the unchanged keygen, signer and verifier.
   Same loop accounting as the physical-cost proofs, instantiated at JointMemo. *)
require import AllCore List Distr IntDiv C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost KeygenExhaustion PreparedRaw C10Bytes PhysicalKeygenCost RoleGrindCost RadixEncoding RawShuffle RawWots RawFors RawMerkle RawWotsCost RawMerkleCost RawLayer RawForsCost RawForest RoleGrind RawForestCost RawLayerCost RawSigner RawSignerCost FullSession.
require import ProjectedBirthday JointMemoOracle.

lemma joint_view_hash_count c :
  hoare[PreparationView(JointMemo(ProjectedSamples)).hash : JointMemo.calls = c ==> JointMemo.calls = c+1].
proof. exact (joint_hash_count c). qed.

lemma joint_view_wots_count c :
  hoare[PreparationView(JointMemo(ProjectedSamples)).wots : JointMemo.calls = c ==> JointMemo.calls = c+1].
proof. proc; call (joint_derive_count c); auto. qed.

lemma leaf_joint_cost c :
  hoare[RawKeygen(PreparationView(JointMemo(ProjectedSamples))).leaf : JointMemo.calls = c ==>
    JointMemo.calls = c+345 /\ size res = 16].
proof.
  proc; call (joint_view_hash_count (c+344)); wp.
  while (0 <= i <= 43 /\ JointMemo.calls = c+8*i).
  + wp; while (0 <= j <= 7 /\ JointMemo.calls = c+8*i+1+j).
    - exists* i, j; elim* => i0 j0; wp.
      call (joint_view_hash_count (c+8*i0+1+j0)); auto; smt().
    wp; exists* i; elim* => i0; call (joint_view_wots_count (c+8*i0)); auto; smt().
  auto; smt(node_width).
qed.

lemma root_joint_cost c :
  hoare[RawKeygen(PreparationView(JointMemo(ProjectedSamples))).root : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+177151 /\ size res = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ JointMemo.calls = c+346*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ JointMemo.calls = c+346*kp+345-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (joint_view_hash_count (c+346*kp0+345-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (leaf_joint_cost (c+346*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma keygen_joint_cost c :
  hoare[KeygenPreparation(PreparationView(JointMemo(ProjectedSamples))).run : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+177151].
proof. proc; call (root_joint_cost c); auto; smt(). qed.

lemma shuffle_derive_joint_cost c :
  hoare[RawShuffle(PreparationView(JointMemo(ProjectedSamples))).derive : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+1].
proof. proc; sp 1; if.
  + wp; call (joint_view_hash_count c); auto; smt().
  auto; smt(). qed.

lemma shuffle_permutation_joint_cost c :
  hoare[RawShuffle(PreparationView(JointMemo(ProjectedSamples))).permutation : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+4].
proof.
  proc; sp 1; if; last by auto; smt().
  while (JointMemo.calls = c+4); first by auto.
  wp; while (0 <= blk <= 4 /\ JointMemo.calls = c+blk).
  + exists* blk; elim* => b; wp; call (joint_view_hash_count (c+b)); auto; smt().
  auto; smt().
qed.

lemma count_joint_cost c :
  hoare[RawWots(PreparationView(JointMemo(ProjectedSamples))).count : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+signing_budget].
proof.
  proc; while (0 <= i <= signing_budget /\ JointMemo.calls = c+i).
  + exists* i; elim* => i0; wp; call (joint_view_hash_count (c+i0)); auto; smt().
  auto; smt().
qed.

lemma chain_joint_cost c :
  hoare[RawWots(PreparationView(JointMemo(ProjectedSamples))).chain :
    JointMemo.calls = c /\ 0 <= start <= stop <= 7 ==>
    c <= JointMemo.calls <= c+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ JointMemo.calls = c+j-start).
  + exists* j, start; elim* => j0 s; wp; call (joint_view_hash_count (c+j0-s)); auto; smt().
  auto; smt().
qed.

lemma wots_sign_joint_cost c :
  hoare[RawWots(PreparationView(JointMemo(ProjectedSamples))).sign : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+signing_budget+348].
proof.
  proc; seq 1 : (c <= JointMemo.calls <= c+signing_budget).
  + call (count_joint_cost c); auto.
  sp 1; if; last by auto; smt().
  wp; seq 2 : (c <= JointMemo.calls <= c+signing_budget+4).
  + exists* JointMemo.calls; elim* => c0; call (shuffle_permutation_joint_cost c0); auto; smt().
  while (0 <= step <= 43 /\ c <= JointMemo.calls <= c+signing_budget+4+8*step).
  + seq 2 : (0 <= step < 43 /\ c <= JointMemo.calls <= c+signing_budget+4+8*step+1).
    - exists* JointMemo.calls; elim* => c0; call (joint_view_wots_count c0); auto; smt().
    wp; exists* JointMemo.calls; elim* => c0; call (chain_joint_cost c0); auto; smt(raw_digit_bounds).
  auto; smt().
qed.

lemma wots_recover_joint_cost c :
  hoare[RawWots(PreparationView(JointMemo(ProjectedSamples))).recover : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+303 /\ size res = 16].
proof.
  proc; seq 1 : (JointMemo.calls = c+1).
  + call (joint_view_hash_count c); auto.
  sp 1; if; last by auto; smt(size_nseq).
  seq 3 : (c+1 <= JointMemo.calls <= c+302).
  + while (0 <= i <= 43 /\ c+1 <= JointMemo.calls <= c+1+7*i).
    - wp; exists* JointMemo.calls; elim* => c1; call (chain_joint_cost c1); auto; smt(raw_digit_bounds).
    auto; smt().
  wp; exists* JointMemo.calls; elim* => c0; call (joint_view_hash_count c0); auto; smt(node_width).
qed.

lemma joint_view_fors_count c :
  hoare[PreparationView(JointMemo(ProjectedSamples)).fors : JointMemo.calls = c ==> JointMemo.calls = c+1].
proof. proc; call (joint_derive_count c); auto. qed.

lemma fors_tree_joint_cost c :
  hoare[RawFors(PreparationView(JointMemo(ProjectedSamples))).tree : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+6143 /\ size res.`1 = 16].
proof.
  proc; while (0 <= j <= 2048 /\ size stack <= j /\ (0 < j => stack <> []) /\
    valid_stack stack /\ JointMemo.calls = c+3*j-size stack).
  + wp; while (0 <= j < 2048 /\ size stack <= j /\ valid_stack stack /\
      size current = 16 /\ JointMemo.calls = c+3*j+2-size stack).
    - exists* j, stack; elim* => j0 st0.
      wp; call (joint_view_hash_count (c+3*j0+2-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* j, stack; elim* => j0 st0.
    call (joint_view_hash_count (c+3*j0+1-size st0)); wp.
    call (joint_view_fors_count (c+3*j0-size st0)); auto.
    rewrite /valid_stack /=; smt(node_width size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma fors_sign_joint_cost c :
  hoare[RawFors(PreparationView(JointMemo(ProjectedSamples))).sign : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+6144 /\ size res.`1 = 16].
proof.
  proc; call (fors_tree_joint_cost (c+1)); wp.
  call (joint_view_fors_count c); auto; smt(node_width).
qed.

lemma fors_root_joint_cost c :
  hoare[RawFors(PreparationView(JointMemo(ProjectedSamples))).root : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+6143 /\ size res = 16].
proof. proc; call (fors_tree_joint_cost c); auto. qed.

lemma fors_recover_joint_cost c :
  hoare[RawFors(PreparationView(JointMemo(ProjectedSamples))).recover : JointMemo.calls = c ==>
    JointMemo.calls = c+12 /\ size res = 16].
proof.
  proc; while (0 <= h <= 11 /\ JointMemo.calls = c+1+h /\ size current = 16).
  + exists* h; elim* => h0; wp; call (joint_view_hash_count (c+1+h0)); auto; smt(node_width).
  wp; call (joint_view_hash_count c); auto; smt(node_width).
qed.

lemma merkle_build_joint_cost c :
  hoare[RawMerkle(PreparationView(JointMemo(ProjectedSamples))).build : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+177151 /\ size res.`2 = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ JointMemo.calls = c+346*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ JointMemo.calls = c+346*kp+345-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (joint_view_hash_count (c+346*kp0+345-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (leaf_joint_cost (c+346*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma merkle_recover_joint_cost c :
  hoare[RawMerkle(PreparationView(JointMemo(ProjectedSamples))).recover : JointMemo.calls = c ==>
    JointMemo.calls = c+9 /\ size res = 16].
proof.
  proc; while (0 <= h <= 9 /\ JointMemo.calls = c+h /\ (0 < h => size current = 16)).
  + exists* h; elim* => h0; wp; call (joint_view_hash_count (c+h0)); auto; smt(node_width).
  auto; smt().
qed.

lemma layer_recover_joint_cost c :
  hoare[RawLayer(PreparationView(JointMemo(ProjectedSamples))).recover : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+312 /\ size res = 16].
proof.
  proc; seq 1 : (c <= JointMemo.calls <= c+303).
  + call (wots_recover_joint_cost c); auto; smt().
  exists* JointMemo.calls; elim* => z; call (merkle_recover_joint_cost z); auto; smt().
qed.

lemma layer_sign_joint_cost c :
  hoare[RawLayer(PreparationView(JointMemo(ProjectedSamples))).sign : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+signing_budget+177812].
proof.
  proc; seq 1 : (c <= JointMemo.calls <= c+177151).
  + call (merkle_build_joint_cost c); auto; smt().
  seq 1 : (c <= JointMemo.calls <= c+177152).
  + exists* JointMemo.calls; elim* => z; call (shuffle_derive_joint_cost z); auto; smt().
  seq 1 : (c <= JointMemo.calls <= c+signing_budget+177500).
  + exists* JointMemo.calls; elim* => z; call (wots_sign_joint_cost z); auto; smt().
  sp 1; if; last by auto; smt().
  wp; exists* JointMemo.calls; elim* => z; call (layer_recover_joint_cost z); auto; smt().
qed.

lemma forest_one_joint_cost c :
  hoare[RawForest(PreparationView(JointMemo(ProjectedSamples))).one : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+6156].
proof.
  proc; seq 1 : (c <= JointMemo.calls <= c+6144).
  + call (fors_sign_joint_cost c); auto; smt().
  exists* JointMemo.calls; elim* => z; call (fors_recover_joint_cost z); auto; smt().
qed.

lemma forest_sign_joint_cost c :
  hoare[RawForest(PreparationView(JointMemo(ProjectedSamples))).sign : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+80022 /\ size res.`3 = 16].
proof.
  proc; seq 5 : (c <= JointMemo.calls <= c+5).
  + seq 4 : (c <= JointMemo.calls <= c+1).
    - call (shuffle_derive_joint_cost c); auto.
    exists* JointMemo.calls; elim* => z; call (shuffle_permutation_joint_cost z); auto; smt().
  seq 2 : (c <= JointMemo.calls <= c+73877).
  + while (0 <= step <= 12 /\ c <= JointMemo.calls <= c+5+6156*step).
    - wp; exists* JointMemo.calls; elim* => z; call (forest_one_joint_cost z); auto; smt().
    auto; smt().
  seq 1 : (c <= JointMemo.calls <= c+80020).
  + exists* JointMemo.calls; elim* => z; call (fors_root_joint_cost z); auto; smt().
  seq 2 : (c <= JointMemo.calls <= c+80021).
  + exists* JointMemo.calls; elim* => z; call (joint_view_hash_count z); auto; smt().
  exists* JointMemo.calls; elim* => z; call (joint_view_hash_count z); auto; smt(node_width).
qed.

lemma forest_recover_joint_cost c :
  hoare[RawForest(PreparationView(JointMemo(ProjectedSamples))).recover : JointMemo.calls = c ==>
    JointMemo.calls = c+146 /\ size res = 16].
proof.
  proc; call (joint_view_hash_count (c+145)); wp; call (joint_view_hash_count (c+144)).
  while (0 <= t <= 12 /\ JointMemo.calls = c+12*t).
  + exists* t; elim* => t0; wp; call (fors_recover_joint_cost (c+12*t0)); auto; smt().
  auto; smt(node_width).
qed.

lemma role_grind_joint_cost c :
  hoare[RoleGrind(JointMemo(ProjectedSamples)).run : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+2*signing_budget].
proof.
  proc; while (0<=i<=signing_budget /\ JointMemo.calls=c+2*i).
  + exists* i; elim* => i0; wp; call (joint_hash_count (c+2*i0+1)).
    wp; call (joint_derive_count (c+2*i0)); auto; smt().
  auto; smt().
qed.

lemma signer_finish_joint_cost c :
  hoare[RawSigner(JointMemo(ProjectedSamples)).finish : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+2*signing_budget+435646].
proof.
  proc; seq 2 : (c <= JointMemo.calls <= c+80022).
  + call (forest_sign_joint_cost c); auto; smt().
  wp; while (0 <= layer <= 2 /\ c <= JointMemo.calls <= c+80022+layer*(signing_budget+177812)).
  + wp; exists* JointMemo.calls; elim* => z; call (layer_sign_joint_cost z); auto; smt().
  auto; rewrite /signing_budget; smt().
qed.

lemma signer_sign_joint_cost c :
  hoare[RawSigner(JointMemo(ProjectedSamples)).sign : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+4*signing_budget+435646].
proof.
  proc; seq 1 : (c <= JointMemo.calls <= c+2*signing_budget).
  + call (role_grind_joint_cost c); auto; smt().
  sp 1; if; last by auto; rewrite /signing_budget; smt().
  exists* JointMemo.calls; elim* => z; call (signer_finish_joint_cost z); auto; smt().
qed.

lemma signer_verify_joint_cost c :
  hoare[RawSigner(JointMemo(ProjectedSamples)).verify : JointMemo.calls = c ==>
    c <= JointMemo.calls <= c+771].
proof.
  proc; seq 1 : (JointMemo.calls = c+1).
  + call (joint_view_hash_count c); auto.
  sp 1; if; last by auto; smt().
  seq 2 : (JointMemo.calls = c+147).
  + call (forest_recover_joint_cost (c+1)); auto; smt().
  wp; while (0 <= layer <= 2 /\ c+147 <= JointMemo.calls <= c+147+312*layer).
  + wp; exists* JointMemo.calls; elim* => z; call (layer_recover_joint_cost z); auto; smt().
  auto; smt().
qed.

lemma full_client_joint_cost (A <: FullClient {-FullSession,-JointMemo,-ProjectedSamples}) q0 :
  hoare[A(FullSession(JointMemo(ProjectedSamples))).run :
    0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    JointMemo.calls <= q0+FullSession.raw_calls+FullSession.sign_calls*(4*signing_budget+435646) ==>
    0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    JointMemo.calls <= q0+FullSession.raw_calls+FullSession.sign_calls*(4*signing_budget+435646)].
proof.
  proc (0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    JointMemo.calls <= q0+FullSession.raw_calls+FullSession.sign_calls*(4*signing_budget+435646)) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* JointMemo.calls; elim* => z; call (joint_view_hash_count z); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* JointMemo.calls; elim* => z; call (signer_sign_joint_cost z); auto; smt().
qed.

lemma full_driver_joint_cost (A <: FullClient {-FullSession,-JointMemo,-ProjectedSamples}) q0 qr0 qs0 :
  0 <= qr0 => 0 <= qs0 =>
  hoare[FullDriver(A,JointMemo(ProjectedSamples)).run : qr = qr0 /\ qs = qs0 /\ JointMemo.calls <= q0 ==>
    JointMemo.calls <= q0+qr0+qs0*(4*signing_budget+435646)+771].
proof.
  move=> hqr hqs; proc; seq 2 : (JointMemo.calls <= q0+qr0+qs0*(4*signing_budget+435646)).
  + call (full_client_joint_cost A q0); inline FullSession(JointMemo(ProjectedSamples)).init;
    auto; rewrite /signing_budget; smt().
  sp 1; if; last by auto; smt().
  exists* JointMemo.calls; elim* => z; call (signer_verify_joint_cost z); auto; smt().
qed.

lemma full_context_joint_cost (A <: FullClient {-FullSession,-JointMemo,-ProjectedSamples,-FullLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[FullContext(A,JointMemo(ProjectedSamples)).run : FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs /\
    JointMemo.calls = 0 ==>
    JointMemo.calls <= 177151+qr+qs*(4*signing_budget+435646)+771].
proof.
  move=> hqr hqs; proc; call (full_driver_joint_cost A 177151 qr qs hqr hqs).
  call (keygen_joint_cost 0); auto; smt().
qed.
