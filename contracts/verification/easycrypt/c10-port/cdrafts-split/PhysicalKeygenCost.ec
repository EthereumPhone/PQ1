(* Every physical SHA-oracle call counts, including keyed WOTS derivations. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import KeygenExhaustion PreparedRaw.

lemma physical_hash_count c :
  hoare[PreparationView(Physical).hash : Shared.calls = c ==> Shared.calls = c+1].
proof.
  proc; exists* Shared.draws; elim* => d; call (hash_cost c d); auto.
qed.
lemma physical_wots_count c :
  hoare[PreparationView(Physical).wots : Shared.calls = c ==> Shared.calls = c+1].
proof.
  proc; inline Physical.derive; wp; exists* Shared.draws; elim* => d.
  call (hash_cost c d); auto.
qed.

lemma leaf_physical_cost c :
  hoare[RawKeygen(PreparationView(Physical)).leaf : Shared.calls = c ==>
    Shared.calls = c+345 /\ size res = 16].
proof.
  proc; call (physical_hash_count (c+344)); wp.
  while (0 <= i <= 43 /\ Shared.calls = c+8*i).
  + wp; while (0 <= j <= 7 /\ Shared.calls = c+8*i+1+j).
    - exists* i, j; elim* => i0 j0; wp.
      call (physical_hash_count (c+8*i0+1+j0)); auto; smt().
    wp; exists* i; elim* => i0; call (physical_wots_count (c+8*i0)); auto; smt().
  auto; smt(node_width).
qed.

lemma root_physical_cost c :
  hoare[RawKeygen(PreparationView(Physical)).root : Shared.calls = c ==>
    c <= Shared.calls <= c+177151 /\ size res = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ Shared.calls = c+346*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ Shared.calls = c+346*kp+345-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (physical_hash_count (c+346*kp0+345-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (leaf_physical_cost (c+346*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma keygen_physical_cost c :
  hoare[KeygenPreparation(PreparationView(Physical)).run : Shared.calls = c ==>
    c <= Shared.calls <= c+177151].
proof. proc; call (root_physical_cost c); auto; smt(). qed.

lemma keygen_and_grind_physical_cost :
  hoare[PreparedRawGame(KeygenPreparation).run : true ==>
    Shared.calls <= 177151+2*signing_budget].
proof.
  proc; seq 4 : (0 <= Shared.calls <= 177151).
  + call (keygen_physical_cost 0); inline Shared.init; auto.
  exists* Shared.calls, Shared.draws; elim* => c d.
  call (grind_cost c d); auto; smt().
qed.
