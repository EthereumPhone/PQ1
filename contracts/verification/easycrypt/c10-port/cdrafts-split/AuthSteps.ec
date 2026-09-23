(* Pure expressions for the concrete authentication-array updates. *)
require import AllCore List IntDiv.
require import C10RawOracle RawFors DyadicStack NodeGridIndex.
require import AuthCaptureIndex AuthCaptureValue AuthCaptureSchedule AuthSlots.

op canonical_auth (auth : raw_input list) target height parent (lval current : raw_input) =
  if parent = target %/ (2^(height+1)) then
    put auth height (selected_sibling target height parent lval current)
  else auth.
op canonical_flags (kept : bool list) target height parent =
  if parent = target %/ (2^(height+1)) then put kept height true else kept.

op merkle_slots_step (auth : raw_input list) (kept : bool list)
    target height parent (lval current : raw_input) =
  if nth false kept height then (auth,kept) else
  if 2*parent = target_sibling target height then
    (put auth height lval,put kept height true) else
  if 2*parent+1 = target_sibling target height then
    (put auth height current,put kept height true) else (auth,kept).

op fors_slots_step (auth : raw_input list) target height parent (lval current : raw_input) =
  let sib = target_sibling target height in
  if sib %% 2 = 0 then
    if sib * 2^height = parent * 2^(height+1) then put auth height lval else auth
  else
    if sib * 2^height = parent * 2^(height+1)+2^height then put auth height current else auth.

lemma merkle_slots_canonical auth kept target height parent lval current n total :
  0 <= height < total => 2^(height+1) %| n =>
  parent = (n-1) %/ (2^(height+1)) =>
  slots_flags kept total (fun level => pair_captured n height target level) =>
  merkle_slots_step auth kept target height parent lval current =
    (canonical_auth auth target height parent lval current,
     canonical_flags kept target height parent).
proof.
  move=> hh hd hp hf.
  have hz : 0 <= height by smt().
  have ht := dyadic_index_step target height hz.
  have hm := sibling_pair_membership (target %/ (2^height)) parent.
  case (parent = target %/ (2^(height+1))) => hc.
  + have he := pair_capture_matches n height target hz hd.
    have he' : target_pair_edge target height = n by smt().
    have hk : !nth false kept height.
    - move: hf; rewrite /slots_flags /pair_captured; smt().
    rewrite /merkle_slots_step /canonical_auth /canonical_flags /selected_sibling /target_sibling;
      smt().
  rewrite /merkle_slots_step /canonical_auth /canonical_flags /selected_sibling /target_sibling;
    smt().
qed.

lemma fors_slots_canonical auth target height parent lval current :
  0 <= height =>
  fors_slots_step auth target height parent lval current =
    canonical_auth auth target height parent lval current.
proof.
  move=> hh.
  have hp := pow2_pos height hh.
  have hs := sibling_parent_cases (target %/ (2^height)).
  have hpar := sibling_index_parity (target %/ (2^height)).
  have ht := dyadic_index_step target height hh.
  have hpow : 2^(height+1) = 2*2^height by rewrite exprS.
  rewrite /fors_slots_step /canonical_auth /selected_sibling /target_sibling; smt().
qed.
