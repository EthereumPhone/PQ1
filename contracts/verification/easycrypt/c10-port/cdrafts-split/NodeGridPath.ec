(* Recorded parent hashes imply a complete bottom-up path witness.
   Supplying this grid from the actual builder remains a separate obligation. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawFors PathReplay NodeGridIndex.

type node_grid = int -> int -> raw_input.

op grid_link (h : (raw_input,digest) fmap)
  (f : int -> int -> raw_input -> raw_input -> raw_input)
  (c : node_grid) level index =
  exists d, h.[f (level+1) (index %/ 2)
    (c level (2*(index %/ 2))) (c level (2*(index %/ 2)+1))] = Some d /\
    c (level+1) (index %/ 2) = node d.

op grid_recorded h f (c : node_grid) total =
  forall level index, 0 <= level < total =>
    0 <= index < 2^(total-level) => grid_link h f c level index.

op grid_auth (c : node_grid) target length =
  mkseq (fun height => c height (sibling_index (target %/ (2^height)))) length.

lemma grid_path_step h f (c : node_grid) level index :
  grid_link h f c level index =>
  exists d,
    h.[path_input f (c level index,level,index) (c level (sibling_index index))] = Some d /\
    c (level+1) (index %/ 2) = node d.
proof.
  rewrite /grid_link /path_input /sibling_index /=.
  move=> [d [hd hv]]; exists d.
  case (index %% 2 = 0) => he.
  + have hi := child_index_even index he; smt().
  have hi := child_index_odd index he; smt().
qed.

lemma grid_auth_zero c target : grid_auth c target 0 = [].
proof. by rewrite /grid_auth mkseq0. qed.

lemma grid_auth_next c target length :
  0 <= length => grid_auth c target (length+1) =
    rcons (grid_auth c target length)
      (c length (sibling_index (target %/ (2^length)))).
proof. by move=> hn; rewrite /grid_auth mkseqS. qed.

lemma grid_recorded_prefix h f c total target length :
  0 <= length <= total => 0 <= target < 2^total =>
  grid_recorded h f c total =>
  path_recorded h f (c 0 target,0,target) (grid_auth c target length) /\
  path_value h f (c 0 target,0,target) (grid_auth c target length) =
    (c length (target %/ (2^length)),length,target %/ (2^length)).
proof.
  move=> [hl hlt] ht hg.
  elim: length hl hlt => [|length hl ih] hlt.
  + by rewrite grid_auth_zero /path_recorded /path_value /= expr0 divz1.
  have [hr hv] := ih _; first by smt().
  have hi := dyadic_index_range target length total _ ht; first by smt().
  have hx : grid_link h f c length (target %/ (2^length))
    by apply hg; smt().
  have [d [hd hc]] := grid_path_step h f c length (target %/ (2^length)) hx.
  have hs := path_recorded_step h f (c 0 target,0,target)
    (grid_auth c target length)
    (c length (sibling_index (target %/ (2^length)))) d
    (c length (target %/ (2^length)),length,target %/ (2^length)) hr hv hd.
  rewrite grid_auth_next 1:hl dyadic_index_step 1:hl.
  smt().
qed.

lemma grid_recorded_path h f c total target :
  0 <= total => 0 <= target < 2^total =>
  grid_recorded h f c total =>
  path_recorded h f (c 0 target,0,target) (grid_auth c target total) /\
  (path_value h f (c 0 target,0,target) (grid_auth c target total)).`1 = c total 0.
proof.
  move=> hh ht hg.
  have hp := grid_recorded_prefix h f c total target total _ ht hg; first by smt().
  have hz : target %/ (2^total) = 0 by apply pdiv_small.
  smt().
qed.
