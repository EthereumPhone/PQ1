(* Distinct selected table keys require distinct pool indices, including when
   their digests agree. No independence of adaptively selected keys is assumed. *)
require import AllCore List FMap.
require import C10RawOracle RawWots WotsCountDomain SelectedWotsCollision.
require import AcceptedEncodingPool WotsPoolRecords.

lemma accepted_encoding_unique_nth nodes :
  uniq (accepted_encoding_words nodes) =>
  forall i j, 0<=i<size nodes => 0<=j<size nodes =>
    count_accepts (nth [] nodes i) => count_accepts (nth [] nodes j) =>
    raw_digits (nth [] nodes i)=raw_digits (nth [] nodes j) => i=j.
proof.
  elim: nodes => [|d ds ih].
  + by rewrite /=; smt().
  move=> hu.
  have hut : uniq (accepted_encoding_words ds).
  + move: hu; rewrite /accepted_encoding_words /=.
    case (count_accepts d); smt().
  have hhead : count_accepts d => !mem (accepted_encoding_words ds) (raw_digits d).
  + move: hu; rewrite /accepted_encoding_words /=.
    case (count_accepts d); smt().
  move=> i j hi hj ha hb he.
  case (i=0) => hi0; case (j=0) => hj0; first smt().
  + have hd : count_accepts d by move: ha; rewrite hi0 /=.
    have hm : mem (accepted_encoding_words ds) (raw_digits d).
    - rewrite accepted_encoding_member 1:hd; apply/List.hasP.
      exists (nth [] ds (j-1)); split; first apply mem_nth; smt(size_ge0).
      move: he; rewrite hi0 /= (: j<>0) 1:hj0 /=; smt().
    smt().
  + have hd : count_accepts d by move: hb; rewrite hj0 /=.
    have hm : mem (accepted_encoding_words ds) (raw_digits d).
    - rewrite accepted_encoding_member 1:hd; apply/List.hasP.
      exists (nth [] ds (i-1)); split; first apply mem_nth; smt(size_ge0).
      move: he; rewrite hj0 /= (: i<>0) 1:hi0 /=; smt().
    smt().
  have ht := ih hut (i-1) (j-1).
  move: ha hb he ht; rewrite /=; smt().
qed.

lemma selected_collision_in_pool h keys nodes :
  wots_accepted_records h keys nodes => selected_accepted_collision h =>
  accepted_encoding_pool_collision nodes.
proof.
  move=> [hs hr] [x y d e [hxy [hx [hy [hd [he [ha [hb hw]]]]]]]].
  have [i [hi [hki hni]]] := hr x d hx ha hd.
  have [j [hj [hkj hnj]]] := hr y e hy hb he.
  rewrite /accepted_encoding_pool_collision; case (uniq (accepted_encoding_words nodes))=> hu; last by [].
  have hij := accepted_encoding_unique_nth nodes hu i j hi hj.
  smt().
qed.
