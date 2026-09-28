require import AllCore List FMap IntDiv.
require import C10RawOracle RawFors NodeCatalog.
require import AuthCaptureValue AuthCaptureSchedule AuthSlots AuthSteps.

lemma canonical_auth_saved c auth target height parent lval current n total :
  0 <= height < total => 2^(height+1) %| n =>
  parent = (n-1) %/ (2^(height+1)) =>
  slots_saved c auth target total (fun level => pair_captured n height target level) =>
  (parent = target %/ (2^(height+1)) =>
    c.[(height,target_sibling target height)] =
      Some (selected_sibling target height parent lval current)) =>
  slots_saved c (canonical_auth auth target height parent lval current) target total
    (fun level => pair_captured n (height+1) target level).
proof.
  move=> hh hd hp hs hv.
  have hz : 0 <= height by smt().
  have he := pair_capture_matches n height target hz hd.
  case (parent = target %/ (2^(height+1))) => hc.
  + have he' : target_pair_edge target height = n by smt().
    have hval : c.[(height,target_sibling target height)] =
      Some (selected_sibling target height parent lval current) by smt().
    have hn := slots_saved_put c auth target total
      (fun level => pair_captured n height target level) height
      (selected_sibling target height parent lval current) hs hh hval.
    rewrite /canonical_auth ifT 1://.
    apply (slots_saved_equiv c (put auth height (selected_sibling target height parent lval current))
      target total (fun level => pair_captured n height target level \/ level = height)
      (fun level => pair_captured n (height+1) target level)) => //.
    smt(pair_capture_next).
  have he' : target_pair_edge target height <> n by smt().
  rewrite /canonical_auth ifF 1://.
  apply (slots_saved_equiv c auth target total
    (fun level => pair_captured n height target level)
    (fun level => pair_captured n (height+1) target level)) => //.
  smt(pair_capture_next).
qed.

lemma canonical_flags_match kept target height parent n total :
  0 <= height < total => 2^(height+1) %| n =>
  parent = (n-1) %/ (2^(height+1)) =>
  slots_flags kept total (fun level => pair_captured n height target level) =>
  slots_flags (canonical_flags kept target height parent) total
    (fun level => pair_captured n (height+1) target level).
proof.
  move=> hh hd hp hs.
  have hz : 0 <= height by smt().
  have he := pair_capture_matches n height target hz hd.
  case (parent = target %/ (2^(height+1))) => hc.
  + have he' : target_pair_edge target height = n by smt().
    have hn := slots_flags_put kept total
      (fun level => pair_captured n height target level) height hs hh.
    rewrite /canonical_flags hc /=.
    apply (slots_flags_equiv (put kept height true) total
      (fun level => pair_captured n height target level \/ level = height)
      (fun level => pair_captured n (height+1) target level)) => //.
    smt(pair_capture_next).
  have he' : target_pair_edge target height <> n by smt().
  rewrite /canonical_flags hc /=.
  apply (slots_flags_equiv kept total
    (fun level => pair_captured n height target level)
    (fun level => pair_captured n (height+1) target level)) => //.
  smt(pair_capture_next).
qed.
