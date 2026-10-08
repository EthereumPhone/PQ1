(* Historical openings identify the same chain values in the final memo tables. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle RawKeygen RawWots RawCountRecorded.
require import PersistentGrind LinearChain RawChainTrace WotsReference WotsChainSplit.
require import WotsReferenceRoot WotsSignatureValue WotsSignWitness LayerSignOpening.

lemma wots_partial_extends h h' s s' seed layer tree kp i cut :
  extends h h' => extends s s' => wots_prefix h s seed layer tree kp 43 =>
  0<=i<43 => 0<=cut<=7 =>
  wots_partial h' s' seed layer tree kp i cut=wots_partial h s seed layer tree kp i cut.
proof.
  move=> hh hs hp hi hc.
  have [hk hr] := hp i hi.
  have hstart := wots_start_extends s s' layer tree kp i hs hk.
  have [hprefix htail] := wots_reference_split h s seed layer tree kp i cut hp hi hc.
  have [hrecord he] := linear_recorded_extends h h' (chain_input seed layer tree kp i)
    (wots_start s layer tree kp i) (range 0 cut) hh hprefix.
  by rewrite /wots_partial hstart.
qed.

lemma wots_signature_extends h h' s s' seed layer tree kp d sigma :
  extends h h' => extends s s' => wots_prefix h s seed layer tree kp 43 =>
  wots_signature h s seed layer tree kp d sigma => wots_signature h' s' seed layer tree kp d sigma.
proof.
  move=> hh hs hp [hw hv]; split; first exact hw.
  move=> i hi; rewrite (wots_partial_extends h h' s s' seed layer tree kp i (digit 3 d i) hh hs hp hi).
  + exact (raw_digit_bounds d i).
  exact (hv i hi).
qed.

lemma wots_opening_extends h h' s s' seed layer tree kp message root signature :
  extends h h' => extends s s' => wots_opening h s seed layer tree kp message root signature =>
  wots_opening h' s' seed layer tree kp message root signature.
proof.
  move=> hh hs [hr [hc [d [ha [hd hw]]]]].
  have hp : wots_prefix h s seed layer tree kp 43 by move: hr; rewrite /wots_root; smt().
  have hr' := wots_root_extends h h' s s' seed layer tree kp root hh hs hr.
  have hw' := wots_signature_extends h h' s s' seed layer tree kp d signature.`1 hh hs hp hw.
  rewrite /wots_opening; split; first exact hr'.
  split; first exact hc.
  exists d; move: hh; rewrite /extends; smt().
qed.

lemma layer_current_wots_opening h s seed layer tree kp message signature root :
  layer_opening h s seed layer tree kp message signature root =>
  exists leaf, wots_opening h s seed layer tree kp message leaf (signature.`1,signature.`2).
proof.
  move=> [leaf h0 s0 [ho [hs [hh hp]]]]; exists leaf.
  exact (wots_opening_extends h0 h s0 s seed layer tree kp message leaf _ hh hs ho).
qed.

lemma wots_same_digest_signature h s seed layer tree kp d sigma sigma' :
  wots_signature h s seed layer tree kp d sigma =>
  wots_signature h s seed layer tree kp d sigma' => sigma=sigma'.
proof.
  move=> [hs hv] [hs' hv']; apply (eq_from_nth (nseq 16 0)); first smt().
  move=> i hi; smt().
qed.
