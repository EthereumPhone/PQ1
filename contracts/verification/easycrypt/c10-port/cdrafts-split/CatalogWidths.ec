(* Width evidence for every node retained by the actual tree observers. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWidths.
require import NodeCatalog NodeCatalogDomain MerkleCatalogObserver ForsCatalogObserver.
require import RawSignature AuthSlots AuthCaptureSchedule AuthPhase.

op catalog_width (c : node_catalog) =
  forall key value, c.[key] = Some value => size value = 16.

lemma catalog_width_empty : catalog_width empty.
proof. rewrite /catalog_width; smt(emptyE). qed.

lemma catalog_width_put c key value :
  catalog_width c => size value = 16 => catalog_width c.[key <- value].
proof. rewrite /catalog_width; smt(get_setE). qed.

lemma merkle_catalog_width (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots =>
  hoare [MerkleCatalogObserver(O).build : true ==> catalog_width res.`3].
proof.
  move=> hh hw; proc; while (catalog_width catalog).
  + wp; while (catalog_width catalog).
    - wp; call (_ : true ==> true); first by trivial.
      auto; smt(catalog_width_put node_width).
    wp; call (raw_leaf_width O hh hw).
    auto; smt(catalog_width_put).
  auto; smt(catalog_width_empty).
qed.

lemma fors_catalog_width (O <: PreparationOracle) :
  hoare [ForsCatalogObserver(O).tree : true ==> catalog_width res.`3].
proof.
  proc; while (catalog_width catalog).
  + wp; while (catalog_width catalog).
    - wp; call (_ : true ==> true); first by trivial.
      auto; smt(catalog_width_put node_width).
    wp; call (_ : true ==> true); first by trivial.
    wp; call (_ : true ==> true); first by trivial.
    auto; smt(catalog_width_put node_width).
  auto; smt(catalog_width_empty).
qed.

lemma catalog_leaf_width c total target :
  0 <= total => 0 <= target < 2^total =>
  catalog_exact c (2^total) => catalog_width c =>
  size (catalog_grid c 0 target) = 16.
proof.
  move=> hh ht hc hw.
  have hd := node_due_range total 0 target _ _; first 2 by smt().
  have hm : (0,target) \in c by apply hc.
  have he : c.[(0,target)] = Some (catalog_grid c 0 target)
    by rewrite /catalog_grid; smt(get_some).
  move: hw; rewrite /catalog_width; smt().
qed.

lemma catalog_auth_width c auth total target :
  0 <= total => 0 <= target < 2^total => catalog_width c =>
  slots_saved c auth target total (captured_full (2^total) target) =>
  rows_width total auth.
proof.
  move=> hh ht hw hp; move: hp; rewrite /slots_saved; move=> [hs ha].
  rewrite /rows_width hs /=.
  apply (all_nthP (fun x : raw_input => size x = 16) auth []).
  move=> level hl.
  have hd := pair_capture_final total target level _ ht; first by smt().
  have he := ha level _ _; first 2 by rewrite /captured_full; smt().
  move: hw; rewrite /catalog_width; smt().
qed.
