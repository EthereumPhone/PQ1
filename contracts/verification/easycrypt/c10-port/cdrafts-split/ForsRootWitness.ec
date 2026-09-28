(* Complete actual FORS catalogs provide references for later-selected leaves. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawFors RawForsPathReplay RawSignature PersistentGrind.
require import NodeCatalog NodeCatalogDomain NodeGridPath CatalogPath CatalogWidths StackPowers.
require import SecretLeafOrigins ForsPrivateLeaves ForsOpening RootCoverage.

op fors_root_witness h s seed ht tree root =
  exists c, catalog_exact c 2048 /\ catalog_sound h (fors_pair seed ht tree) c /\
    catalog_width c /\ secret_leaf_origins h s (fors_leaf_input seed ht tree)
      (fors_private_key ht tree) c /\ root=catalog_grid c 11 0.

lemma fors_root_witness_extends h h' s s' seed ht tree root :
  extends h h' => extends s s' => fors_root_witness h s seed ht tree root =>
  fors_root_witness h' s' seed ht tree root.
proof.
  move=> hh hs [c [hc [hcat [hw [ho hr]]]]].
  have hce := catalog_sound_extend h h' (fors_pair seed ht tree) c c hh (catalog_extension_refl c) hcat.
  have hop := secret_leaf_public_extends h h' s (fors_leaf_input seed ht tree) (fors_private_key ht tree) c hh ho.
  have hos := secret_leaf_private_extends h' s s' (fors_leaf_input seed ht tree) (fors_private_key ht tree) c hs hop.
  exists c; smt().
qed.

lemma fors_root_reference_at h s seed ht tree root target :
  fors_root_witness h s seed ht tree root => 0<=target<2048 =>
  exists sd auth, rows_width 11 auth /\ s.[fors_private_key ht tree target]=Some sd /\
    fors_opening h seed ht tree target (node sd) auth root.
proof.
  move=> [c [hc [hs [hw [ho hr]]]]] hi.
  have hi' : 0<=target<2^11 by smt(stack_pow2_11).
  have hc' : catalog_exact c (2^11) by smt(stack_pow2_11).
  have ha := complete_grid_auth_width c 11 target _ hi' hc' hw; first smt().
  have hp := catalog_recorded_path h (fors_pair seed ht tree) c 11 target _ hi' hc' hs; first smt().
  have [sd d [hpriv [hentry hleaf]]] := catalog_target_secret_origin h s
    (fors_leaf_input seed ht tree) (fors_private_key ht tree) c 11 target _ hi' hc' ho; first smt().
  exists sd (grid_auth (catalog_grid c) target 11).
  split; first exact ha.
  split; first exact hpriv.
  rewrite /fors_opening; split; first by move: ha; rewrite /rows_width; smt().
  exists d; smt().
qed.

lemma fors_root_witness_width h s seed ht tree root :
  fors_root_witness h s seed ht tree root => size root=16.
proof.
  move=> [c [hc [hs [hw [ho hr]]]]].
  have hm : (11,0) \in c by apply hc; rewrite /node_due /node_right_edge stack_pow2_11; smt().
  have he := get_some c (11,0) hm.
  move: hw; rewrite /catalog_width /catalog_grid; smt().
qed.
