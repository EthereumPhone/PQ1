(* Complete actual-builder catalogs determine the returned authentication path. *)
require import AllCore List FMap.
require import C10RawOracle PathReplay NodeGridPath NodeCatalog NodeCatalogDomain.
require import CatalogPath CatalogForest AuthSlots AuthCaptureSchedule AuthPhase.

lemma builder_path h f c stack auth target total default :
  0 <= total => 0 <= target < 2^total =>
  catalog_exact c (2^total) => catalog_sound h f c =>
  map snd stack = [total] => forest_references c stack (2^total) =>
  slots_saved c auth target total (captured_full (2^total) target) =>
  path_recorded h f (catalog_grid c 0 target,0,target) auth /\
  (path_value h f (catalog_grid c 0 target,0,target) auth).`1 =
    (head (default,0) stack).`1.
proof.
  move=> hh ht hc hs hm hf ha.
  have hd : forall level, 0 <= level < total => captured_full (2^total) target level.
  + move=> level hl; rewrite /captured_full; exact (pair_capture_final total target level hl ht).
  have he := slots_saved_complete c auth target total _ hh ha hd.
  have hp := catalog_recorded_path h f c total target hh ht hc hs.
  have hr := forest_singleton_root c stack total default hh hm hf.
  smt().
qed.
