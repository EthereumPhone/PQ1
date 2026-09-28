(* Persistent proof catalog of actual leaf values and recorded parent hashes. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen PersistentGrind NodeGridPath.

type node_catalog = (int * int, raw_input) fmap.
op catalog_grid (c : node_catalog) level index = oget c.[(level,index)].
op catalog_extends (c c' : node_catalog) =
  forall key, key \in c => c'.[key] = c.[key].

op catalog_link (h : (raw_input,digest) fmap) f (c : node_catalog) level index =
  exists left right d,
    c.[(level-1,2*index)] = Some left /\
    c.[(level-1,2*index+1)] = Some right /\
    h.[f level index left right] = Some d /\
    c.[(level,index)] = Some (node d).

op catalog_sound h f (c : node_catalog) =
  forall level index, (level,index) \in c =>
    0 <= level /\ 0 <= index /\
    (level = 0 \/ catalog_link h f c level index).

lemma catalog_extension_refl c : catalog_extends c c.
proof. by rewrite /catalog_extends. qed.

lemma catalog_extension_fresh c key value :
  key \notin c => catalog_extends c c.[key <- value].
proof. rewrite /catalog_extends; smt(get_setE). qed.

lemma catalog_link_extends h h' f c c' level index :
  extends h h' => catalog_extends c c' => catalog_link h f c level index =>
  catalog_link h' f c' level index.
proof.
  rewrite /extends /catalog_extends /catalog_link.
  move=> he ce hc; elim hc => l0 r0 d hd.
  exists l0 r0 d; smt(domE).
qed.

lemma catalog_sound_extend h h' f c c' :
  extends h h' => catalog_extends c c' => catalog_sound h f c =>
  forall level index, (level,index) \in c =>
    0 <= level /\ 0 <= index /\
    (level = 0 \/ catalog_link h' f c' level index).
proof. rewrite /catalog_sound; smt(catalog_link_extends). qed.

lemma catalog_sound_empty h f : catalog_sound h f empty.
proof. by rewrite /catalog_sound; smt(mem_empty). qed.

lemma catalog_sound_insert h h' f c level index value :
  extends h h' => catalog_sound h f c => (level,index) \notin c =>
  0 <= level => 0 <= index =>
  (level = 0 \/ catalog_link h' f c.[(level,index) <- value] level index) =>
  catalog_sound h' f c.[(level,index) <- value].
proof.
  move=> he hs hf hl hi hn.
  have hc := catalog_extension_fresh c (level,index) value hf.
  have ho := catalog_sound_extend h h' f c c.[(level,index) <- value] he hc hs.
  rewrite /catalog_sound; smt(mem_set).
qed.

lemma catalog_sound_history_extends h h' f c :
  extends h h' => catalog_sound h f c => catalog_sound h' f c.
proof.
  move=> he hs.
  exact (catalog_sound_extend h h' f c c he (catalog_extension_refl c) hs).
qed.

lemma catalog_sound_leaf h f c index value :
  catalog_sound h f c => (0,index) \notin c => 0 <= index =>
  catalog_sound h f c.[(0,index) <- value].
proof.
  move=> hs hf hi.
  apply (catalog_sound_insert h h f c 0 index value) => //.
qed.
