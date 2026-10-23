(* Exact history maps for tree construction. Query membership describes every
   new mapping, including repeated/preexisting inputs; it does not claim a
   chronology for the map. Actual call counts and Raw/CommonInput execution
   equivalence are separate contracts. *)
require import AllCore List FMap.
require import C10RawOracle C10FixedBackend NodeCatalog NodeCatalogDomain.

op functional_history_exact (f : raw_input -> digest) (initial history : (raw_input,digest) fmap)
  (queried : raw_input -> bool) =
  forall x, history.[x] = if queried x then Some (f x) else initial.[x].

op functional_catalog_queried (queries : int -> int -> raw_input list) (catalog : node_catalog) x =
  exists height index, (height,index) \in catalog /\ x \in queries height index.

op functional_catalog_history f initial history queries catalog =
  functional_history_exact f initial history (functional_catalog_queried queries catalog).

op functional_tree_queried (queries : int -> int -> raw_input list) total x =
  exists height index, node_due (2^total) height index /\ x \in queries height index.

lemma functional_history_empty f initial :
  functional_history_exact f initial initial (fun _ => false).
proof. by rewrite /functional_history_exact. qed.

lemma functional_history_consistent f initial history queried :
  backend_consistent initial f => functional_history_exact f initial history queried =>
  backend_consistent history f.
proof. rewrite /backend_consistent /functional_history_exact; smt(). qed.

lemma functional_history_remember f initial history queried q :
  backend_consistent initial f => functional_history_exact f initial history queried =>
  functional_history_exact f initial (remember history q (f q)) (fun x => queried x \/ x = q).
proof.
  rewrite /functional_history_exact /backend_consistent /remember;
    smt(get_setE domE).
qed.

lemma functional_history_queries f initial history queried qs :
  backend_consistent initial f => functional_history_exact f initial history queried =>
  functional_history_exact f initial (backend_history f history qs) (fun x => queried x \/ x \in qs).
proof.
  elim qs history queried => [history queried|q qs ih history queried].
  + by rewrite backend_history_nil /functional_history_exact /=.
  move=> hc he.
  have hs := functional_history_remember f initial history queried q hc he.
  have ht := ih (remember history q (f q)) (fun x => queried x \/ x = q) hc hs.
  move: ht; rewrite /backend_history /= /functional_history_exact; smt().
qed.

lemma functional_catalog_queried_set queries catalog height index value x :
  functional_catalog_queried queries catalog.[(height,index) <- value] x <=>
    functional_catalog_queried queries catalog x \/ x \in queries height index.
proof. rewrite /functional_catalog_queried; smt(mem_set). qed.

lemma functional_catalog_history_empty f initial queries :
  functional_catalog_history f initial initial queries empty.
proof.
  rewrite /functional_catalog_history /functional_history_exact /functional_catalog_queried;
    smt(mem_empty).
qed.

lemma functional_catalog_history_set f initial history queries catalog height index value :
  backend_consistent initial f => functional_catalog_history f initial history queries catalog =>
  functional_catalog_history f initial (backend_history f history (queries height index))
    queries catalog.[(height,index) <- value].
proof.
  move=> hc he; rewrite /functional_catalog_history.
  have hs := functional_history_queries f initial history (functional_catalog_queried queries catalog)
    (queries height index) hc he.
  move: hs; rewrite /functional_history_exact; smt(functional_catalog_queried_set).
qed.

lemma functional_catalog_history_complete f initial history queries catalog total :
  catalog_exact catalog (2^total) => functional_catalog_history f initial history queries catalog =>
  functional_history_exact f initial history (functional_tree_queried queries total).
proof.
  rewrite /catalog_exact /functional_catalog_history /functional_history_exact
    /functional_catalog_queried /functional_tree_queried; smt().
qed.

lemma functional_history_preserves f initial history queried x :
  backend_consistent initial f => functional_history_exact f initial history queried =>
  x \in initial => history.[x] = initial.[x].
proof. rewrite /backend_consistent /functional_history_exact; smt(domE). qed.

lemma fixed_builder_hash_history f history0 x0 :
  hoare[FixedBackend.hash : x = x0 /\ FixedBackend.fn = f /\
    FixedBackend.history = history0 /\ backend_consistent history0 f ==>
    res = f x0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember history0 x0 (f x0) /\
    backend_consistent FixedBackend.history f].
proof.
  exists* FixedBackend.calls; elim* => c.
  conseq (fixed_hash f history0 x0 c); smt().
qed.

lemma fixed_builder_derive_history f history0 key0 tail0 :
  hoare[FixedPrefix.derive : tail = tail0 /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = history0 /\ backend_consistent history0 f ==>
    res = f (key0 ++ tail0) /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember history0 (key0 ++ tail0) (f (key0 ++ tail0)) /\
    backend_consistent FixedBackend.history f].
proof. proc; call (fixed_builder_hash_history f history0 (key0 ++ tail0)); auto. qed.
