require import AllCore List IntDiv C10Representation C10RawOracle C10RawGrind RawSigner RawLayer RawForest SignerCoordinates C10FixedBackend C10FixedCallerBridge C10DigestCallers C10Bytes ShuffleBytes C10CallerInputBridge C10OuterCallerBridge C10FunctionalWotsValue C10FunctionalForestRecover C10FunctionalLayerRecover FMap KeygenPrefixes C10HashInputBridge C10SearchAcceptance RawSignature RawDecode C10RepresentationBridge.

op digest_fors_indices (bs : (int list)) : (int list) =
  (mkseq (fun i => (fors_field bs i)) 13).

op verifier_digest (hash_fn : (int list -> int list)) (seed : (int list)) (root : (int list)) (random : (int list)) (message : (int list)) : (int list) =
  (hash_fn (hmsg_preimage seed root (pad_node random) message)).

op digest_forest_value (hash_fn : (int list -> int list)) (seed : (int list)) (bs : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) : (int list) =
  (forest_recover_value hash_fn seed (ht_field bs) (digest_fors_indices bs) forest_secrets forest_paths).

op hypertree_first_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (message : (int list)) (values : ((int list) list)) (nonce : int) (auth : ((int list) list)) : (int list) =
  (layer_recover_value hash_fn seed 0 (ht %/ 512) (ht %% 512) message values nonce auth).

op hypertree_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (message : (int list)) (values0 : ((int list) list)) (nonce0 : int) (auth0 : ((int list) list)) (values1 : ((int list) list)) (nonce1 : int) (auth1 : ((int list) list)) : (int list) =
  (layer_recover_value hash_fn seed 1 ((ht %/ 512) %/ 512) ((ht %/ 512) %% 512) (hypertree_first_value hash_fn seed ht message values0 nonce0 auth0) values1 nonce1 auth1).

op verifier_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (bs : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) (values0 : ((int list) list)) (nonce0 : int) (auth0 : ((int list) list)) (values1 : ((int list) list)) (nonce1 : int) (auth1 : ((int list) list)) : (int list) =
  (hypertree_recover_value hash_fn seed (ht_field bs) (digest_forest_value hash_fn seed bs forest_secrets forest_paths) values0 nonce0 auth0 values1 nonce1 auth1).

op paired_verifier_result fn seed root message (sig : raw_signature) =
  let d = verifier_digest fn seed root sig.`1 message in
  let first = nth ([],0,[]) sig.`4 0 in
  let second = nth ([],0,[]) sig.`4 1 in
  fors_zero_field d = 1 /\
    pad_node (verifier_recover_value fn seed d sig.`2 sig.`3
      first.`1 first.`2 first.`3 second.`1 second.`2 second.`3) = root.
