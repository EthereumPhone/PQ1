require import AllCore List IntDiv.
require import C10RawOracle RawLayer RawSigner RawSignature.
require import C10Representation C10AddressInputBridge C10CallerInputBridge.

op nodes_bytes (values : ((int list) list)) : (int list) =
  (foldr (fun value tail => (value ++ tail)) [] values).

op layer_bytes (values : ((int list) list)) (nonce : int) (auth : ((int list) list)) : (int list) =
  ((nodes_bytes values) ++ (u32_bytes (nonce %% 256)) ++ (nodes_bytes auth)).

op signature_bytes (random : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) (values0 : ((int list) list)) (nonce0 : int) (auth0 : ((int list) list)) (values1 : ((int list) list)) (nonce1 : int) (auth1 : ((int list) list)) : (int list) =
  (random ++ (nodes_bytes forest_secrets) ++ (foldr (fun path_row tail => ((nodes_bytes path_row) ++ tail)) [] forest_paths) ++ (layer_bytes values0 nonce0 auth0) ++ (layer_bytes values1 nonce1 auth1)).
