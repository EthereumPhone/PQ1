(* Complete native signer output, wire bytes, retained backend state and cost.
   Fixed-backend correspondence does not transfer sampled-oracle probabilities. *)
require import AllCore List FMap.
require import C10RawOracle RawSigner RawSignature C10Counter.
require import C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge.
require import C10FunctionalWotsValue C10FunctionalSigner C10FunctionalSignerWidths.
require import C10FunctionalSignatureBytes.

op paired_signer_bytes fn key seed root random message =
  omap paired_signature_bytes (paired_signer_result fn key seed root random message).

lemma signature_option_bytes (signed : raw_signature option) :
  (signed <> None => signature_width (oget signed)) =>
  omap encode_signature signed = omap paired_signature_bytes signed /\
  (signed <> None => size (encode_signature (oget signed)) = 4008).
proof. by case signed => [|sig] //=; smt(signature_bytes_encoder encoded_signature_width). qed.

lemma raw_functional_signer_bytes f h c key0 seed0 root0 random0 message0 shuffle0 :
  equiv[RawSigner(FixedPrefix).sign ~ CommonInputSigner(FixedPrefix).sign :
    ={seed,root,random,message,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ root{1} = root0 /\ random{1} = random0 /\ message{1} = message0 /\ shuffle{1} = shuffle0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = paired_signer_result (interpreted_backend f) key0 seed0 root0 random0 message0 /\
    omap encode_signature res{1} = paired_signer_bytes (interpreted_backend f) key0 seed0 root0 random0 message0 /\
    (res{1} <> None => signature_width (oget res{1}) /\ size (encode_signature (oget res{1})) = 4008) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+functional_signer_cost f key0 seed0 root0 random0 message0 shuffle0 /\
    functional_signer_state f h FixedBackend.history{1} key0 seed0 root0 random0 message0 shuffle0].
proof.
  conseq (raw_functional_signer f h c key0 seed0 root0 random0 message0 shuffle0)
    (raw_functional_signer_width f) (_ : true ==> true) => //.
  rewrite /paired_signer_bytes; smt(signature_option_bytes).
qed.
