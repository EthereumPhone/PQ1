require import AllCore List FMap C10RawOracle RawSigner RawSignature RawWrapper C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge C10FunctionalWotsValue C10FunctionalSigner C10FunctionalSignerBytes C10FunctionalVerifier C10FunctionalVerifierState C10FunctionalCalls.

op paired_wrapper_result (fn : raw_input -> raw_input) (key seed root random message : raw_input)
    (ready guard : bool) =
  let signed = paired_signer_result fn key seed root random message in
  if ready /\ signed <> None /\ guard /\ paired_verifier_result fn seed root message (oget signed)
  then signed else None.

op functional_wrapper_cost (f : raw_input -> digest) (key seed root random message sha shb : raw_input)
    (ready : bool) =
  if !ready then 0 else
    functional_signer_cost f key seed root random message sha +
    (if paired_signer_result (interpreted_backend f) key seed root random message = None then 0 else
      functional_signer_cost f key seed root random message shb +
      0 * functional_verifier_cost f seed root message
        (oget (paired_signer_result (interpreted_backend f) key seed root random message))).

op functional_wrapper_state (f : raw_input -> digest) (initial final : (raw_input,digest) fmap)
    (key seed root random message sha shb : raw_input) (ready : bool) =
  if !ready then final = initial else
    exists first,
      functional_signer_state f initial first key seed root random message sha /\
      (if paired_signer_result (interpreted_backend f) key seed root random message = None
       then final = first else
         exists second, functional_signer_state f first second key seed root random message shb /\
           final = functional_verifier_history f second seed root message
             (oget (paired_signer_result (interpreted_backend f) key seed root random message))).
