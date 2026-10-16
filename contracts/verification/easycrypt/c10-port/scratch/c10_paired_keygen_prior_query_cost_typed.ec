(* Compose the existing common-input keygen relation with the paired byte
   driver. Preserve the original public-input totalization and oracle state;
   no concrete hash interpretation or cross-kernel theorem is asserted. *)
require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen KeygenPrefixes KeygenExhaustion FullSession ByteSession.
require import C10Representation C10CallerInputBridge C10TreeCallerBridge.
require import C10SearchAcceptance C10PairedSession C10PairedInitialization.

module PairedKeygenPreparation (O : PrefixOracle) = {
  proc run() : raw_input * raw_input * raw_input * raw_input = {
    var seed, root;
    seed <- pad_node (node KeygenInputs.public_seed);
    root <@ CommonInputMerkle(O).root(seed,1,0);
    return (KeygenInputs.random,KeygenInputs.message,seed,pad_node root);
  }
}.

module PairedKeygenByteContext (A : ByteClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ PairedKeygenPreparation(O).run();
    Shared.calls <- 0; result <@ PairedByteDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.
