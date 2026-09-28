require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature RawWidths PathReplay PathInputs RawPathReplay RawForsPathReplay ForsLeafInputs.
require import ForsBuilderSecret ForsBuilderComparison MerkleBuilderComparison.

require import NodeCatalog NodeCatalogDomain LeafOrigins.
lemma without_origins (h : (raw_input,digest) fmap)
    (f : int -> raw_input -> raw_input) c total target :
  0 <= total => 0 <= target < 2^total => catalog_exact c (2^total) =>
  exists secret d, size secret = 16 /\
    h.[f target secret] = Some d /\ catalog_grid c 0 target = node d.
proof. exact (catalog_target_origin h f c total target). qed.
