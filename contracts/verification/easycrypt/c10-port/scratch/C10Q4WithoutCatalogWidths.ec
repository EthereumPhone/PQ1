require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature PathReplay RawPathReplay RawForsPathReplay.
require import RawBuilderReference TotalBuilderReference BuildRootProjection.

require import NodeCatalog NodeCatalogDomain CatalogWidths.
lemma without_width c total target :
  0 <= total => 0 <= target < 2^total => catalog_exact c (2^total) =>
  size (catalog_grid c 0 target) = 16.
proof. exact (catalog_leaf_width c total target). qed.
