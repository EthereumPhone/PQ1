(* Byte adapter for the WOTS+C input. Model bit lists are least-significant
   bit first; firmware byte arrays are big-endian integers. Bytes are integers
   in [0,256). This file proves the adapter, not SHA-256 pseudorandomness. *)
require import AllCore List IntDiv Ring BitEncoding.
require C10Counter.
import BS2Int BitChunking.

op bytes_to_bits (bs : int list) : bool list =
  flatten (map (int2bs 8) (rev bs)).
op bits_to_bytes (bs : bool list) : int list =
  rev (map bs2int (chunk 8 bs)).

lemma bytes_to_bits_size (bs : int list) : size (bytes_to_bits bs) = 8 * size bs.
proof.
  rewrite /bytes_to_bits (size_flatten_ctt 8).
  + by move=> x /mapP [b [hb ->]]; rewrite size_int2bs.
  by rewrite size_map size_rev.
qed.

lemma bits_to_bytes_size (bs : bool list) : size (bits_to_bytes bs) = size bs %/ 8.
proof. by rewrite /bits_to_bytes size_rev size_map size_chunk. qed.

lemma bits_bytes_roundtrip (bs : bool list) :
  8 %| size bs => bytes_to_bits (bits_to_bytes bs) = bs.
proof.
  move=> hdiv; rewrite /bytes_to_bits /bits_to_bytes revK -map_comp.
  rewrite (iffLR _ _ (eq_in_map _ idfun _)).
  + move=> b hb; rewrite /(\o) /idfun.
    by rewrite -(in_chunk_size 8 bs b _ hb) 1:// bs2intK.
  by rewrite map_id chunkK.
qed.

lemma bytes_bits_roundtrip (bs : int list) :
  all (fun b => 0 <= b < 256) bs => bits_to_bytes (bytes_to_bits bs) = bs.
proof.
  move=> hb; rewrite /bits_to_bytes /bytes_to_bits flattenK 1://.
  + by move=> x /mapP [b [hm ->]]; rewrite size_int2bs.
  rewrite -map_comp (iffLR _ _ (eq_in_map _ idfun _)).
  + move=> b hm; rewrite /(\o) /idfun int2bsK 1://.
    - have hbyte : 0 <= b < 256 by move: hb=> /allP; apply; rewrite -mem_rev.
      by rewrite (_ : 8 = 2 * 2 * 2) 1:// !IntID.exprM !IntID.expr2.
    by [].
  by rewrite map_id revK.
qed.

op counter_bits (c : C10Counter.counter) = int2bs 32 (C10Counter.U32.val c).
op counter_bytes (c : C10Counter.counter) = bits_to_bytes (counter_bits c).
op compact (node : bool list) (c : C10Counter.counter) = node ++ counter_bits c.

lemma counter_bits_size (c : C10Counter.counter) : size (counter_bits c) = 32.
proof. by rewrite /counter_bits size_int2bs. qed.

lemma counter_bytes_size (c : C10Counter.counter) : size (counter_bytes c) = 4.
proof. by rewrite /counter_bytes bits_to_bytes_size counter_bits_size. qed.

lemma counter_bytes_roundtrip (c : C10Counter.counter) :
  bytes_to_bits (counter_bytes c) = counter_bits c.
proof. by rewrite /counter_bytes bits_bytes_roundtrip 1:counter_bits_size. qed.

(* Matches pad16(node) and the zero-initialised count_uint256 slot. *)
op payload (node : bool list) (c : C10Counter.counter) : int list =
  bits_to_bytes node ++ nseq 16 0 ++ nseq 28 0 ++ counter_bytes c.

op transcript (seed address : int list) (node : bool list)
  (c : C10Counter.counter) : int list = seed ++ address ++ payload node c.

lemma payload_size (node : bool list) (c : C10Counter.counter) :
  size node = 128 => size (payload node c) = 64.
proof.
  by move=> hn; rewrite /payload !size_cat bits_to_bytes_size hn
    !size_nseq counter_bytes_size.
qed.

lemma transcript_size (seed address : int list) (node : bool list)
  (c : C10Counter.counter) :
  size seed = 32 => size address = 32 => size node = 128 =>
  size (transcript seed address node c) = 128.
proof. by move=> hs ha hn; rewrite /transcript 2!size_cat hs ha payload_size. qed.

lemma payload_recovers_compact (node : bool list) (c : C10Counter.counter) :
  size node = 128 =>
  bytes_to_bits (take 16 (payload node c)) ++
    bytes_to_bits (drop 60 (payload node c)) = compact node c.
proof.
  move=> hn; have sz : size (bits_to_bytes node) = 16
    by rewrite bits_to_bytes_size hn.
  rewrite /payload /compact -!catA take_cat sz /=.
  rewrite take0 cats0 !drop_cat sz !size_nseq /max /= drop0.
  by rewrite bits_bytes_roundtrip 1:hn 1:// counter_bytes_roundtrip.
qed.
