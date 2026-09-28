(* Fixed-width slicing is independent of the contents of each node. *)
require import AllCore List IntDiv BitEncoding.
require import C10RawOracle RawSignature RawCodec.
import BitChunking.

lemma slice_inside n width offset start (bs : raw_input) :
  0<=n => 0<=start => start+n<=width => 0<=offset =>
  take n (drop start (take width (drop offset bs))) = take n (drop (offset+start) bs).
proof.
  move=> hn hs hw ho; rewrite drop_take 1,2:/# drop_drop 1,2:/# take_take; smt().
qed.

lemma read_nodes_slice n width offset start (bs : raw_input) :
  0<=n => 0<=start => start+16*n<=width => 0<=offset =>
  read_nodes n (take width (drop offset bs)) start = read_nodes n bs (offset+start).
proof.
  move=> hn hs hw ho; rewrite /read_nodes; apply eq_in_mkseq => i hi /=.
  rewrite slice_inside 1..4:/#; congr; smt().
qed.

lemma slice_body (prefix body suffix : raw_input) :
  take (size body) (drop (size prefix) (prefix ++ body ++ suffix)) = body.
proof.
  by rewrite -catA drop_size_cat 1:// take_size_cat 1://.
qed.

lemma read_nodes_body n rows (prefix suffix : raw_input) :
  rows_width n rows =>
  read_nodes n (prefix ++ flatten rows ++ suffix) (size prefix)=rows.
proof.
  move=> hw; have hn : 0<=n by move: hw; rewrite /rows_width; smt(size_ge0).
  have hz : size (flatten rows)=16*n by exact (rows_flatten_width n rows hw).
  have hbound : size prefix+16*n<=size (prefix ++ flatten rows ++ suffix) by smt(size_cat size_ge0).
  rewrite read_nodes_chunk 1:hn 1:size_ge0 1:hbound -hz slice_body.
  apply flattenK; first smt().
  move: hw; rewrite /rows_width; smt(allP).
qed.

lemma flat_block w rows i :
  0<w => all (fun (x : raw_input) => size x=w) rows => 0<=i<size rows =>
  take w (drop (w*i) (flatten rows))=nth [] rows i.
proof.
  move=> hw ha hi.
  have he : chunk w (flatten rows)=rows by apply flattenK; smt(allP).
  have hall : forall x, mem rows x => size x=w by smt(allP).
  have hs : size (flatten rows)=w*size rows by rewrite (size_flatten_ctt w rows hall); smt().
  have hn : nth [] (chunk w (flatten rows)) i=nth [] rows i by rewrite he.
  move: hn; rewrite /chunk hs mulKz 1:/# nth_mkseq 1:hi /=; smt().
qed.
